# -*- coding: utf-8 -*-
'''
Handle minion keys that must be validated
via a puppet CA; this lets you re-use your
puppet keys as minion keys
'''

import os
import salt.payload
import salt.utils
from salt.external_keys import ExternalKeys
import OpenSSL

# this horrible stuff is for hacked add-ons to pyopenssl
from functools import partial
from OpenSSL._util import lib as _lib
from OpenSSL._util import ffi as _ffi
from OpenSSL._util import exception_from_error_queue as _exception_from_error_queue


class Error(Exception):
    '''
    for errors from hacs to PyOpenSSL
    '''

_raise_current_error = partial(_exception_from_error_queue, Error)


class PuppetKeys(ExternalKeys):
    '''
    re-use puppet keys as minion keys
    '''

    @staticmethod
    def get_minion_keypair(opts, pub_path, priv_path,
                           refreshifchanged=False):
        '''
        retrieve keys for minion with id specified in opts,
        from the puppet public and private key files, and
        store them in the specified locations

        if 'refreshifchanged' is True, then only if the
        public key at the path passed in is different
        than the external key or it does not exist, we 
        get the external private and public key and stash
        them

        if 'refreshifchanged' is False, then we get the
        external keys and stash them, overwriting any keys
        that might currently exist without checking

        a return of True indicates the external keys were
        retrieved and stashed
        any other outcome results in a return of False
        and in attempted removal of the local key pair
        '''
        if (not os.path.exists(opts['puppet_client_priv_key'])
            or not os.path.exists(opts['puppet_client_pub_key'])):
            msg = 'minion private or public key file is missing, {0} or {1}'.format(
                opts['puppet_client_priv_key'], opts['puppet_client_pub_key'])
            ExternalKeys.whine(msg)
            return False
        try:
            with salt.utils.fopen(opts['puppet_client_pub_key']) as fp_:
                pub_data = fp_.read()
            with salt.utils.fopen(opts['puppet_client_priv_key']) as fp_:
                priv_data = fp_.read()
        except IOError:
            msg = 'minion public/private key could not be read at {0}/{1}'.format(
                opts['puppet_client_pub_key'], opts['puppet_client_priv_key'])
            ExternalKeys.whine(msg)
            return False
            
        if refreshifchanged:
            # check the old key, if it's the same we abort
            try:
                with salt.utils.fopen(pub_path, 'r') as fp_:
                    old_data = fp_.read()
            except IOError:
                # if there is no old pub key file, that's as
                # good as a changed pub key, proceed accordingly
                old_data = ''

            if pub_data == old_data:
                return False
            else:
                # delete our current key if present, then stash
                # the new externally retrieved one.
                try:
                    os.remove(pub_path)
                    os.remove(priv_path)
                except IOError:
                    msg = 'failed to remove old key at {0} or {1}'.format(
                        pub_path, priv_path)
                    ExternalKey.whine(msg)
                    # don't bail, maybe the key was removed in the meantime

        try:
            with salt.utils.fopen(priv_path, 'w+') as fp_:
                fp_.write(priv_data)
            with salt.utils.fopen(pub_path, 'w+') as fp_:
                fp_.write(pub_data)
        except:
            msg = 'minion key could not be stored at {0}/{1}'.format(
                priv_path, pub_path)
            ExternalKeys.whine(msg)
            return False

        return True

    def __init__(self, opts):
        super(PuppetKeys, self).__init__(opts)

        if not os.path.isdir(self.opts['puppet_certs_dir']):
            msg = 'puppet_certs_dir is missing or not a directory'.format(
                self.opts['puppet_certs_dir'])
            ExternalKeys.whine(msg, fatal=True)
        if not os.path.exists(self.opts['puppet_ca_cert']):
            msg = 'puppet_ca_cert is missing'.format(
                self.opts['puppet_ca_cert'])
            ExternalKeys.whine(msg, fatal=True)
        try:
            with salt.utils.fopen(self.opts['puppet_ca_cert']) as fp_:
                data = fp_.read()
            self.ca_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, data)
        except:
            msg = 'failed to read puppet ca cert at {0}'.format(
                self.opts['puppet_ca_cert'])
            ExternalKeys.whine(msg, fatal=True)
        if (self.opts['puppet_crl_path'] and
            not os.path.isdir(self.opts['puppet_crl_path'])):
            msg = 'crl path {0} is not a directory'.format(
                self.opts['puppet_crl_path'])
            ExternalKeys.whine(msg)

        self.store = OpenSSL.crypto.X509Store()
        self.store.add_cert(self.ca_cert)

    def validate(self, minion, key):
        '''
        validate a minion key by checking the
        corresponding puppet cert
        '''
        if self.check_last_validate_time(minion):
            # previous validation of key is still good
            return True

        minion_cert_path = os.path.join(self.opts['puppet_certs_dir'],
                                        minion + '.pem')
        if not os.path.exists(minion_cert_path):
            ExternalKeys.whine('cert path %s does not exist' % minion_cert_path)
            return False

        try:
            with salt.utils.fopen(minion_cert_path) as fp_:
                data = fp_.read()
            minion_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, data)
        except:
            msg = 'failed to load minion certificate {0}'.format(
                minion_cert_path)
            ExternalKeys.whine(msg)

        data = OpenSSL.crypto.X509.get_pubkey(minion_cert)
        try:
            minion_key = self.dump_publickey(data)
        except Exception as exc:
            msg = 'failed to extract pub key from minion cert {0}, {1}'.format(
                minion_cert, exc)
            ExternalKeys.whine(msg)
            return False
        if minion_key != key:
            msg = 'key provided by minion does not match puppet key'
            ExternalKeys.whine(msg)
            return False

        try:
            self.crypto_verify_cert(minion_cert)
        except Exception as exc:
            msg = 'verification of cert {0} failed, {1}'.format(
                minion_cert, exc)
            ExternalKeys.whine(msg)
            return False

        if not self.check_crl(minion_cert):
            return False

        self.stash_validate_time(minion)
        return True

    def dump_publickey(self, pkey):
        bio = OpenSSL.crypto._new_mem_buf()
        result_code = _lib.PEM_write_bio_PUBKEY(bio, pkey._pkey)
        if result_code == 0:
            _raise_current_error()

        return OpenSSL.crypto._bio_to_string(bio)

    # adapted from patch to bug on launchpad:
    # https://bugs.launchpad.net/pyopenssl/+bug/892522
    def crypto_verify_cert(self, subject_cert):
        '''
        verify a certificate against the issuer cert
        specified in salt options (does it check extensions?
        use type? dunno, haven't looked)
        '''
        ctx = _lib.X509_STORE_CTX_new()

        result = _lib.X509_STORE_CTX_init(ctx, self.store._store,
                                          subject_cert._x509, _ffi.NULL)
        if not result:
            _raise_current_error()

        err = _lib.X509_verify_cert(ctx)
        err_depth = _lib.X509_STORE_CTX_get_error_depth(ctx)
        _lib.X509_STORE_CTX_free(ctx)

        #  Don't accept verification failure at the leaf level, but DO accept
        #  failure one level above (this will always fail if the issuer is not a
        #  root certificate)
        if err != 1 and err_depth == 0:
            _raise_current_error()
        return True

    def check_crl(self, cert_path):
        if not self.opts['puppet_crl_path']:
            return True
        # fixme do this.  someday. but for now...
        return True

ExternalKeys.register('puppet', PuppetKeys)
