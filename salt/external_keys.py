# -*- coding: utf-8 -*-
'''
Handle minion keys that must be validated via an
external source
'''

import os
import sys
import time
import logging
import salt.payload
import salt.utils
import salt.log

log = logging.getLogger(__name__)

class ExternalKeys(object):
    '''
    manage minion keys provided from an
    external source
    '''
    sources = {}

    @staticmethod
    def whine(msg, level='error', fatal=False):
        if salt.log.is_console_configured():
            if level == 'error':
                log.error(msg)
            else:
                log.warning(msg)
        else:
            print msg
        if fatal:
            sys.exit(1)

    @staticmethod
    def get_handler(opts):
        if opts['external_key_source'] in ExternalKeys.sources:
            return ExternalKeys.sources[opts['external_key_source']]
        else:
            return None

    @staticmethod
    def get_minion_keypair(opts, pub_path, priv_path):
        '''
        retrieve keys for minion with id specified in opts,
        store them in specified locations

        define in the subclass as a static method
        '''
        raise NotImplementedError

    @staticmethod
    def register(sourcename, classname):
        ExternalKeys.sources[sourcename] = classname

    def __init__(self, opts):
        self.opts = opts
        self.validation_dir = os.path.join(self.opts['cachedir'], 'validation')
        if not os.path.isdir(self.validation_dir):
            os.makedirs(self.validation_dir)
        self.serial = salt.payload.Serial(self.opts)
        self.validated_filename = 'validated'

    def validate(self, minion, key):
        '''
        validate a minion key via an external source
        override this in subclass
        '''
        raise NotImplementedError

    def stash_validate_time(self, minion):
        '''
        set the last validate time for the specified
        minion as now
        '''
        minion_dir = os.path.join(self.validation_dir, minion)
        if not os.path.isdir(minion_dir):
            os.makedirs(minion_dir)
        data = {'validated': time.time()}
        with salt.utils.fopen(os.path.join(
                minion_dir, self.validated_filename), 'w+') as fp_:
            fp_.write(self.serial.dumps(data))

    def get_last_validate_time(self, minion):
        '''
        retrieve and return the last time the specified
        minion key was validated
        '''
        minion_dir = os.path.join(self.validation_dir, minion)
        validated_path = os.path.join(minion_dir, self.validated_filename)
        if os.path.exists(validated_path):
            with salt.utils.fopen(validated_path) as fp_:
                data = self.serial.loads(fp_.read())
                return data['validated']
        return None

    def check_last_validate_time(self, minion):
        '''
        determine if revalidation of minion key
        is overdue
        '''
        if not self.opts['key_revalidation']:
            # not configured, ignore
            return True

        last_validated = self.get_last_validate_time(minion)
        if last_validated is None:
            # never validated
            return False

        now = time.time()
        if now - last_validated > float(self.opts['key_revalidation']):
            return False
        else:
            return True
