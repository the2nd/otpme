# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from hashlib import md5
from dogpile.cache.region import RegionInvalidationStrategy

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import multiprocessing

from otpme.lib.exceptions import *

REGISTER_AFTER = []
REGISTER_BEFORE = []

def register():
    config.register_config_var("dogpile_caching", bool, False)
    multiprocessing.register_shared_dict("dogpile_invalidate")

# https://stackoverflow.com/questions/23102971/sqlalchemy-cache-with-dogpile
def md5_key_mangler(prefix, key):
    """Receive cache keys as long concatenated strings;
    distill them into an md5 hash.

    """
    key_hash = md5(key.encode('ascii')).hexdigest()
    key_string = "dogpile.%s.%s" % (prefix, key_hash)
    return key_string

# https://dogpilecache.sqlalchemy.org/en/latest/api.html#dogpile.cache.region.RegionInvalidationStrategy
class CustomInvalidationStrategy(RegionInvalidationStrategy):
    def __init__(self, region):
        self.region = region
        multiprocessing.dogpile_invalidate[self.region] = {}

    @property
    def _soft_invalidated(self):
        try:
            _soft_invalidated = multiprocessing.dogpile_invalidate[self.region]['soft']
        except:
            return
        return _soft_invalidated

    @_soft_invalidated.setter
    def _soft_invalidated(self, val):
        if self.region not in multiprocessing.dogpile_invalidate:
            multiprocessing.dogpile_invalidate[self.region] = {}
        multiprocessing.dogpile_invalidate[self.region]['soft'] = val

    @property
    def _hard_invalidated(self):
        try:
            _hard_invalidated = multiprocessing.dogpile_invalidate[self.region]['hard']
        except:
            return
        return _hard_invalidated

    @_hard_invalidated.setter
    def _hard_invalidated(self, val):
        if self.region not in multiprocessing.dogpile_invalidate:
            multiprocessing.dogpile_invalidate[self.region] = {}
        multiprocessing.dogpile_invalidate[self.region]['hard'] = val

    def invalidate(self, hard=None):
        if hard:
            self._soft_invalidated = None
            self._hard_invalidated = time.time()
        else:
            self._soft_invalidated = time.time()
            self._hard_invalidated = None

    def is_invalidated(self, timestamp):
        is_invalidated = ((self._soft_invalidated and
             timestamp < self._soft_invalidated) or
            (self._hard_invalidated and
             timestamp < self._hard_invalidated))
        return is_invalidated

    def was_hard_invalidated(self):
        return bool(self._hard_invalidated)

    def is_hard_invalidated(self, timestamp):
        return (self._hard_invalidated and
            timestamp < self._hard_invalidated)

    def was_soft_invalidated(self):
        return bool(self._soft_invalidated)

    def is_soft_invalidated(self, timestamp):
        return (self._soft_invalidated and
            timestamp < self._soft_invalidated)
