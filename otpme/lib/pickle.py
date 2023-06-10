# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import gc
import bson

try:
    import larch.pickle as _lpickle
    PICKLE_TYPE = "larch"
except:
    PICKLE_TYPE = "pickle"
    import pickle as _pickle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

class PickleHandler(object):
    def __init__(self, pickle_type, encode=True, disable_gc=True):
        if pickle_type == "auto":
            pickle_type = PICKLE_TYPE
        # Set pickler.
        self.pickler = self.get_pickler(pickle_type)
        self.pickle_type = pickle_type
        self.encode = encode
        self.disable_gc = disable_gc

    def get_pickler(self, pickle_type):
        if pickle_type == "pickle":
            import pickle as _pickle
            pickle = _pickle
        if pickle_type == "larch":
            try:
                import larch.pickle as _lpickle
                pickle = _lpickle
            except:
                msg = "Please install larch-pickle."
                raise OTPmeException(msg)
        return pickle

    def dumps(self, instance, protocol=None, **kwargs):
        if self.pickle_type == "pickle":
            if protocol is None:
                protocol = self.pickler.HIGHEST_PROTOCOL
                kwargs['protocol'] = protocol
        if self.disable_gc:
            gc.disable()
        pickle_data = self.pickler.dumps(instance, **kwargs)
        dump_data = {
                    'pickle_type' : self.pickle_type,
                    'pickle_data' : pickle_data,
                    }
        if self.encode:
            dump_data = bson.dumps(dump_data)
        if self.disable_gc:
            gc.enable()
        return dump_data

    def loads(self, dump_data, **kwargs):
        if self.disable_gc:
            gc.disable()
        if self.encode:
            dump_data = bson.loads(dump_data)
        pickle_type = dump_data['pickle_type']
        pickle_data = dump_data['pickle_data']
        pickler = self.get_pickler(pickle_type)
        instance = pickler.loads(pickle_data, **kwargs)
        if self.disable_gc:
            gc.enable()
        return instance
