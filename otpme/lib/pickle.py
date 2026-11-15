# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pickle as _pickle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

class PickleHandler(object):
    """ Pickles what goes into the cache, with the pickle of the standard
    library.

    It used to offer larch-pickle as well, through PICKLE_CACHE_MODULE
    (and by itself, with "auto", once larch was installed). larch does
    not call __setstate__, which is what puts the incremental objects of
    an OTPme object back together, so what came out of the cache was
    broken.
    """
    def dumps(self, instance, protocol=None, **kwargs):
        if protocol is None:
            protocol = _pickle.HIGHEST_PROTOCOL
        return _pickle.dumps(instance, protocol=protocol, **kwargs)

    def loads(self, dump_data, **kwargs):
        return _pickle.loads(dump_data, **kwargs)
