# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def get_class(sc_type):
    """ get smartcard class by type """
    # build smartcard class name from smartcard type
    class_name = sc_type.replace("_", "")
    class_name = "%s%s" % (class_name[0].upper(), class_name[1:])
    # build module path to smartcard module
    smartcard_module_path = "otpme.lib.smartcard.%s.%s" % (sc_type, sc_type)
    smartcard_module_path = smartcard_module_path.replace("-", "_")
    # import smartcard module
    smartcard_module = importlib.import_module(smartcard_module_path)
    # get smartcard class
    smartcard_class = getattr(smartcard_module, class_name)
    return smartcard_class
