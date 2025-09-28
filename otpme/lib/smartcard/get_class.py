# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

def get_class(sc_type):
    """ get smartcard class by type """
    # build smartcard class name from smartcard type
    class_name = sc_type.replace("_", "")
    class_name = f"{class_name[0].upper()}{class_name[1:]}"
    # build module path to smartcard module
    smartcard_module_path = f"otpme.lib.smartcard.{sc_type}.{sc_type}"
    smartcard_module_path = smartcard_module_path.replace("-", "_")
    # import smartcard module
    smartcard_module = importlib.import_module(smartcard_module_path)
    # get smartcard class
    smartcard_class = getattr(smartcard_module, class_name)
    return smartcard_class
