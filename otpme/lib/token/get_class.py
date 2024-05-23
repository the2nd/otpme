# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def get_module(token_type):
    """ Get token module by type. """
    # Fix token type name to match module path.
    token_type = token_type.replace("-", "_")
    # Build module path to token module.
    token_module_path = "otpme.lib.token.%s.%s" % (token_type, token_type)
    # Import token module.
    token_module = importlib.import_module(token_module_path)
    return token_module

def get_class(token_type):
    """ Get token class by type. """
    # Build token class name from token type.
    class_name = token_type.replace("_", "")
    class_name = "%s%sToken" % (class_name[0].upper(), class_name[1:])
    # Get token module.
    token_module = get_module(token_type)
    # Get token class.
    class_name = class_name.replace("-", "")
    token_class = getattr(token_module, class_name)
    return token_class
