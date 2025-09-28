# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {}")
        msg = msg.format(__name__)
        print(msg)
except:
    pass

from otpme.lib import config

def get_module(resolver_type):
    """ Get resolver module by type. """
    # Build module path to resolver module.
    module_path = (f"otpme.lib.resolver.{resolver_type}.{resolver_type}")
    # Import resolver module.
    resolver_module = importlib.import_module(module_path)
    return resolver_module

def get_class(resolver_type):
    """ Get resolver class by type """
    # Build resolver class name from resolver type.
    class_name = resolver_type.replace("-", "")
    class_name = f"{class_name[0].upper()}{class_name[1:]}Resolver"
    # Import resolver module.
    resolver_module = get_module(resolver_type)
    # Get resolver class.
    try:
        resolver_class = getattr(resolver_module, class_name)
    except Exception as e:
        config.raise_exception()
        msg = _("Error loading resolver '{}': {}")
        msg = msg.format(class_name, e)
        raise Exception(msg)
    return resolver_class
