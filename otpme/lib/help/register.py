# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

# Base help files.
help_dir = os.path.realpath(__file__)
help_dir = os.path.dirname(help_dir)

def register_help():
    """ Register help files. """
    # Get all help files.
    help_modules = []
    for x in os.walk(help_dir):
        x_dir = x[0]
        help_files = x[2]
        for x_file in help_files:
            if not x_file.endswith(".py"):
                continue
            if x_file == "register.py":
                continue
            mod_name = x_file.split(".")[:-1]
            mod_name = ".".join(mod_name)
            if x_dir == help_dir:
                if x_file == "__init__.py":
                    continue
                mod_path = "otpme.lib.help.%s" % mod_name
            else:
                sub_dir = os.path.basename(x_dir)
                mod_path = "otpme.lib.help.%s.%s" % (sub_dir, mod_name)
            help_modules.append(mod_path)

    # Register modules.
    for x in help_modules:
        x_module = importlib.import_module(x)
        try:
            x_method = getattr(x_module, "register")
        except Exception as e:
            if e.message == "'module' object has no attribute 'register'":
                continue
            raise
        x_method()
