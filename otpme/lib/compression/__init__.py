# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
        'otpme.lib.compression.base',
        ]

def register():
    """ Register modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
