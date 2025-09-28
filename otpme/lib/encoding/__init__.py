# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
	'otpme.lib.encoding.base',
        ]

def register():
    """ Register modules. """
    from ..register import _register_modules
    _register_modules(modules)
