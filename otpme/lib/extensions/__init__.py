# Copyright (C) 2014 the2nd <the2nd@otpme.org>

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
        'otpme.lib.extensions.base.base',
        'otpme.lib.extensions.posix.posix',
        ]

def register():
    """ Register modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
