# Copyright (C) 2014 the2nd <the2nd@otpme.org>

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.cache']

modules = [
        'otpme.lib.index.mysql',
        'otpme.lib.index.sqlite3',
        'otpme.lib.index.postgres',
        ]

def register(**kwargs):
    """ Register modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules, **kwargs)
