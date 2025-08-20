# Copyright (C) 2014 the2nd <the2nd@otpme.org>

REGISTER_BEFORE = []
REGISTER_AFTER = []

# Object modules to register.
modules = [
        'otpme.lib.classes.otpme_object',
        'otpme.lib.classes.user',
        'otpme.lib.classes.accessgroup',
        'otpme.lib.classes.ca',
        'otpme.lib.classes.client',
        'otpme.lib.classes.dictionary',
        'otpme.lib.classes.group',
        'otpme.lib.classes.host',
        'otpme.lib.classes.node',
        'otpme.lib.classes.policy',
        'otpme.lib.classes.realm',
        'otpme.lib.classes.resolver',
        'otpme.lib.classes.role',
        'otpme.lib.classes.script',
        'otpme.lib.classes.site',
        'otpme.lib.classes.token',
        'otpme.lib.classes.unit',
        'otpme.lib.classes.share',
        'otpme.lib.classes.pool',
        ]

def register():
    """ Register object modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
