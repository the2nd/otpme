# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>

REGISTER_BEFORE = []
REGISTER_AFTER = []

# Daemon modules to register.
modules = [
        'otpme.lib.daemon.controld',
        'otpme.lib.daemon.syncd',
        'otpme.lib.daemon.authd',
        'otpme.lib.daemon.joind',
        'otpme.lib.daemon.scriptd',
        'otpme.lib.daemon.mgmtd',
        'otpme.lib.daemon.hostd',
        'otpme.lib.daemon.ldapd',
        'otpme.lib.daemon.httpd',
        'otpme.lib.daemon.clusterd',
        ]

def register():
    """ Register object modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
