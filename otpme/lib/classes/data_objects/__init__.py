# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>

REGISTER_BEFORE = []
REGISTER_AFTER = []

# Protocol modules to register.
modules = [
	'otpme.lib.classes.data_objects.failed_pass',
	'otpme.lib.classes.data_objects.revoked_signature',
	'otpme.lib.classes.data_objects.token_counter',
	'otpme.lib.classes.data_objects.data_revision',
	'otpme.lib.classes.data_objects.used_hash',
	'otpme.lib.classes.data_objects.used_otp',
	'otpme.lib.classes.data_objects.used_sotp',
	'otpme.lib.classes.data_objects.rsa_key',
	'otpme.lib.classes.data_objects.cert',
    ]

def register():
    """ Register object modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
