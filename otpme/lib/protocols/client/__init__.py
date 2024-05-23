# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from .get_class import get_class

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

# Protocol modules to register.
modules = [
            'otpme.lib.protocols.client.agent1',
            'otpme.lib.protocols.client.auth1',
            'otpme.lib.protocols.client.join1',
            'otpme.lib.protocols.client.host1',
            'otpme.lib.protocols.client.mgmt1',
            'otpme.lib.protocols.client.sync1',
        ]

def register():
    """ Register protocol modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
