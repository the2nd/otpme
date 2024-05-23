# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from .get_class import get_class
from .get_class import get_module

REGISTER_BEFORE = []
REGISTER_AFTER = [
                'otpme.lib.encoding.base',
                'otpme.lib.protocols.otpme_server',
                ]

# Protocol modules to register.
modules = [
            'otpme.lib.protocols.server.join1',
            'otpme.lib.protocols.server.host1',
            'otpme.lib.protocols.server.mgmt1',
            'otpme.lib.protocols.server.sync1',
            'otpme.lib.protocols.server.agent1',
            'otpme.lib.protocols.server.auth1',
            'otpme.lib.protocols.server.cluster1',
        ]

def register():
    """ Register protocol modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)
