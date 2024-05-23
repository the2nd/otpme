# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from . import server
from . import client

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

def register():
    """ Register protocol modules. """
    # Register modules.
    server.register()
    client.register()
