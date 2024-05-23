# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-auth-1.0"

def register():
    config.register_otpme_protocol("authd", PROTOCOL_VERSION)

class OTPmeAuthP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-auth-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "authd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeAuthP1, self).__init__(self.daemon, **kwargs)
