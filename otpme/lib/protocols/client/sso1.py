# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-sso-1.0"

def register():
    config.register_otpme_protocol("ssod", PROTOCOL_VERSION)

class OTPmeSsoP1(OTPmeClient1):
    """ Class that implements client for protocol OTPme-sso-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "ssod"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeSsoP1, self).__init__(self.daemon, **kwargs)
