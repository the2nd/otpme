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
PROTOCOL_VERSION = "OTPme-join-1.0"

def register():
    config.register_otpme_protocol("joind", PROTOCOL_VERSION)

class OTPmeJoinP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-join-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "joind"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeJoinP1, self).__init__(self.daemon, **kwargs)
