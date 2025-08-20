# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.response import decode_response
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-fs-1.0"

def register():
    config.register_otpme_protocol("fsd", PROTOCOL_VERSION)

class OTPmeFsP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-fs-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "fsd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeFsP1, self).__init__(self.daemon, **kwargs)

    def decode_response(self, *args, **kwargs):
        return decode_response(*args, **kwargs)
