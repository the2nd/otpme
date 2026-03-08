# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.client.fs import OTPmeFsClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-fs-1.0"

def register():
    config.register_otpme_protocol("fsd", PROTOCOL_VERSION)

class OTPmeFsP1(OTPmeFsClient1):
    """ Class that implements client for protocol OTPme-fs-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "fsd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeFsP1, self).__init__(self.daemon, **kwargs)
