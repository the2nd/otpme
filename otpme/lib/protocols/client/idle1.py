# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-idle-1.0"

def register():
    config.register_otpme_protocol("idled", PROTOCOL_VERSION)

class OTPmeIdleP1(OTPmeClient1):
    """ Class that implements client for protocol OTPme-idle-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "idled"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super().__init__(self.daemon, **kwargs)

    def wait(self):
        """ Wait. """
        command = "wait"
        command_args = {}
        status, \
        status_code, \
        response, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = _("Failed to send wait command: {response}")
            msg = msg.format(response=response)
            raise OTPmeException(msg)
        return response

