# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.request import build_request
from otpme.lib.protocols.response import decode_response

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []

PROTOCOL_VERSION = "OTPme-agent-1.0"

def register():
    config.register_otpme_protocol("agent", PROTOCOL_VERSION)

class OTPmeAgentP1(object):
    """ Class that implements management client for protocol OTPme-agent-1.0. """
    def __init__(self, **kwargs):
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeAgentP1, self).__init__(**kwargs)

    def build_request(self, daemon, command, realm, site, use_dns=True,
        command_args=None, encode_request=True, encrypt_request=True, **kwargs):
        """ Build agent request. """
        # Original request parameters.
        proxy_request = {
                        'command'           : command,
                        'command_args'      : command_args,
                        'encode_request'    : encode_request,
                        'encrypt_request'   : encrypt_request,
                        }
        # Agent request parameters.
        request_args = {
                        'realm'             : realm,
                        'site'              : site,
                        'daemon'            : daemon,
                        'use_dns'           : use_dns,
                        'proxy_request'     : proxy_request,
                        }
        request = build_request(command="proxy_command",
                                command_args=request_args)
        return request

    def decode_response(self, *args, **kwargs):
        return decode_response(*args, **kwargs)
