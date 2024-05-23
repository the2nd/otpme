# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import json
from otpme.lib.exceptions import *

def decode_command(command):
    pass

def build_request(command, command_args={},
    encryption=None, enc_key=None, compress=True):
    """ Build JSON request. """
    request = {
            'command'       : command,
            'command_args'  : command_args,
            }
    request = json.encode(request,
                        compress=compress,
                        compress_level=1,
                        encoding="base64",
                        encryption=encryption,
                        enc_key=enc_key)
    return request

def decode_request(request, encryption=None, enc_key=None):
    """ Decode OTPme request. """
    try:
        request = json.decode(request,
                            encoding="base64",
                            encryption=encryption,
                            enc_key=enc_key)
    except Exception as e:
        msg = "Failed to decode request: %s" % e
        raise OTPmeException(msg)
    # Get command and args.
    try:
        command = request['command']
    except:
        msg = "Received invalid request: Command is missing"
        raise OTPmeException(msg)
    try:
        command_args = request['command_args']
    except:
        msg = "Received invalid request: Command args missing"
        raise OTPmeException(msg)
    return command, command_args
