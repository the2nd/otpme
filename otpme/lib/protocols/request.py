# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import struct
import ujson

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import json
from otpme.lib.exceptions import *

def build_request(command, command_args={}, encryption=None,
    enc_key=None, compress=True, encoding="base64", binary_data=None):
    """ Build JSON request. """
    request = {
            'command'       : command,
            'command_args'  : command_args,
            }
    request = json.encode(request,
                        compress=compress,
                        compress_level=1,
                        encoding=encoding,
                        encryption=encryption,
                        enc_key=enc_key)
    request = request.encode()

    if binary_data is None:
        binary_data = b''

    header = {
        'text_length': len(request),
        'binary_length': len(binary_data)
    }
    header_bytes = ujson.dumps(header).encode('utf-8')
    header_len = struct.pack('>I', len(header_bytes))

    request = header_len + header_bytes + request + binary_data

    return request

def decode_request(request, encoding="base64", encryption=None, enc_key=None):
    """ Decode OTPme request. """
    header_len = struct.unpack('>I', request[:4])[0]
    header_start = 4
    header_end = header_start + header_len
    header = ujson.loads(request[header_start:header_end].decode('utf-8'))
    text_start = header_end
    text_end = text_start + header['text_length']
    binary_start = text_end
    binary_end = binary_start + header['binary_length']
    binary_data = request[binary_start:binary_end]
    request = request[text_start:text_end].decode('utf-8')

    try:
        request = json.decode(request,
                            encoding=encoding,
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
    return command, command_args, binary_data
