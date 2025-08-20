# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import ujson
import struct

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import json
from otpme.lib.protocols import status_codes

from otpme.lib.exceptions import *

def build_response(status, data, encryption=None, encoding="base64",
    enc_key=None, compress=True, binary_data=None):
    """ Build response. """
    response = {'data':data}
    # Build response.
    if status is True:
        response['status_code'] = status_codes.OK
    elif status is None:
        response['status_code'] = status_codes.ABORT
    elif status is False:
        response['status_code'] = status_codes.ERR
    else:
        response['status_code'] = status
    # Encode/encrypt response.
    response = json.encode(response,
                    compress=compress,
                    compress_level=1,
                    encoding=encoding,
                    encryption=encryption,
                    enc_key=enc_key)
    response = response.encode()

    if binary_data is None:
        binary_data = b''

    header = {
        'text_length': len(response),
        'binary_length': len(binary_data)
    }
    header_bytes = ujson.dumps(header).encode('utf-8')
    header_len = struct.pack('>I', len(header_bytes))

    response = header_len + header_bytes + response + binary_data

    return response

def decode_response(response, encryption=None, encoding="base64", enc_key=None):
    """ Decode OTPme response. """
    if isinstance(response, str):
        response = response.decode()
    header_len = struct.unpack('>I', response[:4])[0]
    header_start = 4
    header_end = header_start + header_len
    header = ujson.loads(response[header_start:header_end].decode('utf-8'))
    text_start = header_end
    text_end = text_start + header['text_length']
    binary_start = text_end
    binary_end = binary_start + header['binary_length']
    binary_data = response[binary_start:binary_end]
    response = response[text_start:text_end].decode('utf-8')
    try:
        response = json.decode(response,
                        encoding=encoding,
                        encryption=encryption,
                        enc_key=enc_key)
    except Exception as e:
        msg = (_("Failed to decode JSON response: %s" % e))
        raise OTPmeException(msg)
    try:
        data = response['data']
    except:
        msg = "Invalid response: Data is missing"
        raise OTPmeException(msg)
    try:
        status_code = response['status_code']
    except:
        msg = "Invalid response: Status code missing"
        raise OTPmeException(msg)
    return status_code, data, binary_data
