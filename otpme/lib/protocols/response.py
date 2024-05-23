# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import json
from otpme.lib.protocols import status_codes

from otpme.lib.exceptions import *

def build_response(status, data, encryption=None,
    enc_key=None, compress=True):
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
                    encoding="base64",
                    encryption=encryption,
                    enc_key=enc_key)
    return response

def decode_response(response, encryption=None, enc_key=None):
    """ Decode OTPme response. """
    try:
        response = json.decode(response,
                        encoding="base64",
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
    return status_code, data
