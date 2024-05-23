# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import codecs
import base64

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    """ Register encoding types. """
    from otpme.lib import config
    enc_mod = sys.modules[__name__]
    config.register_encoding_type("HEX", enc_mod)
    config.register_encoding_type("BASE32", enc_mod)
    config.register_encoding_type("BASE64", enc_mod)

def encode(data, encoding, oneline=True):
    """ Encode given data. """
    # Make sure data is bytes()
    if isinstance(data, str):
        data = data.encode()
    # Encode data.
    if encoding == "base64":
        encoded_data = base64.b64encode(data)
    elif encoding == "base32":
        encoded_data = base64.b32encode(data)
    else:
        encoded_data = codecs.encode(data, encoding)
    # Remove newlines.
    if encoding == "base64" and oneline:
        encoded_data = encoded_data.replace(b"\n", b"")
    # Make sure we return string.
    if isinstance(encoded_data, bytes):
        encoded_data = encoded_data.decode()
    return encoded_data

def decode(data, encoding):
    """ Decode given data. """
    # Make sure data is bytes()
    if isinstance(data, str):
        data = data.encode()
    if encoding == "base64":
        decoded_data = base64.b64decode(data)
    elif encoding == "base32":
        decoded_data = base64.b32decode(data)
    else:
        decoded_data = codecs.decode(data, encoding)
    # Try to return string.
    try:
        decoded_data = decoded_data.decode()
    except ValueError:
        pass
    return decoded_data
