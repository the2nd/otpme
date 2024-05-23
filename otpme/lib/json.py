# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.encoding.base import encode as _encode
from otpme.lib.encoding.base import decode as _decode

from otpme.lib.exceptions import *

def add_header(string, header):
    """ Add given header to string. """
    string = "%s{%s}" % (header, string)
    return string

def remove_header(string, header):
    """ Remove given header from string. """
    if not string.startswith("%s{" % header):
        return
    string = "}".join("{".join(string.split("{")[1:]).split("}")[:-1])
    return string

def encode(data, encoding=None, encryption=None, enc_key=None,
    compress=False, compress_level=1, **kwargs):
    """ Convert list/dict to JSON string. """
    # Generate JSON string.
    json_string = json.dumps(data, **kwargs)
    # Compress data.
    if compress:
        json_string = json_string.encode()
        if encoding is None:
            encoding = "hex"
        try:
            json_string = stuff.compress(json_string, "zlib", compress_level)
        except Exception as e:
            msg = (_("Error while compressing: %s") % e)
            raise OTPmeException(msg)
    # Encrypt data.
    if encryption:
        if encoding is None:
            encoding = "hex"
        if enc_key is None:
            msg = (_("Need <enc_key> when encryption is True."))
            raise OTPmeException(msg)
        try:
            json_string = encryption.encrypt(enc_key, json_string)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error while encrypting: %s") % e)
            raise OTPmeException(msg)
    # Encode data.
    if encoding:
        try:
            json_string = _encode(json_string, encoding).replace("\n", "")
        except Exception as e:
            msg = (_("Error while encoding: %s") % e)
            raise OTPmeException(msg)
    # Add headers.
    if compress:
        json_string = add_header(json_string, "JSON_COMPRESSED")
    if encryption:
        json_string = add_header(json_string, "JSON_ENCRYPTED")
    if encoding:
        json_string = add_header(json_string, "JSON_ENCODED")
    # Add JSON header.
    json_string = add_header(json_string, "JSON")
    return json_string

def decode(string, encoding=None, encryption=None,
    enc_key=None, compress=False):
    """ Convert JSON string to list/dict. """
    wrong_type = True
    try:
        if string.startswith("JSON{"):
            wrong_type = False
    except:
        pass
    if wrong_type:
        raise OTPmeTypeError("No JSON data found.")

    # Remove headers.
    json_string = remove_header(string, "JSON")

    encoded_data = remove_header(json_string, "JSON_ENCODED")
    if encoded_data:
        if encoding is None:
            encoding = "hex"
        json_string = encoded_data
    else:
        encoding = None

    encrypted_data = remove_header(json_string, "JSON_ENCRYPTED")
    if encrypted_data:
        if encryption is None:
            msg = (_("Found encrypted JSON data but got no <encryption>."))
            raise OTPmeException(msg)
        if enc_key is None:
            msg = (_("Found encrypted JSON data but got no <enc_key>."))
            raise OTPmeException(msg)
        json_string = encrypted_data
    else:
        encryption = None

    compressed_data = remove_header(json_string, "JSON_COMPRESSED")
    if compressed_data:
        compress = True
        if encoding is None:
            encoding = "hex"
        json_string = compressed_data
    else:
        compress = False

    # Decode data.
    if encoding:
        try:
            json_string = _decode(json_string, encoding)
        except Exception as e:
            msg = (_("Error while decoding: %s") % e)
            raise OTPmeException(msg)

    # Decrypt data.
    if encryption:
        try:
            json_string = encryption.decrypt(enc_key, json_string)
        except Exception as e:
            msg = (_("Error while decrypting: %s") % e)
            raise OTPmeException(msg)

    # Decompress data.
    if compress:
        try:
            json_string = stuff.decompress(json_string, "zlib")
        except Exception as e:
            msg = (_("Error while decompressing: %s") % e)
            raise OTPmeException(msg)

    # Return on empty string.
    if len(json_string) == 0:
        return json_string

    # Handle encoding stuff.
    if isinstance(json_string, bytes):
        json_string = json_string.decode()

    # Load JSON string.
    try:
        data = json.loads(json_string)
    except Exception as e:
        raise OTPmeException("%s: %s" % (e, json_string))

    return data
