# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.encryption import get_module

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

HASH_TYPES = [
                {
                'PBKDF2'  :{
                        'hash_algo' : 'sha256',
                        'encoding'  : 'hex',
                        'key_len'   : 32,
                        },
                'HKDF'  :{
                        'hash_algo' : 'SHA256',
                        'encoding'  : 'hex',
                        'key_len'   : 32,
                        },
                },
            ]

def register():
    from otpme.lib import config
    enc_mod = sys.modules[__name__]
    config.register_encryption_type("AES_CFB", enc_mod)

try:
    enc_module = get_module("aes")
except Exception as e:
    msg = "Unable to load encryption module: %s" % e
    raise OTPmeException(msg)

gen_key = getattr(enc_module, "gen_key")
derive_key = getattr(enc_module, "derive_key")

def encrypt(*args, **kwargs):
    kwargs['mode'] = "CFB"
    _encrypt = getattr(enc_module, "encrypt")
    return _encrypt(*args, **kwargs)

def decrypt(*args, **kwargs):
    kwargs['mode'] = "CFB"
    _encrypt = getattr(enc_module, "decrypt")
    return _encrypt(*args, **kwargs)
