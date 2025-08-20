# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
from cryptography.fernet import Fernet

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import encryption
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

HASH_TYPES = [
                {
                    'HKDF' : {
                        'hash_algo' : 'SHA256',
                        'encoding'  : 'base64',
                        'key_len'   : 32,
                        }
                }
            ]
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

def register():
    from otpme.lib import config
    enc_mod = sys.modules[__name__]
    config.register_encryption_type("FERNET", enc_mod)

def gen_key():
    """ Gen encryption key. """
    enc_key = Fernet.generate_key()
    enc_key = enc_key.decode()
    return enc_key

def derive_key(secret, salt=None, encoding="base64", key_len=32, **kwargs):
    """ Derive key from secret. """
    # Derive key from secret.
    result = encryption.derive_key(secret,
                                salt=salt,
                                encoding=encoding,
                                key_len=key_len,
                                **kwargs)
    return result

def encrypt(enc_key, data, encoding=None):
    """ Encrypt string with given key. """
    try:
        cipher_suite = Fernet(enc_key)
    except Exception as e:
        raise EncryptException("Failed to load encryption key: %s" % e)
    if isinstance(data, str):
        data = data.encode()
    try:
        encrypted_data = cipher_suite.encrypt(data)
    except Exception as e:
        raise EncryptException("Failed encrypt data: %s" % e)
    encrypted_data = encrypted_data.decode()
    if encoding is None:
        return encrypted_data
    return encode(encrypted_data, encoding)

def decrypt(enc_key, data, encoding=None, return_str=True):
    """ Decrypt data with given AES key. """
    if data == "":
        return ""
    if encoding is not None:
        try:
            data = decode(data, encoding)
        except Exception as e:
            raise DecryptException("Failed to decode data: %s" % e)
    # Make sure data is bytes.
    if isinstance(data, str):
        data = data.encode()
    if isinstance(enc_key, str):
        enc_key = enc_key.encode()
    try:
        cipher_suite = Fernet(enc_key)
    except Exception as e:
        raise DecryptException("Failed to load decryption key: %s" % e)
    try:
        decrypted_data = cipher_suite.decrypt(data)
    except Exception as e:
        raise DecryptException("Failed to decrypt data: %s" % e)
    if return_str:
        # Try to return string.
        try:
            decrypted_data = decrypted_data.decode()
        except ValueError:
            pass
    return decrypted_data
