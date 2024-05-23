# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.exceptions import *

PBKDF2_DEFAULTS = {
            'iterations'    : 100000,
            'hash_algo'     : 'SHA256',
            'key_len'       : 128,
            }

CONFIG_OPTIONS = {
                'default_pw_hash_pbkdf2_iter'      : {
                                                'type'      : int,
                                                'argument'  : 'iterations',
                                                'default'   : PBKDF2_DEFAULTS['iterations'],
                                            },
                'default_pw_hash_pbkdf2_algo'      : {
                                                'type'      : str,
                                                'argument'  : 'hash_algo',
                                                'default'   : PBKDF2_DEFAULTS['hash_algo'],
                                            },
                'default_pw_hash_pbkdf2_key_len'      : {
                                                'type'      : int,
                                                'argument'  : 'key_len',
                                                'default'   : PBKDF2_DEFAULTS['key_len'],
                                            },
                }

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_hash_type(hash_type="PBKDF2",
                            hash_func=derive,
                            default_opts=PBKDF2_DEFAULTS,
                            config_opts=CONFIG_OPTIONS)
    # Object types our config parameters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                    'token',
                    ]
    for config_name in CONFIG_OPTIONS:
        ctype = CONFIG_OPTIONS[config_name]['type']
        default_value = CONFIG_OPTIONS[config_name]['default']
        config.register_config_parameter(name=config_name,
                                        ctype=ctype,
                                        default_value=default_value,
                                        object_types=object_types)

def derive(secret, hash_algo="SHA256", key_len=128, salt=None,
    iterations=100000, backend=None, quiet=True, **kwargs):
    if backend is None:
        backend = default_backend()
    if hash_algo is None:
        hash_algo = "SHA256"
    try:
        algo_method = getattr(hashes, hash_algo)
        _hash_algo = algo_method()
    except:
        msg = "Unknown hash type: %s" % hash_algo
        raise OTPmeException(msg)
    # Encode pw and salt.
    secret = secret.encode("utf-8")
    _salt = salt
    if salt is not None:
        _salt = salt.encode("utf-8")
    # Perform key derivation.
    kdf = PBKDF2HMAC(algorithm=_hash_algo,
                length=key_len,
                salt=_salt,
                iterations=iterations,
                backend=backend)
    _hash = kdf.derive(secret)

    # Build result.
    result = {
            'hash'          : _hash,
            'hash_type'     : 'PBKDF2',
            'hash_algo'     : hash_algo,
            'iterations'    : iterations,
            'key_len'       : key_len,
            'salt'          : salt,
            }

    return result
