# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.exceptions import *

HKDF_DEFAULTS = {
            'hash_algo' : 'SHA256',
            'key_len'   : 32,
            'version'   : 1,
            }

CONFIG_OPTIONS = {
                'default_pw_hash_hkdf_algo'      : {
                                                'type'      : str,
                                                'argument'  : 'hash_algo',
                                                'default'   : HKDF_DEFAULTS['hash_algo'],
                                            },
                'default_pw_hash_hkdf_key_len'      : {
                                                'type'      : int,
                                                'argument'  : 'key_len',
                                                'default'   : HKDF_DEFAULTS['key_len'],
                                            },
                }

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_hash_type(hash_type="HKDF",
                            hash_func=derive,
                            default_opts=HKDF_DEFAULTS,
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

def derive(secret, hash_algo="SHA256", key_len=32,
    salt=None, info=None, backend=None, **kwargs):
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
    kdf = HKDF(algorithm=_hash_algo,
                length=key_len,
                salt=_salt,
                info=info,
                backend=backend)
    _hash = kdf.derive(secret)

    # Build result.
    result = {
            'hash'          : _hash,
            'hash_type'     : 'HKDF',
            'hash_algo'     : hash_algo,
            'key_len'       : key_len,
            'salt'          : salt,
            'version'       : 1,
            }

    return result
