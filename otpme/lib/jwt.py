# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import jwt as _jwt

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

_valid_algorithms = ['RS256', 'ES256', 'HS256']

def register_algorithm(algo):
    """ Kept for API compatibility.

    PyJWT >= 2.0 ships RS256/ES256/HS256 out of the box when the
    'cryptography' package is available (it is a hard OTPme dependency),
    so no explicit registration is needed anymore.
    """
    if algo not in _valid_algorithms:
        msg = _("Unknown algorithm: {algorithm}")
        msg = msg.format(algorithm=algo)
        raise Exception(msg)

def encode(payload, key=None, secret=None, algorithm=None, **kwargs):
    """ Wrapper to call jwt.encode() """
    if not algorithm:
        msg = _("JWT algorithm must be specified.")
        raise Exception(msg)
    register_algorithm(algorithm)
    _key = ""
    if key:
        _key = key.private_key_base64
    if secret:
        _key = secret
    jwt_string = _jwt.encode(payload=payload,
                            key=_key,
                            algorithm=algorithm,
                            **kwargs)
    if isinstance(jwt_string, bytes):
        jwt_string = jwt_string.decode()
    return jwt_string

def decode(jwt, key=None, secret=None, algorithm=None, **kwargs):
    """ Wrapper to call jwt.decode() """
    if not algorithm:
        msg = _("JWT algorithm must be specified.")
        raise Exception(msg)
    register_algorithm(algorithm)
    _key = ""
    if key:
        _key = key.public_key_base64
    if secret:
        _key = secret
    jwt_data = _jwt.decode(jwt=jwt,
                        key=_key,
                        algorithms=[algorithm],
                        **kwargs)
    return jwt_data
