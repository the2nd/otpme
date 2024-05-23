# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import jwt as _jwt
from jwt.api_jwt import _jwt_global_obj
from jwt.contrib.algorithms import pycrypto

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

_valid_algorithms = {
                    'RS256' : ['RSAAlgorithm', 'SHA256'],
                    'ES256' : ['ECAlgorithm', 'SHA256'],
                    'HS256' : ['HMACAlgorithm', 'SHA256'],
                }

def register_algorithm(algo):
    """ Register algorithm to JWT module """
    if not algo in _valid_algorithms:
        raise Exception(_("Unknown algorithm: %s") % algo)
    if algo in _jwt_global_obj._algorithms:
        return
    algo_class = _valid_algorithms[algo][0]
    hash_class = _valid_algorithms[algo][1]
    _algo_class = getattr(pycrypto, algo_class)
    _hash_class = getattr(_algo_class, hash_class)
    _jwt.register_algorithm(algo, _algo_class(_hash_class))

def encode(payload, key=None, secret=None, algorithm=None, **kwargs):
    """ Wrapper to call jwt.encode() """
    _key = ""
    if algorithm:
        register_algorithm(algorithm)
    if key:
        _key = key.private_key_base64
    if secret:
        _key = secret
    jwt_string = _jwt.encode(payload=payload,
                            key=_key,
                            algorithm=algorithm,
                            **kwargs)
    jwt_string = jwt_string.decode()
    return jwt_string

def decode(jwt, key=None, secret=None, algorithm=None, **kwargs):
    """ Wrapper to call jwt.decode() """
    _key = ""
    if algorithm:
        register_algorithm(algorithm)
    if key:
        _key = key.public_key_base64
    if secret:
        _key = secret
    jwt_data = _jwt.decode(jwt=jwt,
                        key=_key,
                        algorithm=algorithm,
                        **kwargs)
    return jwt_data
