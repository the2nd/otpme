# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.encoding.base import encode
from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []

loaded_mods = {}
modules = [
	'otpme.lib.encryption.ec',
	'otpme.lib.encryption.aes_cfb',
	'otpme.lib.encryption.hkdf',
	'otpme.lib.encryption.argon2',
	'otpme.lib.encryption.fernet',
	'otpme.lib.encryption.pbkdf2',
        ]

def register():
    """ Register modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)

def get_module(enc_name):
    """ Get encryption module by type. """
    # Build module path to encryption module.
    enc_mod_path = "otpme.lib.encryption.%s" % enc_name.lower()
    try:
        enc_module = loaded_mods[enc_mod_path]
    except:
        # Import encryption module.
        try:
            enc_module = importlib.import_module(enc_mod_path)
        except:
            msg = "Unknown encryption: %s" % enc_mod_path
            raise OTPmeException(msg)
    return enc_module

def derive_key(secret, **kwargs):
    """ Derive key from secret. """
    # Generate hash.
    result = hash_password(secret, **kwargs)
    ##_hash = result.pop('hash')
    #_hash = result['hash']
    #key = _hash[0:key_len]
    #result['key'] = key
    result['key'] = result['hash']
    return result

def hash_password(password, salt=None, iterations=None,
    hash_type=None, hash_algo=None, quiet=True,
    encoding="hex", key_len=None, **kwargs):
    """ Generate password hash. """
    import time
    from otpme.lib import stuff
    from otpme.lib import config
    logger = config.logger

    if not quiet:
        logger.debug("Generating %s hash..." % hash_type)

    # Get hash type function.
    hash_function = config.get_hash_function(hash_type)
    # Get default opts for given hash type.
    default_opts = config.get_hash_type_default_otps(hash_type)

    if hash_algo is None:
        try:
            hash_algo = default_opts['hash_algo']
        except:
            pass
    if key_len is None:
        try:
            key_len = default_opts['key_len']
        except:
            pass
    if iterations is None:
        if 'iterations' in default_opts:
            if not quiet:
                logger.debug("Using default iterations.")
            iterations = default_opts['iterations']

    start_time = time.time()
    # Generate salt if needed.
    if salt is None:
        salt = stuff.gen_secret(32)

    # Generate hash.
    result = hash_function(password,
                        salt=salt,
                        iterations=iterations,
                        hash_algo=hash_algo,
                        key_len=key_len,
                        quiet=quiet, **kwargs)

    if encoding is not None:
        _hash = result['hash']
        _hash = encode(_hash, encoding)
        result['hash'] = _hash

    duration = time.time() - start_time
    if not quiet:
        logger.debug("Duration: %f" % duration)

    return result

def verify_pass_hash(result, password):
    """ Verify password hash result from password_hash(). """
    hash_type = result['hash_type']
    pass_hash = result['hash']
    iterations = result['iterations']
    threads = result['threads']
    memory = result['memory']
    salt = result['salt']
    # Get hash type function.
    hash_function = config.get_hash_function(hash_type)
    # Generate and verify hash.
    result = hash_function(password=password,
                        salt=salt,
                        iterations=iterations,
                        hash_type=hash_type,
                        threads=threads,
                        memory=memory,
                        quiet=quiet, **kwargs)
    if result['hash'] == pass_hash:
        return True
    return False
