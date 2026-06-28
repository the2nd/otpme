# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import hmac
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib.encoding.base import encode
from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []

loaded_mods = {}
modules = [
	'otpme.lib.encryption.ec',
	'otpme.lib.encryption.ed25519',
	'otpme.lib.encryption.x25519',
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


def load_public_key(pem):
    """ Parse a public-key PEM (str or bytes) and return the matching
    OTPme wrapper (RSAKey / ECKey / Ed25519Key / X25519Key). Single
    parse pass -- the cryptography key object is handed to the wrapper
    directly via key_instance, no second load_pem_public_key call. """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.asymmetric import x25519 as _x25519
    if isinstance(pem, str):
        pem = pem.encode()
    key_obj = load_pem_public_key(pem)
    if isinstance(key_obj, rsa.RSAPublicKey):
        from otpme.lib.encryption.rsa import RSAKey
        return RSAKey(key_instance=key_obj)
    if isinstance(key_obj, _ed25519.Ed25519PublicKey):
        from otpme.lib.encryption.ed25519 import Ed25519Key
        return Ed25519Key(key_instance=key_obj)
    if isinstance(key_obj, _x25519.X25519PublicKey):
        from otpme.lib.encryption.x25519 import X25519Key
        return X25519Key(key_instance=key_obj)
    if isinstance(key_obj, _ec.EllipticCurvePublicKey):
        from otpme.lib.encryption.ec import ECKey
        return ECKey(key_instance=key_obj)
    msg = _("Unsupported public key type: {t}")
    msg = msg.format(t=type(key_obj).__name__)
    raise OTPmeException(msg)


def gen_keypair(algo, **kwargs):
    """ Create a fresh asymmetric key wrapper for the given algo.
    Extra kwargs (e.g. bits=2048 for rsa) are forwarded to the
    underlying gen_key(). """
    if algo == "rsa":
        from otpme.lib.encryption.rsa import RSAKey
        return RSAKey(**kwargs)
    if algo == "ed25519":
        from otpme.lib.encryption.ed25519 import Ed25519Key
        return Ed25519Key(**kwargs)
    if algo == "x25519":
        from otpme.lib.encryption.x25519 import X25519Key
        return X25519Key(**kwargs)
    if algo == "ec":
        from otpme.lib.encryption.ec import ECKey
        return ECKey(**kwargs)
    msg = _("Unsupported keygen algo: {algo}")
    msg = msg.format(algo=algo)
    raise OTPmeException(msg)


def load_private_key(pem, password=None, aes_key=None):
    """ Parse a private-key PEM (str or bytes) and return the matching
    OTPme wrapper. password is forwarded to cryptography's loader for
    PEM-encrypted keys. aes_key triggers the OTPme AES keypack unwrap
    (matches RSAKey(key=..., aes_key=...) semantics) before parsing. """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.asymmetric import x25519 as _x25519
    if aes_key is not None:
        # AES-wrapped keypack -- unwrap via the base handler (instance
        # only needed for the decrypt_key method; no algo dispatch yet).
        from otpme.lib.encryption.asymmetric_key_handler import AsymmetricKeyHandler
        unwrapper = AsymmetricKeyHandler.__new__(AsymmetricKeyHandler)
        unwrapper.pass_hash_type = "PBKDF2"
        pem = unwrapper.decrypt_key(key_pack=pem, aes_key=aes_key)
    if isinstance(pem, str):
        pem = pem.encode()
    if isinstance(password, str):
        password = password.encode()
    key_obj = load_pem_private_key(pem, password=password)
    if isinstance(key_obj, rsa.RSAPrivateKey):
        from otpme.lib.encryption.rsa import RSAKey
        return RSAKey(key_instance=key_obj)
    if isinstance(key_obj, _ed25519.Ed25519PrivateKey):
        from otpme.lib.encryption.ed25519 import Ed25519Key
        return Ed25519Key(key_instance=key_obj)
    if isinstance(key_obj, _x25519.X25519PrivateKey):
        from otpme.lib.encryption.x25519 import X25519Key
        return X25519Key(key_instance=key_obj)
    if isinstance(key_obj, _ec.EllipticCurvePrivateKey):
        from otpme.lib.encryption.ec import ECKey
        return ECKey(key_instance=key_obj)
    msg = _("Unsupported private key type: {t}")
    msg = msg.format(t=type(key_obj).__name__)
    raise OTPmeException(msg)

def get_module(enc_name):
    """ Get encryption module by type. """
    # Build module path to encryption module.
    enc_mod_path = f"otpme.lib.encryption.{enc_name.lower()}"
    try:
        enc_module = loaded_mods[enc_mod_path]
    except Exception:
        # Import encryption module.
        try:
            enc_module = importlib.import_module(enc_mod_path)
        except Exception:
            msg = _("Unknown encryption: {path}")
            msg = msg.format(path=enc_mod_path)
            raise OTPmeException(msg) from None
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
        log_msg = _("Generating {hash_type} hash...", log=True)[1]
        log_msg = log_msg.format(hash_type=hash_type)
        logger.debug(log_msg)

    # Get hash type function.
    hash_function = config.get_hash_function(hash_type)
    # Get default opts for given hash type.
    default_opts = config.get_hash_type_default_otps(hash_type)

    if hash_algo is None:
        try:
            hash_algo = default_opts['hash_algo']
        except Exception:
            pass
    if key_len is None:
        try:
            key_len = default_opts['key_len']
        except Exception:
            pass
    if iterations is None:
        if 'iterations' in default_opts:
            if not quiet:
                log_msg = _("Using default iterations.", log=True)[1]
                logger.debug(log_msg)
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
        log_msg = _("Duration: %f" % duration, log=True)[1]
        logger.debug(log_msg)

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
    if hmac.compare_digest(result['hash'], pass_hash):
        return True
    return False
