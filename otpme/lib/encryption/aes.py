# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import encryption
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

GCM_NONCE_SIZE = 12

def gen_key(key_len=32):
    """ Gen AES key. """
    aes_key = os.urandom(key_len)
    aes_key = encode(aes_key, "hex")
    return aes_key

def derive_key(password, salt=None, encoding="hex", **kwargs):
    """ Derive key from password. """
    # Derive key from password.
    result = encryption.derive_key(password,
                                salt=salt,
                                encoding=encoding,
                                **kwargs)
    return result

def encrypt(key, data, encoding=None, mode="GCM", backend=None):
    """ Encrypt string with given AES key. """
    _key = decode(key, "hex")
    if isinstance(data, str):
        data = data.encode()

    if mode == "GCM":
        nonce = os.urandom(GCM_NONCE_SIZE)
        aesgcm = AESGCM(_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        result = nonce + ciphertext
    else:
        try:
            _mode = getattr(modes, mode)
        except:
            msg = _("Unknown AES mode: {mode}")
            msg = msg.format(mode=mode)
            raise OTPmeException(msg)
        if backend is None:
            backend = default_backend()
        try:
            iv = os.urandom(16)
        except Exception as e:
            msg = _("Failed to gen IV data: {error}")
            msg = msg.format(error=e)
            raise EncryptException(msg)
        try:
            algo = algorithms.AES(_key)
            cipher = Cipher(algo, _mode(iv), backend=backend)
        except Exception as e:
            msg = _("Failed to load AES key: {error}")
            msg = msg.format(error=e)
            raise EncryptException(msg)
        try:
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data)
            ciphertext = iv + ciphertext
            encryptor.finalize()
        except Exception as e:
            msg = _("Failed encrypt data: {error}")
            msg = msg.format(error=e)
            raise EncryptException(msg)
        result = ciphertext

    if encoding is None:
        return result
    return encode(result, encoding)

def decrypt(key, aesdata, encoding=None, mode="GCM", backend=None):
    """ Decrypt data with given AES key. """
    if aesdata == "" or aesdata == b"":
        return ""
    if encoding is not None:
        try:
            aesdata = decode(aesdata, encoding)
        except Exception as e:
            msg = _("Failed to decode AES data: {error}")
            msg = msg.format(error=e)
            raise DecryptException(msg)

    _key = decode(key, "hex")

    if mode == "GCM":
        nonce = aesdata[:GCM_NONCE_SIZE]
        ciphertext = aesdata[GCM_NONCE_SIZE:]
        aesgcm = AESGCM(_key)
        try:
            cleartext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            msg = _("Failed to decrypt data: {error}")
            msg = msg.format(error=e)
            raise DecryptException(msg)
    else:
        try:
            _mode = getattr(modes, mode)
        except:
            msg = _("Unknown AES mode: {mode}")
            msg = msg.format(mode=mode)
            raise OTPmeException(msg)
        if backend is None:
            backend = default_backend()
        iv = aesdata[:16]
        data = aesdata[16:]
        try:
            algo = algorithms.AES(_key)
            cipher = Cipher(algo, _mode(iv), backend=backend)
        except Exception as e:
            msg = _("Failed to load AES key: {error}")
            msg = msg.format(error=e)
            raise EncryptException(msg)
        try:
            decryptor = cipher.decryptor()
            cleartext = decryptor.update(data)
            decryptor.finalize()
        except Exception as e:
            msg = _("Failed to decrypt data: {error}")
            msg = msg.format(error=e)
            raise DecryptException(msg)

    # Try to return string.
    try:
        cleartext = cleartext.decode()
    except (ValueError, UnicodeDecodeError):
        pass
    return cleartext
