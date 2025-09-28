# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms

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

def encrypt(key, data, encoding=None, mode="CFB", backend=None):
    """ Encrypt string with given AES key. """
    try:
        mode = getattr(modes, mode)
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
    _key = decode(key, "hex")
    try:
        algo = algorithms.AES(_key)
        cipher = Cipher(algo, mode(iv), backend=backend)
    except Exception as e:
        msg = _("Failed to load AES key: {error}")
        msg = msg.format(error=e)
        raise EncryptException(msg)
    data = data.encode()
    try:
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data)
        ciphertext = iv + ciphertext
        encryptor.finalize()
    except Exception as e:
        msg = _("Failed encrypt data: {error}")
        msg = msg.format(error=e)
        raise EncryptException(msg)
    if encoding is None:
        return ciphertext
    return encode(ciphertext, encoding)

def decrypt(key, aesdata, encoding=None, mode="CFB", backend=None):
    """ Decrypt data with given AES key. """
    if aesdata == "":
        return ""
    #aesdata = aesdata.encode("ascii")
    try:
        mode = getattr(modes, mode)
    except:
        msg = _("Unknown AES mode: {mode}")
        msg = msg.format(mode=mode)
        raise OTPmeException(msg)
    if backend is None:
        backend = default_backend()
    if encoding is not None:
        try:
            aesdata = decode(aesdata, encoding)
        except Exception as e:
            msg = _("Failed to decode AES data: {error}")
            msg = msg.format(error=e)
            raise DecryptException(msg)
    iv = aesdata[:16]
    data = aesdata[16:]
    _key = decode(key, "hex")
    try:
        algo = algorithms.AES(_key)
        cipher = Cipher(algo, mode(iv), backend=backend)
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
    except ValueError:
        pass
    return cleartext
