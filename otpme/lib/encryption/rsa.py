# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as _padding

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
#from otpme.lib import config
from otpme.lib import encryption
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.asymmetric_key_handler import AsymmetricKeyHandler

from otpme.lib.exceptions import *

class RSAKey(AsymmetricKeyHandler):
    """ Represents a RSA private/public key pair. """
    def __init__(self, **kwargs):
        super(RSAKey, self).__init__(**kwargs)

    def gen_key(self, bits=2048, public_exponent=65537, backend=None):
        """ Generate RSA private/public key pair of len 'bits'. """
        if backend is None:
            backend = default_backend()
        private_key = rsa.generate_private_key(public_exponent=public_exponent,
                                                key_size=bits, backend=backend)
        return private_key

    def encrypt(self, cleartext, cipher='PKCS1_OAEP',
        algorithm="SHA1", encoding=None):
        """ Encrypt cleartext with our public key. """
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        # Get cleartext as bytes.
        if isinstance(cleartext, str):
            cleartext = cleartext.encode()
        if cipher == 'PKCS1_OAEP':
            _mgf = _padding.MGF1(algorithm=hash_algo_method())
            padding = _padding.OAEP(mgf=_mgf,
                                algorithm=hash_algo_method(),
                                label=None)
            ciphertext = self.public_key.encrypt(cleartext, padding)
        elif cipher == 'PKCS1_v1_5':
            padding = _padding.PKCS1v15()
            ciphertext = self.public_key.encrypt(cleartext, padding)
        else:
            raise OTPmeException("'cipher' must be 'PKCS1_v1_5', 'PKCS1_OAEP'")
        if encoding is not None:
            ciphertext = encode(ciphertext, encoding)
        return ciphertext

    def decrypt(self, ciphertext, cipher='PKCS1_OAEP',
        algorithm="SHA1", encoding=None):
        """ Decrypt ciphertext with our private key. """
        if encoding is not None:
            ciphertext = decode(ciphertext, encoding)
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        if cipher == 'PKCS1_OAEP':
            _mgf = _padding.MGF1(algorithm=hash_algo_method())
            padding = _padding.OAEP(mgf=_mgf,
                                algorithm=hash_algo_method(),
                                label=None)
            plaintext = self.private_key.decrypt(ciphertext, padding)
        elif cipher == 'PKCS1_v1_5':
            padding = _padding.PKCS1v15()
            plaintext = self.private_key.decrypt(ciphertext, padding)
        else:
            raise OTPmeException("'cipher' must be 'PKCS1_v1_5', 'PKCS1_OAEP'")
        return plaintext

    def sign(self, message=None, digest=None,
        padding='PSS', algorithm="SHA256", encoding=None):
        """ Sign data with our private key. """
        if not message and not digest:
            raise OTPmeException("Need at least 'message' or 'digest'.")
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        if padding == 'PSS':
            _mgf = _padding.MGF1(algorithm=hash_algo_method())
            padding = _padding.PSS(mgf=_mgf, salt_length=_padding.PSS.MAX_LENGTH)
        elif padding == "PKCS1v15":
            padding = _padding.PKCS1v15()
        else:
            msg = "Invalid padding: %s" % padding
            raise OTPmeException(msg)
        if message:
            message = message.encode()
        if digest:
            digest = stuff.decode(digest, "hex")
            pre_hashed = utils.Prehashed(hash_algo_method())
            signature = self.private_key.sign(digest, padding, pre_hashed)
        else:
            signature = self.private_key.sign(message, padding, hash_algo_method())
        if encoding is not None:
            signature = encode(signature, encoding)
        return signature

    def verify(self, signature, message=None, digest=None,
        padding='PSS', algorithm="SHA256", encoding=None):
        """ Verify signed data and clear-text with public key. """
        if not message and not digest:
            raise OTPmeException("Need at least 'message' or 'digest'.")
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        if padding == 'PSS':
            _mgf = _padding.MGF1(algorithm=hash_algo_method())
            padding = _padding.PSS(mgf=_mgf, salt_length=_padding.PSS.MAX_LENGTH)
        elif padding == "PKCS1v15":
            padding = _padding.PKCS1v15()
        else:
            msg = "Invalid padding: %s" % padding
            raise OTPmeException(msg)
        if message:
            message = message.encode()
        if encoding is not None:
            signature = decode(signature, encoding)
        if digest:
            digest = stuff.decode(digest, "hex")
            pre_hashed = utils.Prehashed(hash_algo_method())
            try:
                signature = self.public_key.verify(signature, digest, padding, pre_hashed)
                verify_result = True
            except exceptions.InvalidSignature:
                verify_result = False
        else:
            try:
                self.public_key.verify(signature, message, padding, hash_algo_method())
                verify_result = True
            except exceptions.InvalidSignature:
                verify_result = False
        if verify_result is True:
            return True
        return False

def derive_key_pair_from_pass(password, salt, hash_type="Argon2_d",
    hash_len=128, iterations=2, threads=8, memory=256, key_len=2048):
    """ Derive always the same key pair from a static password. """
    # https://stackoverflow.com/questions/20483504/making-rsa-keys-from-a-password-in-python
    from Cryptodome.PublicKey import RSA
    def my_rand(n):
        my_rand.counter += 1
        my_salt = "my_salt:%d" % my_rand.counter
        x = encryption.hash_password(master_key,
                                hash_type=hash_type,
                                salt=my_salt,
                                threads=threads,
                                memory=memory,
                                key_len=n,
                                iterations=1)['hash']
        x = x.encode()
        return x

    master_key = encryption.hash_password(password,
                                    hash_type=hash_type,
                                    salt=salt,
                                    threads=threads,
                                    memory=memory,
                                    key_len=hash_len,
                                    iterations=iterations)['hash']
    my_rand.counter = 0
    rsa_key = RSA.generate(key_len, randfunc=my_rand)
    #rsa_key_base64 = rsa_key.exportKey())
    return rsa_key
