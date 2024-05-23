# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import encryption
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

class AsymmetricKeyHandler(object):
    def __init__(self, key_file=None, key=None,
        password=None, aes_key=None, **kwargs):
        self._public_key = None
        self._private_key = None
        self._public_key_base64 = None
        self._private_key_base64 = None
        self._ssh_public_key = None
        #self._ssh_private_key = None
        self.pass_hash_type = "PBKDF2"
        if key_file:
            fd = open(key_file, "r")
            key = fd.read()
            fd.close()
        if key:
            if password or aes_key:
                key = self.decrypt_key(key_pack=key,
                                    password=password,
                                    aes_key=aes_key)
            self.load_key(key=key)
        else:
            self._private_key = self.gen_key(**kwargs)
        super(AsymmetricKeyHandler, self).__init__()

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        if self._public_key:
            return self._public_key
        if self._private_key:
            return self._private_key.public_key()
        return

    @property
    def private_key_base64(self):
        if not self._private_key_base64:
            self._private_key_base64 = self.export_private_key('PEM')
        return self._private_key_base64

    @property
    def public_key_base64(self):
        if not self._public_key_base64:
            self._public_key_base64 = self.export_public_key('PEM')
        return self._public_key_base64

    @property
    def ssh_public_key(self):
        if not self._ssh_public_key:
            self._ssh_public_key = self.export_public_key(encoding="openssh",
                                                        key_format='openssh')
        return self._ssh_public_key

    #@property
    #def ssh_private_key(self):
    #    if not self._ssh_private_key:
    #        self._ssh_private_key = self.export_private_key(encoding="openssh",
    #                                                    key_format='openssh')
    #    return self._ssh_private_key

    def fingerprint(self, algorithm="SHA256"):
        """ Get cert fingerprint. """
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        public_key_der = self.export_public_key(encoding="DER")
        hasher = hashes.Hash(hash_algo_method(), backend=default_backend())
        hasher.update(public_key_der)
        digest = hasher.finalize()
        fingerprint = encode(digest, "hex")
        return fingerprint

    def export_private_key(self, encoding="PEM",
        key_format="openssl", password=None):
        """ Export private key. """
        if key_format == "openssl":
            key_format = PrivateFormat.TraditionalOpenSSL
        elif key_format == "PKCS8":
            key_format = PrivateFormat.PKCS8
        # Available since version 3.0.
        #elif key_format == "openssh":
        #    key_format = PrivateFormat.OpenSSH
        else:
            msg = "Unknown key format: %s" % key_format
            raise OTPmeException(msg)
        if encoding == "PEM":
            _encoding = Encoding.PEM
        elif encoding == "DER":
            _encoding = Encoding.DER
        elif encoding == "openssh":
            _encoding = Encoding.OpenSSH
        else:
            msg = "Invalid encoding: %s" % encoding
            raise OTPmeException(msg)
        if password is None:
            encryption_algorithm = NoEncryption()
        else:
            password = password.encode()
            encryption_algorithm = BestAvailableEncryption(password)
        key_data = self._private_key.private_bytes(_encoding,
                                                key_format,
                                                encryption_algorithm)
        if encoding == "PEM":
            key_data = key_data.decode()
        return key_data

    def export_public_key(self, encoding="PEM", key_format="subject_info"):
        """ Export public key. """
        if key_format == "subject_info":
            key_format = PublicFormat.SubjectPublicKeyInfo
        elif key_format == "PKCS1":
            key_format = PublicFormat.PKCS1
        elif key_format == "openssh":
            key_format = PublicFormat.OpenSSH
        else:
            msg = "Unknown key format: %s" % key_format
            raise OTPmeException(msg)
        if encoding == "PEM":
            _encoding = Encoding.PEM
        elif encoding == "DER":
            _encoding = Encoding.DER
        elif encoding == "openssh":
            _encoding = Encoding.OpenSSH
        else:
            msg = "Invalid encoding: %s" % encoding
            raise OTPmeException(msg)
        key_data = self.public_key.public_bytes(_encoding, key_format)
        if encoding == "PEM":
            key_data = key_data.decode()
        return key_data

    def load_private_key(self, key_data,
        encoding="PEM", password=None, backend=None):
        if isinstance(key_data, str):
            key_data = key_data.encode()
        if backend is None:
            backend = default_backend()
        if encoding == "PEM":
            private_key = load_pem_private_key(key_data,
                                            password=password,
                                            backend=backend)
        elif encoding == "DER":
            private_key = load_der_private_key(key_data,
                                            password=password,
                                            backend=backend)
        else:
            msg = "Invalid encoding: %s" % encoding
            raise OTPmeException(msg)
        return private_key

    def load_public_key(self, key_data, encoding="PEM", backend=None):
        if isinstance(key_data, str):
            key_data = key_data.encode()
        if backend is None:
            backend = default_backend()
        if encoding == "PEM":
            public_key = load_pem_public_key(key_data, backend)
        elif encoding == "DER":
            public_key = load_der_public_key(key_data, backend)
        else:
            msg = "Invalid encoding: %s" % encoding
            raise OTPmeException(msg)
        return public_key

    def load_key(self, key_file=None, key=None,
        encoding="PEM", password=None, backend=None):
        """ Load RSA key from file or string. """
        if backend is None:
            backend = default_backend()
        if key:
            key_data = key
        elif key_file:
            try:
                fd = open(key_file, "r")
                key_data = fd.read()
                fd.close()
            except Exception as e:
                msg = (_("Unable to load key from file: %s") % e)
                raise OTPmeException(msg)
        else:
            msg = ("Need 'key' or 'key_file'!")
            raise OTPmeException(msg)
        try:
            self._private_key = self.load_private_key(key_data,
                                                encoding=encoding,
                                                password=password,
                                                backend=backend)
        except:
            self._public_key = self.load_public_key(key_data,
                                                encoding=encoding,
                                                backend=backend)

    def encrypt_key(self, password=None, hash_type=None,
        aes_key=None, encoding="base64"):
        """ Return AES encrypted private key. """
        if not password and not aes_key:
            raise Exception("Need 'password' or 'aes_key'.")
        if hash_type is None:
            hash_type = self.pass_hash_type
        if password:
            x = encryption.derive_key(password, hash_type=hash_type)
            aes_key = x['key']
            salt = x['salt']
        else:
            salt = "NULL"
        encrypted_key = encryption.aes.encrypt(aes_key, self.private_key_base64)
        encoded_key = encode(encrypted_key, "hex")
        key_pack = {'salt':salt, 'key':encoded_key, 'hash_type':hash_type}
        key_pack = json.dumps(key_pack)
        return key_pack

    def decrypt_key(self, key_pack, password=None, aes_key=None, encoding="base64"):
        """ Decrypt AES encrypted private key. """
        if not password and not aes_key:
            raise Exception("Need 'password' or 'aes_key'.")
        decoded_key_pack = json.loads(key_pack)
        if password:
            salt = decoded_key_pack['salt']
            hash_type = decoded_key_pack['hash_type']
            aes_key = encryption.derive_key(password,
                                        salt=salt,
                                        hash_type=hash_type)['key']
            # Remember hash type.
            self.pass_hash_type = hash_type
        encrypted_key = decoded_key_pack['key']
        encrypted_key = decode(encrypted_key, "hex")
        private_key = encryption.aes.decrypt(aes_key, encrypted_key)
        return private_key
