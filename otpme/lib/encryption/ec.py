# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.encoding.base import encode as _encode
from otpme.lib.encoding.base import decode as _decode
from otpme.lib.encryption.asymmetric_key_handler import AsymmetricKeyHandler

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_ecdh_curve("SECP384R1")
    #config.register_ecdh_hash_type("SHA256")

class ECKey(AsymmetricKeyHandler):
    def __init__(self, **kwargs):
        super(ECKey, self).__init__(**kwargs)

    def gen_key(self, curve="SECP384R1", backend=None):
        """ Generate private key. """
        if backend is None:
            backend = default_backend()
        try:
            curve_method = getattr(ec, curve)
            curve = curve_method()
        except:
            msg = "Unknown curve: %s" % curve
            raise OTPmeException(msg)
        private_key = ec.generate_private_key(curve=curve, backend=backend)
        return private_key

    def dhexchange(self, peer_public_key,
        algorithm="ECDH", backend=None, encode="hex"):
        """ Generate DH shared secret. """
        if backend is None:
            backend = default_backend()
        if algorithm is None:
            algorithm = "ECDH"
        try:
            algo_method = getattr(ec, algorithm)
            algorithm = algo_method()
        except:
            msg = "Unknown algorithm: %s" % algorithm
            raise OTPmeException(msg)
        shared_key = self.private_key.exchange(algorithm, peer_public_key)
        if encode is not None:
            shared_key = _encode(shared_key, "hex")
        return shared_key

    def sign(self, message=None, digest=None, algorithm="SHA256"):
        """ Sign data with our private key. """
        if not message and not digest:
            raise OTPmeException("Need at least 'message' or 'digest'.")
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        if message:
            message = message.encode()
        if digest:
            digest = _decode(digest, "hex")
            pre_hashed = utils.Prehashed(hash_algo_method())
            signature = self.private_key.sign(digest, ec.ECDSA(pre_hashed))
        else:
            signature = self.private_key.sign(message,
                            ec.ECDSA(hash_algo_method()))
        return signature

    def verify(self, signature, message=None, digest=None, algorithm="SHA256"):
        """ Verify signed data and clear-text with public key. """
        if not message and not digest:
            raise OTPmeException("Need at least 'message' or 'digest'.")
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except:
            msg = "Unknown hash algorithm: %s" % algorithm
            raise OTPmeException(msg)
        if message:
            message = message.encode()
        if digest:
            digest = _decode(digest, "hex")
            pre_hashed = utils.Prehashed(hash_algo_method())
            try:
                signature = self.public_key.verify(signature,
                                                    digest,
                                                    ec.ECDSA(pre_hashed))
                verify_result = True
            except exceptions.InvalidSignature:
                verify_result = False
        else:
            try:
                self.public_key.verify(signature, message,
                                ec.ECDSA(hash_algo_method()))
                verify_result = True
            except exceptions.InvalidSignature:
                verify_result = False
        if verify_result is True:
            return True
        return False
