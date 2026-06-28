# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib.encoding.base import encode as _encode
from otpme.lib.encoding.base import decode as _decode
from otpme.lib.encryption.asymmetric_key_handler import AsymmetricKeyHandler

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []

# Map cryptography curve.name (lower-case) → HPKE KEM enum.
# Extend when introducing a new ECDH-capable curve.
HPKE_KEM_BY_CURVE = {
    "secp256r1" : hpke.KEM.P256,
    "secp384r1" : hpke.KEM.P384,
    "secp521r1" : hpke.KEM.P521,
}

# Pair each curve with an HKDF hash of matching security level
# (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512) as recommended by
# RFC 9180 §7.1. Override via the kdf= kwarg if a different binding
# is required for interop.
HPKE_KDF_BY_CURVE = {
    "secp256r1" : hpke.KDF.HKDF_SHA256,
    "secp384r1" : hpke.KDF.HKDF_SHA384,
    "secp521r1" : hpke.KDF.HKDF_SHA512,
}

HPKE_AEAD_DEFAULT = hpke.AEAD.AES_256_GCM
HPKE_INFO_DEFAULT = b"otpme-hpke-v1"

def register():
    # NIST curves are dual-use (ECDH + ECDSA), registered in both
    # registries. Ed25519 / X25519 register themselves in their own
    # modules (ed25519.py / x25519.py).
    config.register_ecdh_curve("SECP256R1")
    config.register_ecdh_curve("SECP384R1")
    config.register_ecdh_curve("SECP521R1")
    config.register_ec_signing_curve("SECP256R1")
    config.register_ec_signing_curve("SECP384R1")
    config.register_ec_signing_curve("SECP521R1")


def _hpke_suite(curve_name, kdf=None, aead=None):
    """ Build an HPKE Suite tied to the curve of the recipient key. """
    curve_key = curve_name.lower()
    try:
        kem = HPKE_KEM_BY_CURVE[curve_key]
    except KeyError:
        msg = _("Unsupported HPKE curve: {curve}")
        msg = msg.format(curve=curve_name)
        raise OTPmeException(msg) from None
    if kdf is None:
        kdf = HPKE_KDF_BY_CURVE[curve_key]
    if aead is None:
        aead = HPKE_AEAD_DEFAULT
    return hpke.Suite(kem, kdf, aead)

class ECKey(AsymmetricKeyHandler):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def gen_key(self, curve="SECP384R1", backend=None):
        """ Generate private key. """
        if backend is None:
            backend = default_backend()
        try:
            curve_method = getattr(ec, curve)
            curve = curve_method()
        except Exception:
            msg = _("Unknown curve: {curve}")
            msg = msg.format(curve=curve)
            raise OTPmeException(msg) from None
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
        except Exception:
            msg = _("Unknown algorithm: {algorithm}")
            msg = msg.format(algorithm=algorithm)
            raise OTPmeException(msg) from None
        shared_key = self.private_key.exchange(algorithm, peer_public_key)
        if encode is not None:
            shared_key = _encode(shared_key, "hex")
        return shared_key

    def encrypt(self, cleartext, info=HPKE_INFO_DEFAULT,
        kdf=None, aead=None, encoding=None):
        """ ECIES via HPKE Base mode (RFC 9180). """
        if isinstance(cleartext, str):
            cleartext = cleartext.encode()
        suite = _hpke_suite(self.public_key.curve.name, kdf=kdf, aead=aead)
        blob = suite.encrypt(cleartext, self.public_key, info)
        if encoding is not None:
            blob = _encode(blob, encoding)
        return blob

    def decrypt(self, blob, info=HPKE_INFO_DEFAULT,
        kdf=None, aead=None, encoding=None):
        """ ECIES decrypt counterpart for blobs produced by encrypt(). """
        if encoding is not None:
            blob = _decode(blob, encoding)
        suite = _hpke_suite(self.private_key.curve.name, kdf=kdf, aead=aead)
        return suite.decrypt(blob, self.private_key, info)

    def sign(self, message=None, digest=None, algorithm="SHA256", encoding=None):
        """ Sign data with our private key. """
        if not message and not digest:
            raise OTPmeException("Need at least 'message' or 'digest'.")
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except Exception:
            msg = _("Unknown hash algorithm: {algorithm}")
            msg = msg.format(algorithm=algorithm)
            raise OTPmeException(msg) from None
        if message:
            message = message.encode()
        if digest:
            digest = _decode(digest, "hex")
            pre_hashed = utils.Prehashed(hash_algo_method())
            signature = self.private_key.sign(digest, ec.ECDSA(pre_hashed))
        else:
            signature = self.private_key.sign(message,
                            ec.ECDSA(hash_algo_method()))
        if encoding is not None:
            signature = _encode(signature, encoding)
        return signature

    def verify(self, signature, message=None, digest=None,
        algorithm="SHA256", encoding=None):
        """ Verify signed data and clear-text with public key. """
        if not message and not digest:
            raise OTPmeException("Need at least 'message' or 'digest'.")
        try:
            hash_algo_method = getattr(hashes, algorithm)
        except Exception:
            msg = _("Unknown hash algorithm: {algorithm}")
            msg = msg.format(algorithm=algorithm)
            raise OTPmeException(msg) from None
        if message:
            message = message.encode()
        if encoding is not None:
            signature = _decode(signature, encoding)
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
