# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import hashlib
from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric import ed25519

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


def register():
    # Ed25519 is sign-only (EdDSA). Lives in the signing-curve registry.
    config.register_ec_signing_curve("ED25519")


class Ed25519Key(AsymmetricKeyHandler):
    """ EdDSA over edwards25519 (RFC 8032). Sign-only -- for encryption
    you want the X25519Key sibling on the Montgomery form of the same
    underlying curve. Deterministic by spec: same (privkey, message)
    always yields the same signature, which is why this key type can
    drive derive_password etc. without needing to cache state. """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def gen_key(self, backend=None):
        # cryptography's Ed25519 ignores the backend arg, accepted for symmetry.
        return ed25519.Ed25519PrivateKey.generate()

    def export_private_key(self, encoding="PEM", key_format="PKCS8",
        password=None):
        # Ed25519 only serialises under PKCS#8; override the base default
        # of TraditionalOpenSSL which would raise.
        return super().export_private_key(encoding=encoding,
                                          key_format=key_format,
                                          password=password)

    def sign(self, message=None, digest=None, encoding=None):
        """ Sign data with our private key.

        EdDSA has no Prehashed-style API. To keep the message/digest
        protocol consistent with RSAKey (where RSA-PSS-SHA256 always
        hashes the message internally), we standardise on SHA-256:

          - digest=<hex>  → caller already supplied SHA-256(payload); we
                            feed the 32 raw bytes to Ed25519.sign().
          - message=<x>   → we SHA-256 it ourselves, then feed the
                            32-byte hash to Ed25519.sign().

        Either way the signature is over the 32-byte SHA-256 of the
        payload; Ed25519 then internally hashes SHA-512 over those 32
        bytes. Double-hash, still ~128-bit security. verify() mirrors
        this so message-based callers (signing.py) and digest-based
        callers (key_script.sh) interoperate. """
        if not message and not digest:
            raise OTPmeException("Need 'message' or 'digest'.")
        if digest:
            data_to_sign = _decode(digest, "hex")
        else:
            if isinstance(message, str):
                message = message.encode()
            data_to_sign = hashlib.sha256(message).digest()
        signature = self.private_key.sign(data_to_sign)
        if encoding is not None:
            signature = _encode(signature, encoding)
        return signature

    def verify(self, signature, message=None, digest=None, encoding=None):
        """ Verify EdDSA signature. Mirrors sign()'s SHA-256 pre-hash so
        message- and digest-based callers see the same signed payload. """
        if not message and not digest:
            raise OTPmeException("Need 'message' or 'digest'.")
        if digest:
            data_signed = _decode(digest, "hex")
        else:
            if isinstance(message, str):
                message = message.encode()
            data_signed = hashlib.sha256(message).digest()
        if encoding is not None:
            signature = _decode(signature, encoding)
        try:
            self.public_key.verify(signature, data_signed)
            return True
        except exceptions.InvalidSignature:
            return False
