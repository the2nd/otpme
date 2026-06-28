# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import x25519

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

# Fixed HPKE suite for X25519. KEM/KDF/AEAD locked to one combination so
# every party (server, client, key_script via otpme-tool) interoperates
# without negotiating. To migrate to a different suite later, bump the
# HPKE_INFO label so old and new blobs are distinguishable.
HPKE_SUITE = hpke.Suite(
    hpke.KEM.X25519,
    hpke.KDF.HKDF_SHA256,
    hpke.AEAD.AES_256_GCM,
)
HPKE_INFO_DEFAULT = b"otpme-hpke-x25519-v1"


def register():
    # X25519 is DH-only (ECDH/HPKE-KEM). Lives in the ECDH-curve registry.
    config.register_ecdh_curve("X25519")


class X25519Key(AsymmetricKeyHandler):
    """ X25519 ECDH key on the Montgomery form of Curve25519. KEM/DH-only --
    for signatures use the Ed25519Key sibling. Wraps secrets via HPKE Base
    mode (RFC 9180) using the fixed suite above. """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def gen_key(self, backend=None):
        # cryptography's X25519 ignores the backend arg, accepted for symmetry.
        return x25519.X25519PrivateKey.generate()

    def export_private_key(self, encoding="PEM", key_format="PKCS8",
        password=None):
        # X25519 only serialises under PKCS#8; override the base default
        # of TraditionalOpenSSL which would raise.
        return super().export_private_key(encoding=encoding,
                                          key_format=key_format,
                                          password=password)

    def encrypt(self, cleartext, info=HPKE_INFO_DEFAULT, encoding=None):
        """ HPKE Base-mode encrypt under the recipient's X25519 public key.
        Each call uses a fresh ephemeral sender key (forward secrecy). """
        if isinstance(cleartext, str):
            cleartext = cleartext.encode()
        ciphertext = HPKE_SUITE.encrypt(cleartext, self.public_key, info)
        if encoding is not None:
            ciphertext = _encode(ciphertext, encoding)
        return ciphertext

    def decrypt(self, ciphertext, info=HPKE_INFO_DEFAULT, encoding=None):
        """ HPKE Base-mode decrypt with our X25519 private key. """
        if encoding is not None:
            ciphertext = _decode(ciphertext, encoding)
        return HPKE_SUITE.decrypt(ciphertext, self.private_key, info)

    def dhexchange(self, peer_public_key, encode="hex"):
        """ Raw X25519 ECDH. Returns the 32-byte shared secret. Useful for
        deterministic derive operations where HPKE is overkill. """
        shared = self.private_key.exchange(peer_public_key)
        if encode is not None:
            shared = _encode(shared, "hex")
        return shared
