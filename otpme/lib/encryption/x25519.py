# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import hmac
import hashlib
import struct
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

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
    from otpme.lib import config
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


# ---------------------------------------------------------------------------
# Manual RFC 9180 DHKEM(X25519, HKDF-SHA256) + HPKE Base mode (AES-256-GCM)
# decap with an externally-provided ECDH callback.
#
# cryptography.hpke.Suite.decrypt() requires a Python private-key object
# with .exchange(). For HW-backed X25519 keys (YubiKey-PIV slot 9D etc.)
# that object doesn't exist -- only an ECDH primitive across the PC/SC
# bridge. This helper re-implements just the decap path so the DH step
# can come from anywhere (HW, PKCS#11, network HSM, ...).
#
# Suite (matches HPKE_SUITE above):
#   KEM  = X25519                  (KEM ID 0x0020, Nsecret = 32)
#   KDF  = HKDF-SHA256             (KDF ID 0x0001, Nh = 32)
#   AEAD = AES-256-GCM             (AEAD ID 0x0002, Nk = 32, Nn = 12)
# Wire format: 32-byte ephemeral pubkey || ct (ct includes the 16-byte
# AEAD tag at the end). Matches cryptography.hpke.Suite output verbatim.
# ---------------------------------------------------------------------------

_KEM_ID  = 0x0020
_KDF_ID  = 0x0001
_AEAD_ID = 0x0002
_NSECRET = 32
_NK      = 32
_NN      = 12
_NH      = 32


def _hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * _NH
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk, info, length):
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _labeled_extract(salt, label, ikm, suite_id):
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    return _hkdf_extract(salt, labeled_ikm)


def _labeled_expand(prk, label, info, length, suite_id):
    labeled_info = (
        struct.pack(">H", length)
        + b"HPKE-v1" + suite_id + label + info
    )
    return _hkdf_expand(prk, labeled_info, length)


def hpke_decap_x25519_aes256gcm(blob, recipient_public_bytes,
        ecdh_func, info=HPKE_INFO_DEFAULT, aad=b""):
    """ Decap an HPKE blob produced by cryptography.hpke.Suite(
        KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_256_GCM).

    blob: full HPKE wire (32-byte ephemeral pubkey || ct+tag).
    recipient_public_bytes: 32 raw bytes of the recipient X25519 pubkey
        (must match the key the sender encrypted to; goes into the
        KEM context).
    ecdh_func: callable(peer_pub_bytes: bytes) -> 32-byte shared secret.
        Wraps the actual ECDH op (HW token, PKCS#11, software ...).
    info: HPKE info string (must match encrypt-side).
    aad: AAD (must match encrypt-side; HPKE Base single-shot uses b"").
    """
    if len(blob) < 32 + 16:
        raise ValueError("HPKE blob too short.")
    enc = blob[:32]
    ct = blob[32:]

    # DHKEM(X25519, HKDF-SHA256) decap.
    kem_suite_id = b"KEM" + struct.pack(">H", _KEM_ID)
    dh = ecdh_func(enc)
    kem_context = enc + recipient_public_bytes
    eae_prk = _labeled_extract(b"", b"eae_prk", dh, kem_suite_id)
    shared_secret = _labeled_expand(eae_prk, b"shared_secret",
                                    kem_context, _NSECRET, kem_suite_id)

    # HPKE Base mode key schedule.
    hpke_suite_id = (
        b"HPKE"
        + struct.pack(">H", _KEM_ID)
        + struct.pack(">H", _KDF_ID)
        + struct.pack(">H", _AEAD_ID)
    )
    mode_base = b"\x00"
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", hpke_suite_id)
    info_hash = _labeled_extract(b"", b"info_hash", info, hpke_suite_id)
    key_schedule_context = mode_base + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, b"secret", b"", hpke_suite_id)
    key = _labeled_expand(secret, b"key", key_schedule_context,
                          _NK, hpke_suite_id)
    base_nonce = _labeled_expand(secret, b"base_nonce", key_schedule_context,
                                 _NN, hpke_suite_id)

    # Single-shot AEAD decrypt at sequence number 0 → nonce = base_nonce.
    return AESGCM(key).decrypt(base_nonce, ct, aad)
