# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import sys
import hashlib
import datetime
import getpass

# Use shared PC/SC connection mode to allow concurrent access (e.g. ssh-agent).
os.environ['YKMAN_NO_EXLUSIVE'] = '1'

from cryptography import x509
from cryptography.x509.oid import NameOID
from yubikit.piv import SLOT
from yubikit.piv import PivSession
from yubikit.piv import PIN_POLICY
from yubikit.piv import TOUCH_POLICY
from yubikit.piv import MANAGEMENT_KEY_TYPE
from yubikit.core import NotSupportedError
from ykman.device import list_all_devices
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from yubikit.core.smartcard import SmartCardConnection
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
from cryptography.hazmat.primitives.asymmetric import x25519 as _x25519


def algo_for_public_key(public_key):
    """ Map a cryptography public key object to an OTPme algo tag
    ("rsa" / "ed25519" / "x25519" / "ec"). Used to read back what's
    in an already-initialised PIV slot. """
    if isinstance(public_key, _rsa.RSAPublicKey):
        return "rsa"
    if isinstance(public_key, _ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(public_key, _x25519.X25519PublicKey):
        return "x25519"
    if isinstance(public_key, _ec.EllipticCurvePublicKey):
        return "ec"
    raise RuntimeError(
        f"Unknown public key type: {type(public_key).__name__}"
    )


def protect_management_key(
    pin: str,
    current_mgmt_key: bytes = None,
    serial: int = None,
):
    """ Replace the factory-default PIV management key with a fresh
    random one and store it PIN-protected on the card itself.

    After this, all admin ops (importing keys, writing certs, future
    re-deploys) can be unlocked with just the PIN -- no separate
    mgmt-key secret needs to be remembered or stored externally.

    Without this, anyone with physical access to the YubiKey could
    overwrite the slot keys via the well-known default mgmt key
    (010203...0708), effectively impersonating the user.

    AES-192 is the modern default (YubiKey FW >= 5.4); falls back to
    3DES (TDES) automatically for older firmware. """
    from ykman.piv import generate_random_management_key, pivman_set_mgm_key
    if current_mgmt_key is None:
        current_mgmt_key = DEFAULT_MGMT_KEY
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.authenticate(current_mgmt_key)
        piv.verify_pin(pin)
        try:
            algorithm = MANAGEMENT_KEY_TYPE.AES192
            new_key = generate_random_management_key(algorithm)
            pivman_set_mgm_key(piv, new_key, algorithm,
                               touch=False, store_on_device=True)
        except NotSupportedError:
            # YubiKey firmware < 5.4 only supports 3DES.
            algorithm = MANAGEMENT_KEY_TYPE.TDES
            new_key = generate_random_management_key(algorithm)
            pivman_set_mgm_key(piv, new_key, algorithm,
                               touch=False, store_on_device=True)


def get_slot_algo(slot: str = "AUTHENTICATION", serial: int = None,
        piv_session: PivSession = None):
    """ Return the OTPme algo tag of the key currently in the slot,
    or None if the slot is empty. """
    slot_obj = slot_map[slot]
    if piv_session is None:
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
    try:
        pub = get_public_key(slot, serial=serial, piv_session=piv_session)
    except Exception:
        return None
    return algo_for_public_key(pub)

DEFAULT_PIN = "123456"
DEFAULT_PUK = "12345678"
DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")

slot_map = {
    "AUTHENTICATION": SLOT.AUTHENTICATION,
    "SIGNATURE": SLOT.SIGNATURE,
    "KEY_MANAGEMENT": SLOT.KEY_MANAGEMENT,
    "CARD_AUTH": SLOT.CARD_AUTH,
}

def _open_piv(serial: int = None):
    devices = list_all_devices([SmartCardConnection])
    if not devices:
        raise RuntimeError("No YubiKey found.")
    if serial:
        for dev, info in devices:
            if info.serial == serial:
                return dev.open_connection(SmartCardConnection)
        raise RuntimeError(f"YubiKey with serial {serial} not found.")
    device, _ = devices[0]
    return device.open_connection(SmartCardConnection)

def get_piv(serial: int = None):
    conn = _open_piv(serial)
    piv_session = PivSession(conn)
    return piv_session, conn

def import_private_key(
    private_key,
    slot: str = "AUTHENTICATION",
    mgmt_key: bytes = DEFAULT_MGMT_KEY,
    pin: str = DEFAULT_PIN,
    serial: int = None,
):
    """ Import a PEM-encoded private key (RSA / EC / Ed25519 / X25519)
    into the given PIV slot. Self-signed cert is also written so OpenSC
    can expose the slot via PKCS#11. X25519 keys can't self-sign, so
    we skip the cert step (PKCS#11 visibility is irrelevant for
    encrypt-only / KEM keys). """
    slot = slot_map[slot]
    if isinstance(private_key, (str, bytes)):
        if isinstance(private_key, str):
            private_key = private_key.encode()
        private_key = load_pem_private_key(private_key, password=None)
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.authenticate(mgmt_key)
        piv.put_key(slot, private_key, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        # X25519 has no sign primitive -- can't produce a self-signed cert.
        if isinstance(private_key, _x25519.X25519PrivateKey):
            print(f"Key imported to slot {slot.name} (no cert: X25519 is sign-incapable).")
            return
        # Pick the right hash for the cert signature:
        #   Ed25519 → None (EdDSA does its own SHA-512 internally)
        #   EC → SHA matching curve security level
        #   RSA → SHA-256
        if isinstance(private_key, _ed25519.Ed25519PrivateKey):
            sig_hash = None
        elif isinstance(private_key, _ec.EllipticCurvePrivateKey):
            sig_hash = _ec_hash_for_curve(private_key.curve)
        else:
            sig_hash = hashes.SHA256()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OTPme PIV")])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * 10))
            .sign(private_key, sig_hash)
        )
        piv.put_certificate(slot, cert)
    print(f"Key imported to slot {slot.name}.")


def _ec_hash_for_curve(curve):
    """ Curve-matched SHA size for EC cert signatures (P-256→SHA-256 etc.). """
    size = curve.key_size
    if size <= 256:
        return hashes.SHA256()
    if size <= 384:
        return hashes.SHA384()
    return hashes.SHA512()




def reset(serial: int = None, confirm: bool = True):
    if confirm:
        answer = input("Reset PIV-Applet? All keys, certs and PIN are deleted! [y/N]: ")
        if answer.strip().lower() != "y":
            print("Aborted.")
            return
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.reset()
    print("PIV-Applet reset.")
    return True


def change_pin(old_pin: str = None, new_pin: str = None, serial: int = None):
    if old_pin is None:
        old_pin = getpass.getpass("Current PIN: ")
    if new_pin is None:
        new_pin = getpass.getpass("New PIN: ")
        confirm = getpass.getpass("Repeat new PIN: ")
        if new_pin != confirm:
            raise ValueError("PINs do not match.")
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.change_pin(old_pin, new_pin)
    print("PIN changed.")


def change_puk(old_puk: str = None, new_puk: str = None, serial: int = None):
    if old_puk is None:
        old_puk = getpass.getpass("Current PUK: ")
    if new_puk is None:
        new_puk = getpass.getpass("New PUK: ")
        confirm = getpass.getpass("Repeat new PUK: ")
        if new_puk != confirm:
            raise ValueError("PUKs do not match.")
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.change_puk(old_puk, new_puk)
    print("PUK changed.")


def get_public_key(
    slot: str = "AUTHENTICATION",
    serial: int=None,
    piv_session: PivSession = None,
):
    slot = slot_map[slot]
    if not piv_session:
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
    if _slot_has_cert(piv_session, slot):
        return piv_session.get_certificate(slot).public_key()
    return piv_session.get_slot_metadata(slot).public_key

def decrypt(
    cipher_text: bytes,
    slot: str = "AUTHENTICATION",
    pin: str = None,
    padding: str = "oaep",
    serial: int = None,
    piv_session: PivSession = None,
):
    slot = slot_map[slot]
    if padding == "oaep":
        pad = asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    else:
        pad = asym_padding.PKCS1v15()

    if not piv_session:
        if pin is None:
            pin = getpass.getpass("PIN: ")
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
        piv_session.verify_pin(pin)

    return piv_session.decrypt(slot, cipher_text, pad)


def ecdh(
    peer_public_key,
    slot: str = "KEY_MANAGEMENT",
    pin: str = None,
    serial: int = None,
    piv_session: PivSession = None,
) -> bytes:
    """ Compute ECDH shared secret using the slot's private key.

    peer_public_key may be a PEM/DER byte string, raw 32-byte X25519
    public-key bytes, or an X25519PublicKey / EllipticCurvePublicKey
    object. Returns the raw shared-secret bytes (32 for X25519,
    curve-coordinate length for NIST EC). Caller is responsible for
    feeding the result through a KDF (HKDF, HPKE labels) before use. """
    slot_obj = slot_map[slot]
    # Normalise peer to a cryptography key object.
    if isinstance(peer_public_key, (bytes, bytearray)):
        if len(peer_public_key) == 32:
            peer_public_key = _x25519.X25519PublicKey.from_public_bytes(
                bytes(peer_public_key)
            )
        else:
            peer_public_key = load_pem_public_key(bytes(peer_public_key))
    elif isinstance(peer_public_key, str):
        peer_public_key = load_pem_public_key(peer_public_key.encode())
    if not piv_session:
        if pin is None:
            pin = getpass.getpass("PIN: ")
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
        piv_session.verify_pin(pin)
    return piv_session.calculate_secret(slot_obj, peer_public_key)


def sign(
    data,
    slot: str = "AUTHENTICATION",
    pin: str = None,
    padding: str = "pss",
    serial: int = None,
    piv_session: PivSession = None,
):
    """ Sign data with the slot's private key, algo-aware:

      - RSA      : PSS or PKCS#1 v1.5 over SHA-256
      - ECDSA    : signature over curve-matched SHA digest
      - Ed25519  : data is SHA-256'd first, then EdDSA-signs the
                   32-byte hash. Mirrors Ed25519Key.sign() so a
                   signature produced here verifies via Ed25519Key.verify
                   on the server side and vice versa.

    Returns raw signature bytes. """
    slot_obj = slot_map[slot]
    if isinstance(data, str):
        data = data.encode()

    if not piv_session:
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
        piv_session.verify_pin(pin)

    meta = piv_session.get_slot_metadata(slot_obj)
    pub = meta.public_key

    if isinstance(pub, _ed25519.Ed25519PublicKey):
        # SHA-256 first to match the convention in Ed25519Key.sign().
        # EdDSA does its own SHA-512 internally over what we pass.
        data = hashlib.sha256(data).digest()
        return piv_session.sign(slot_obj, meta.key_type, data, None, None)

    if isinstance(pub, _ec.EllipticCurvePublicKey):
        sig_hash = _ec_hash_for_curve(pub.curve)
        return piv_session.sign(slot_obj, meta.key_type, data, sig_hash, None)

    # RSA path
    if padding == "pss":
        pad = asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        )
    else:
        pad = asym_padding.PKCS1v15()
    return piv_session.sign(slot_obj, meta.key_type, data, hashes.SHA256(), pad)


def verify(
    data,
    signature: bytes,
    public_key=None,
    slot=None,
    padding: str = "pss",
    serial: int = None,
):
    """ Verify a signature against the slot's public key. Mirrors sign():
      - Ed25519: SHA-256 the data first, then EdDSA-verify
      - ECDSA: curve-matched SHA
      - RSA: PSS/PKCS#1 over SHA-256
    """
    if public_key is None:
        if slot is None:
            slot = SLOT.SIGNATURE
        if isinstance(slot, str):
            public_key = get_public_key(slot, serial=serial)
        else:
            public_key = get_public_key(slot.name, serial=serial)
    if isinstance(data, str):
        data = data.encode()

    try:
        if isinstance(public_key, _ed25519.Ed25519PublicKey):
            data = hashlib.sha256(data).digest()
            public_key.verify(signature, data)
            return True
        if isinstance(public_key, _ec.EllipticCurvePublicKey):
            sig_hash = _ec_hash_for_curve(public_key.curve)
            public_key.verify(signature, data, _ec.ECDSA(sig_hash))
            return True
        # RSA
        if padding == "pss":
            pad = asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            )
        else:
            pad = asym_padding.PKCS1v15()
        public_key.verify(signature, data, pad, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def _slot_has_cert(piv: PivSession, slot: SLOT) -> bool:
    try:
        piv.get_certificate(slot)
        return True
    except Exception:
        return False


def detect(serial: int = None, slot: str = "AUTHENTICATION"):
    slot = slot_map[slot]
    try:
        conn = _open_piv(serial)
        piv = PivSession(conn)
        try:
            meta = piv.get_slot_metadata(slot)
            if meta:
                print(f"Slot {slot.name}: {meta.key_type.name}, touch={meta.touch_policy.name}")
                return conn
        except Exception:
            pass
    except Exception:
        pass
    return False


def list_keys(serial: int = None):
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        for slot in SLOT:
            try:
                meta = piv.get_slot_metadata(slot)
                if meta:
                    print(f"Slot {slot.name}: {meta.key_type.name}, touch={meta.touch_policy.name}")
            except Exception:
                pass


def derive_password(
    challenge: str,
    pin: str = None,
    slot: str = "AUTHENTICATION",
    length: int = 32,
    serial: int = None,
    piv_session: PivSession = None,
) -> str:
    slot = slot_map[slot]

    if not piv_session:
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
        piv_session.verify_pin(pin)

    meta = piv_session.get_slot_metadata(slot)
    signature = piv_session.sign(
        slot,
        meta.key_type,
        challenge.encode(),
        hashes.SHA256(),
        asym_padding.PKCS1v15(),
    )

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=challenge.encode(),
    ).derive(signature)

    return derived.hex()
