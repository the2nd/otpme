# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
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
# It builds the request info, has the slot sign it and puts the
# signature back, which is the one thing a card-held key needs.
from ykman.piv import generate_csr as ykman_generate_csr
from ykman.piv import sign_csr_builder as ykman_sign_csr_builder
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
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


def get_management_key(piv_session, pin: str = None, mgmt_key: bytes = None):
    """ The management key to write to a slot with.

    One that was given wins. Otherwise the card is asked: a card that
    went through protect_management_key() carries a random one in its
    own protected data, and that is the ordinary state of a deployed
    token -- the PIN reads it out.

    Only a card that has none is written with the factory default, and
    that is the state right after reset(), which is where a deploy
    starts.
    """
    from ykman.piv import get_pivman_data
    from ykman.piv import get_pivman_protected_data
    if mgmt_key:
        return mgmt_key
    if not get_pivman_data(piv_session).has_stored_key:
        return DEFAULT_MGMT_KEY
    if not pin:
        msg = _("The management key of this card is stored on it and the PIN is needed to read it.")
        raise RuntimeError(msg)
    piv_session.verify_pin(pin)
    stored_key = get_pivman_protected_data(piv_session).key
    if not stored_key:
        msg = _("This card says it stores its management key, but there is none in its protected data.")
        raise RuntimeError(msg)
    return stored_key

def get_slot_algo(slot: str = "AUTHENTICATION", serial: int = None,
        piv_session: PivSession = None):
    """ Return the OTPme algo tag of the key currently in the slot,
    or None if the slot is empty. """
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
    mgmt_key: bytes = None,
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
        # A deploy comes here right after reset(), so the card has no
        # stored key and this is the factory default. A card that was
        # deployed before carries a random one, see get_management_key().
        piv.authenticate(get_management_key(piv, pin=pin, mgmt_key=mgmt_key))
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


def export_public_key(
    slot: str = "AUTHENTICATION",
    serial: int = None,
    piv_session: PivSession = None,
):
    """ The public key of a slot, as PEM.

    For a key that cannot sign a certificate request of its own -- an
    X25519 key in the key management slot is the case this exists for.
    A request proves possession by signing itself, X25519 has no sign
    primitive (RFC 8410 says so), and then the only way to a
    certificate is to hand the CA the public key and let it issue one
    without a request.
    """
    public_key = get_public_key(slot, serial=serial, piv_session=piv_session)
    if public_key is None:
        msg = _("No key in slot: {slot}")
        msg = msg.format(slot=slot)
        raise RuntimeError(msg)
    public_bytes = public_key.public_bytes(Encoding.PEM,
                                        PublicFormat.SubjectPublicKeyInfo)
    return public_bytes.decode()

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


def import_certificate(
    certificate,
    slot: str = "AUTHENTICATION",
    pin: str = None,
    mgmt_key: bytes = None,
    serial: int = None,
):
    """ Put a certificate into a slot.

    What a PKCS#11 module hands to a mail client or a browser: it shows
    the key of a slot only together with the certificate that sits in
    it. So a request that came back signed has to go here before the
    key behind it can be used for anything.

    <certificate> is PEM.
    """
    slot_obj = slot_map[slot]
    if isinstance(certificate, str):
        certificate = certificate.encode()
    cert = x509.load_pem_x509_certificate(certificate)
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        # Writing to a slot is a management key operation, not a PIN
        # one, the same as importing a key. On a deployed token that key
        # is random and lies on the card, see get_management_key().
        piv.authenticate(get_management_key(piv, pin=pin, mgmt_key=mgmt_key))
        piv.put_certificate(slot_obj, cert)
    return cert

def gen_csr(
    subject: str,
    slot: str = "AUTHENTICATION",
    pin: str = None,
    san_email=None,
    key_usage=None,
    ext_key_usage=None,
    serial: int = None,
    piv_session: PivSession = None,
):
    """ A certificate signing request for the key in a slot.

    The private key never leaves the card, so the request is signed by
    the card: ykman builds the request info, hands it to the slot and
    puts the signature back.

    <subject> is an RFC 4514 string ("CN=alice,O=OTPme"). That is the
    form ykman reads, and the one our own parts pass around, because
    its escaping is defined -- see pki.utils.build_rfc4514_subject().

    <san_email>, <key_usage> and <ext_key_usage> are what a request has
    to ask for to be of any use for S/MIME: the address in the subject
    alternative name, digitalSignature and keyEncipherment, and the
    extended key usage emailProtection. A request without them leaves
    all of it to whatever the CA puts in.

    Returns the request as PEM.
    """
    from otpme.lib.pki.utils import build_san
    from otpme.lib.pki.utils import build_key_usage
    from otpme.lib.pki.utils import build_ext_key_usage
    slot_obj = slot_map[slot]
    if not piv_session:
        conn = _open_piv(serial)
        piv_session = PivSession(conn)
        piv_session.verify_pin(pin)
    public_key = get_public_key(slot, piv_session=piv_session)
    if public_key is None:
        msg = _("No key in slot: {slot}")
        msg = msg.format(slot=slot)
        raise RuntimeError(msg)
    if not san_email and not key_usage and not ext_key_usage:
        csr = ykman_generate_csr(piv_session, slot_obj, public_key, subject)
        return csr.public_bytes(Encoding.PEM).decode()
    # The same request, with the extensions on it. ykman builds the
    # plain one itself and signs whatever builder it is handed, so the
    # builder is built here and handed over.
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name.from_rfc4514_string(subject))
    san = build_san(email=san_email)
    if san:
        builder = builder.add_extension(san, critical=False)
    if key_usage:
        builder = builder.add_extension(build_key_usage(key_usage),
                                        critical=True)
    if ext_key_usage:
        builder = builder.add_extension(build_ext_key_usage(ext_key_usage),
                                        critical=False)
    csr = ykman_sign_csr_builder(piv_session, slot_obj, public_key, builder)
    return csr.public_bytes(Encoding.PEM).decode()

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
