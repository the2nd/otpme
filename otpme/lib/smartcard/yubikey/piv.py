import sys
import datetime
import getpass

from cryptography import x509
from cryptography.x509.oid import NameOID
from yubikit.piv import SLOT
from yubikit.piv import PivSession
from yubikit.piv import PIN_POLICY
from yubikit.piv import TOUCH_POLICY
from ykman.device import list_all_devices
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from yubikit.core.smartcard import SmartCardConnection
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

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


def import_rsa_key(
    private_key: str,
    slot: str = "AUTHENTICATION",
    mgmt_key: bytes = DEFAULT_MGMT_KEY,
    pin: str = DEFAULT_PIN,
    serial: int = None,
):
    slot = slot_map[slot]
    if isinstance(private_key, str):
        private_key = private_key.encode()
    private_key = load_pem_private_key(private_key, password=None)
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.authenticate(mgmt_key)
        piv.put_key(slot, private_key, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        # Write a self-signed certificate so OpenSC can expose the public key
        # via PKCS#11 (required e.g. for SSH logins with ssh-keygen -D).
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
            .sign(private_key, hashes.SHA256())
        )
        piv.put_certificate(slot, cert)
    print(f"Key imported to slot {slot.name}.")


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
    slot: SLOT = SLOT.AUTHENTICATION,
    serial: int=None,
):
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        public_key = piv.get_certificate(slot).public_key() if _slot_has_cert(piv, slot) \
            else piv.get_slot_metadata(slot).public_key
    return public_key

def decrypt(
    cipher_text: bytes,
    slot: SLOT = SLOT.KEY_MANAGEMENT,
    pin: str = None,
    padding: str = "oaep",
    serial: int = None,
):
    if pin is None:
        pin = getpass.getpass("PIN: ")

    if padding == "oaep":
        pad = asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    else:
        pad = asym_padding.PKCS1v15()

    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.verify_pin(pin)
        plain_text = piv.decrypt(slot, cipher_text, pad)

    return plain_text


def sign(
    data: str,
    slot: str = "AUTHENTICATION",
    pin: str = None,
    padding: str = "pss",
    serial: int = None,
):
    slot = slot_map[slot]
    if padding == "pss":
        pad = asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        )
    else:
        pad = asym_padding.PKCS1v15()

    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.verify_pin(pin)
        meta = piv.get_slot_metadata(slot)
        signature = piv.sign(slot, meta.key_type, data, hashes.SHA256(), pad)
        return signature


def verify(
    data: bytes,
    signature: bytes,
    public_key=None,
    slot: SLOT = SLOT.SIGNATURE,
    padding: str = "pss",
    serial: int = None,
):
    if public_key is None:
        public_key = get_public_key(slot, serial)

    if padding == "pss":
        pad = asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        )
    else:
        pad = asym_padding.PKCS1v15()

    try:
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
) -> str:
    slot = slot_map[slot]
    with _open_piv(serial) as conn:
        piv = PivSession(conn)
        piv.verify_pin(pin)
        meta = piv.get_slot_metadata(slot)
        signature = piv.sign(
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
