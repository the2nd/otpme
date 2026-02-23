#!/usr/bin/env python3
import os
import sys
import getpass
import argparse

# When run via symlink, resolve the real script location and add the
# project root (two levels up from otpme/yk_piv.py) to sys.path.
_script_dir = os.path.dirname(os.path.realpath(__file__))
_project_root = os.path.dirname(_script_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Add PYTHONPATH.
PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
if os.path.exists(PYTHONPATH_FILE):
    fd = open(PYTHONPATH_FILE, "r")
    try:
        for x in fd.readlines():
            x = x.replace("\n", "")
            if x in sys.path:
                continue
            sys.path.insert(0, x)
    finally:
        fd.close()

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def _resolve_pin(pin_arg):
    """Resolve PIN similar to openssl -pass: pass:<val>, file:<path>, fd:<n>, env:<var>."""
    if pin_arg is None:
        return None
    if pin_arg.startswith("pass:"):
        return pin_arg[5:]
    if pin_arg.startswith("file:"):
        with open(pin_arg[5:], "r") as f:
            return f.read().rstrip("\n")
    if pin_arg.startswith("fd:"):
        with os.fdopen(int(pin_arg[3:]), "r") as f:
            return f.read().rstrip("\n")
    if pin_arg.startswith("env:"):
        return os.environ[pin_arg[4:]]
    return pin_arg


from otpme.lib.smartcard.yubikey.piv import slot_map
from otpme.lib.smartcard.yubikey.piv import reset
from otpme.lib.smartcard.yubikey.piv import change_pin
from otpme.lib.smartcard.yubikey.piv import change_puk
from otpme.lib.smartcard.yubikey.piv import decrypt
from otpme.lib.smartcard.yubikey.piv import sign
from otpme.lib.smartcard.yubikey.piv import verify
from otpme.lib.smartcard.yubikey.piv import list_keys
from otpme.lib.smartcard.yubikey.piv import import_rsa_key
from otpme.lib.smartcard.yubikey.piv import derive_password


def main():
    parser = argparse.ArgumentParser(description="YubiKey PIV management tool")
    parser.add_argument("--slot", default="AUTHENTICATION", choices=slot_map.keys(),
                        help="PIV slot (default: AUTHENTICATION / 9a)")
    parser.add_argument("--mgmt-key", default=None, help="Management key (hex)")
    parser.add_argument("--pin", default=None, help="PIN")
    parser.add_argument("--serial", type=int, default=None, help="YubiKey serial number")
    parser.add_argument("--list", action="store_true", help="List keys on YubiKey")
    parser.add_argument("--reset", action="store_true", help="Reset PIV applet to factory defaults")
    parser.add_argument("--import", dest="import_key", action="store_true",
                        help="Import RSA private key from stdin")
    parser.add_argument("--passphrase", action="store_true", help="Prompt for PEM passphrase")
    parser.add_argument("--change-pin", action="store_true", help="Change PIN")
    parser.add_argument("--change-puk", action="store_true", help="Change PUK")
    parser.add_argument("--old-pin", default=None, help="Current PIN")
    parser.add_argument("--new-pin", default=None, help="New PIN")
    parser.add_argument("--old-puk", default=None, help="Current PUK")
    parser.add_argument("--new-puk", default=None, help="New PUK")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt stdin to stdout")
    parser.add_argument("--sign", action="store_true", help="Sign stdin, write signature to stdout")
    parser.add_argument("--verify", action="store_true", help="Verify stdin against --signature")
    parser.add_argument("--signature", default=None, help="Signature file (for --verify)")
    parser.add_argument("--public-key", default=None, help="Public key PEM (for --verify, otherwise from YubiKey)")
    parser.add_argument("--padding", default=None, choices=["oaep", "pkcs1v15", "pss"],
                        help="RSA padding (decrypt: oaep, sign: pss)")
    parser.add_argument("--derive-password", action="store_true", help="Derive a password from a challenge")
    parser.add_argument("--challenge", default=None, help="Challenge string for password derivation")
    parser.add_argument("--derive-length", type=int, default=32,
                        help="Length of derived password in bytes (default: 32)")
    args = parser.parse_args()

    if args.derive_password:
        if not args.challenge:
            parser.error("--derive-password requires --challenge")
        pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
        pw = derive_password(
            challenge=args.challenge,
            pin=pin,
            slot=args.slot,
            length=args.derive_length,
            serial=args.serial,
        )
        print(pw)

    elif args.reset:
        reset(serial=args.serial)

    elif args.list:
        list_keys(serial=args.serial)

    elif args.change_pin:
        change_pin(old_pin=args.old_pin, new_pin=args.new_pin, serial=args.serial)

    elif args.change_puk:
        change_puk(old_puk=args.old_puk, new_puk=args.new_puk, serial=args.serial)

    elif args.decrypt:
        data = sys.stdin.buffer.read()
        plain_text = decrypt(
            cipher_text=data,
            slot=slot_map[args.slot],
            pin=_resolve_pin(args.pin),
            padding=args.padding or "oaep",
            serial=args.serial,
        )
        sys.stdout.buffer.write(plain_text)

    elif args.verify:
        if not args.signature:
            parser.error("--verify requires --signature")
        data = sys.stdin.buffer.read()
        with open(args.signature, "rb") as f:
            signature = f.read()
        public_key = None
        if args.public_key:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            with open(args.public_key, "rb") as f:
                public_key = load_pem_public_key(f.read())
        valid = verify(
            data=data,
            signature=signature,
            public_key=public_key,
            slot=slot_map[args.slot],
            padding=args.padding or "pss",
            serial=args.serial,
        )
        if valid:
            print("Signature valid.")
        else:
            print("Signature INVALID!")
            sys.exit(1)

    elif args.sign:
        pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
        data = sys.stdin.buffer.read()
        signature = sign(
            data=data,
            slot=args.slot,
            pin=pin,
            padding=args.padding or "pss",
            serial=args.serial,
        )
        sys.stdout.buffer.write(signature)

    elif args.import_key:
        pem_data = sys.stdin.buffer.read()
        if args.passphrase:
            pem_password = getpass.getpass("PEM passphrase: ").encode()
            key = load_pem_private_key(pem_data, password=pem_password)
            pem_data = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        kwargs = dict(slot=args.slot, serial=args.serial)
        if args.mgmt_key:
            kwargs["mgmt_key"] = bytes.fromhex(args.mgmt_key)
        if _resolve_pin(args.pin):
            kwargs["pin"] = _resolve_pin(args.pin)
        import_rsa_key(pem_data, **kwargs)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
