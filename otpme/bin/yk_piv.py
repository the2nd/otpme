#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import sys
import getpass
import argparse

# When run via symlink, resolve the real script location and add the
# project root (two levels up from otpme/yk_piv.py) to sys.path.
_script_dir = os.path.dirname(os.path.realpath(__file__))
_project_root = os.path.dirname(_script_dir)
_project_root = os.path.dirname(_project_root)
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
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from otpme.lib.smartcard.yubikey.piv import slot_map
from otpme.lib.smartcard.yubikey.piv import reset
from otpme.lib.smartcard.yubikey.piv import change_pin
from otpme.lib.smartcard.yubikey.piv import change_puk
from otpme.lib.smartcard.yubikey.piv import decrypt
from otpme.lib.smartcard.yubikey.piv import sign
from otpme.lib.smartcard.yubikey.piv import gen_csr
from otpme.lib.smartcard.yubikey.piv import import_certificate
from otpme.lib.smartcard.yubikey.piv import export_public_key
from otpme.lib.smartcard.yubikey.piv import verify
from otpme.lib.smartcard.yubikey.piv import list_keys
from otpme.lib.smartcard.yubikey.piv import import_private_key
from otpme.lib.smartcard.yubikey.piv import derive_password


# Per-op default slots: sign+derive run against the sign key (9A);
# decrypt runs against the encrypt key (9D). --slot overrides explicitly.
SIGN_SLOT_DEFAULT = "AUTHENTICATION"
ENCRYPT_SLOT_DEFAULT = "KEY_MANAGEMENT"


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


def _split_list(value):
    """A comma separated option as a list, empty ones dropped."""
    if not value:
        return None
    items = [x.strip() for x in value.split(",")]
    return [x for x in items if x] or None


def _get_agent():
    """Connect to otpme-agent and return AgentConn."""
    from otpme.lib.otpme_config import OTPmeConfig
    OTPmeConfig(tool_name="otpme-yk-piv")
    from otpme.lib import connections
    agent_conn = connections.get("agent")
    return agent_conn


def main():
    parser = argparse.ArgumentParser(description="YubiKey PIV management tool")
    parser.add_argument("--slot", default=None, choices=slot_map.keys(),
                        help="PIV slot. Default per operation: AUTHENTICATION (9a) "
                             "for --sign / --verify / --derive-password, "
                             "KEY_MANAGEMENT (9d) for --decrypt. "
                             "Required for --import.")
    parser.add_argument("--mgmt-key", default=None,
                        help="Management key (hex). Accepts pass:<val> / file:<path> / fd:<n> / env:<var> selectors -- recommended in production so the key never appears on argv / /proc/<pid>/cmdline.")
    parser.add_argument("--pin", default=None,
                        help="PIN. Accepts pass:<val> / file:<path> / fd:<n> / env:<var> selectors -- recommended in production.")
    parser.add_argument("--serial", type=int, default=None, help="YubiKey serial number")
    parser.add_argument("--use-agent", action="store_true",
                        help="Use otpme-agent for PIV operations")
    parser.add_argument("--list", action="store_true", help="List keys on YubiKey")
    parser.add_argument("--reset", action="store_true", help="Reset PIV applet to factory defaults")
    parser.add_argument("--import", dest="import_key", action="store_true",
                        help="Import RSA private key from stdin")
    parser.add_argument("--passphrase", action="store_true", help="Prompt for PEM passphrase")
    parser.add_argument("--change-pin", action="store_true", help="Change PIN")
    parser.add_argument("--change-puk", action="store_true", help="Change PUK")
    parser.add_argument("--old-pin", default=None,
                        help="Current PIN. Accepts pass:<val> / file:<path> / fd:<n> / env:<var> selectors -- recommended in production.")
    parser.add_argument("--new-pin", default=None,
                        help="New PIN. Accepts pass:<val> / file:<path> / fd:<n> / env:<var> selectors -- recommended in production.")
    parser.add_argument("--old-puk", default=None,
                        help="Current PUK. Accepts pass:<val> / file:<path> / fd:<n> / env:<var> selectors -- recommended in production.")
    parser.add_argument("--new-puk", default=None,
                        help="New PUK. Accepts pass:<val> / file:<path> / fd:<n> / env:<var> selectors -- recommended in production.")
    parser.add_argument("--decrypt", action="store_true", help="RSA-decrypt stdin to stdout (slot 9D by default)")
    parser.add_argument("--hpke-decrypt", action="store_true",
                        help="HPKE-decap stdin (X25519+HKDF-SHA256+AES-256-GCM) using slot 9D ECDH, write plaintext to stdout. --info must match the encrypt-side label.")
    parser.add_argument("--info", default=None,
                        help="HPKE info string (default: otpme-hpke-x25519-v1)")
    parser.add_argument("--sign", action="store_true", help="Sign stdin, write signature to stdout")
    parser.add_argument("--csr", action="store_true",
                    help="Write a certificate signing request for the slot's key to stdout")
    parser.add_argument("--subject", default=None,
                    help="Subject of the request, RFC 4514 (for --csr), e.g. 'CN=alice,O=OTPme'")
    parser.add_argument("--san-email", default=None,
                    help="E-mail address(es) for the subject alternative name (for --csr), comma separated")
    parser.add_argument("--key-usage", default=None,
                    help="Key usage of the request (for --csr), e.g. 'digital_signature,key_encipherment'")
    parser.add_argument("--ext-key-usage", default=None,
                    help="Extended key usage of the request (for --csr), e.g. 'email_protection'")
    parser.add_argument("--import-cert", action="store_true",
                    help="Put the certificate on stdin (PEM) into the slot")
    parser.add_argument("--public-key-out", action="store_true",
                    help="Write the public key of the slot to stdout (PEM). For a key that cannot sign a request of its own, e.g. X25519 in slot 9d.")
    parser.add_argument("--verify", action="store_true", help="Verify stdin against --signature")
    parser.add_argument("--signature", default=None, help="Signature file (for --verify)")
    parser.add_argument("--public-key", default=None, help="Public key PEM (for --verify, otherwise from YubiKey)")
    parser.add_argument("--padding", default=None, choices=["oaep", "pkcs1v15", "pss"],
                        help="RSA padding (decrypt: oaep, sign: pss)")
    parser.add_argument("--derive-password", action="store_true", help="Derive a password from a challenge")
    parser.add_argument("--challenge", default=None, help="Challenge string for password derivation")
    parser.add_argument("--derive-length", type=int, default=32,
                        help="Length of derived password in bytes (default: 32)")
    parser.add_argument("--piv-login", action="store_true",
                        help="Login to PIV session via otpme-agent")
    parser.add_argument("--piv-check", action="store_true",
                        help="Check if PIV session in otpme-agent is alive")
    args = parser.parse_args()

    if args.piv_login:
        agent = _get_agent()
        pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
        response = agent.piv_login(pin)
        print(response)

    elif args.piv_check:
        agent = _get_agent()
        if agent.piv_check():
            print("PIV session is active.")
        else:
            print("No active PIV session.")
            sys.exit(1)

    elif args.derive_password:
        if not args.challenge:
            parser.error("--derive-password requires --challenge")
        slot = args.slot or SIGN_SLOT_DEFAULT
        if args.use_agent:
            agent = _get_agent()
            pw = agent.piv_derive_password(
                challenge=args.challenge,
                slot=slot,
                length=args.derive_length,
            )
        else:
            pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
            pw = derive_password(
                challenge=args.challenge,
                pin=pin,
                slot=slot,
                length=args.derive_length,
                serial=args.serial,
            )
        print(pw)

    elif args.reset:
        reset(serial=args.serial)

    elif args.list:
        list_keys(serial=args.serial)

    elif args.change_pin:
        change_pin(old_pin=_resolve_pin(args.old_pin),
                   new_pin=_resolve_pin(args.new_pin),
                   serial=args.serial)

    elif args.change_puk:
        change_puk(old_puk=_resolve_pin(args.old_puk),
                   new_puk=_resolve_pin(args.new_puk),
                   serial=args.serial)

    elif args.decrypt:
        data = sys.stdin.buffer.read()
        slot = args.slot or ENCRYPT_SLOT_DEFAULT
        if args.use_agent:
            agent = _get_agent()
            data = data.hex()
            plain_text = agent.piv_decrypt(
                data=data,
                slot=slot,
                padding=args.padding or "oaep",
            )
            plain_text = bytes.fromhex(plain_text)
        else:
            plain_text = decrypt(
                cipher_text=data,
                slot=slot,
                pin=_resolve_pin(args.pin),
                padding=args.padding or "oaep",
                serial=args.serial,
            )
        sys.stdout.buffer.write(plain_text)

    elif args.hpke_decrypt:
        # HPKE-decap via the slot's X25519 ECDH primitive. yubikit's
        # calculate_secret returns the raw 32-byte shared secret; our
        # decap helper does the RFC 9180 key schedule + AEAD.
        slot = args.slot or ENCRYPT_SLOT_DEFAULT
        blob = sys.stdin.buffer.read()
        if args.use_agent:
            # Agent owns the PIV session (cached PIN). Hand it the blob
            # hex-encoded; the agent runs the ECDH + decap and returns
            # the plaintext hex-encoded.
            agent = _get_agent()
            info_str = args.info  # already a str, or None → agent default
            plain_text_hex = agent.piv_hpke_decrypt(
                data=blob.hex(),
                slot=slot,
                info=info_str,
            )
            plain_text = bytes.fromhex(plain_text_hex)
        else:
            from otpme.lib.smartcard.yubikey.piv import (
                get_public_key as _piv_get_pub, ecdh as _piv_ecdh,
            )
            from otpme.lib.encryption.x25519 import (
                hpke_decap_x25519_aes256gcm, HPKE_INFO_DEFAULT,
            )
            info = args.info.encode() if args.info else HPKE_INFO_DEFAULT
            pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
            # Recipient pubkey for the KEM context. Read from the same slot
            # we'll do the ECDH on (otherwise the kem_context wouldn't bind).
            recipient_pub = _piv_get_pub(slot=slot, serial=args.serial)
            recipient_pub_bytes = recipient_pub.public_bytes(
                Encoding.Raw, PublicFormat.Raw,
            )
            def _ecdh(enc_bytes):
                return _piv_ecdh(peer_public_key=enc_bytes,
                                 slot=slot, pin=pin, serial=args.serial)
            plain_text = hpke_decap_x25519_aes256gcm(
                blob=blob,
                recipient_public_bytes=recipient_pub_bytes,
                ecdh_func=_ecdh,
                info=info,
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
            with open(args.public_key, "rb") as f:
                public_key = load_pem_public_key(f.read())
        slot = args.slot or SIGN_SLOT_DEFAULT
        valid = verify(
            data=data,
            signature=signature,
            public_key=public_key,
            slot=slot_map[slot],
            padding=args.padding or "pss",
            serial=args.serial,
        )
        if valid:
            print("Signature valid.")
        else:
            print("Signature INVALID!")
            sys.exit(1)

    elif args.sign:
        data = sys.stdin.buffer.read()
        slot = args.slot or SIGN_SLOT_DEFAULT
        if args.use_agent:
            agent = _get_agent()
            data = data.hex()
            signature = agent.piv_sign(
                data=data,
                slot=slot,
                padding=args.padding or "pss",
            )
            signature = bytes.fromhex(signature)
        else:
            pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
            signature = sign(
                data=data,
                slot=slot,
                pin=pin,
                padding=args.padding or "pss",
                serial=args.serial,
            )
        sys.stdout.buffer.write(signature)

    elif args.csr:
        if not args.subject:
            parser.error("--csr requires --subject")
        # No --use-agent: the agent signs data, and a request has to be
        # built around the signature. The card is asked directly, which
        # means the PIN is asked for here.
        pin = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
        csr = gen_csr(
            subject=args.subject,
            slot=args.slot or SIGN_SLOT_DEFAULT,
            pin=pin,
            san_email=_split_list(args.san_email),
            key_usage=_split_list(args.key_usage),
            ext_key_usage=_split_list(args.ext_key_usage),
            serial=args.serial,
        )
        sys.stdout.write(csr)

    elif args.public_key_out:
        # No PIN: the public key is read from the slot metadata, or
        # from the certificate of the slot where there is one.
        slot = args.slot or SIGN_SLOT_DEFAULT
        if args.use_agent:
            # The agent holds the card while it has a PIV session.
            agent = _get_agent()
            sys.stdout.write(agent.piv_get_public_key(slot=slot))
        else:
            sys.stdout.write(export_public_key(
                slot=slot,
                serial=args.serial,
            ))

    elif args.import_cert:
        if not args.slot:
            parser.error(
                "--import-cert requires --slot — the certificate belongs "
                "to the key of one slot."
            )
        # The management key, not the PIN: writing to a slot is a
        # management operation, the same as importing a key. Resolved
        # the way --import resolves it, so "file:" and the rest work
        # here too.
        kwargs = dict(slot=args.slot, serial=args.serial)
        if args.mgmt_key:
            kwargs["mgmt_key"] = bytes.fromhex(_resolve_pin(args.mgmt_key))
        else:
            # A card that was deployed keeps its management key on
            # itself, and the PIN is what reads it out.
            kwargs["pin"] = _resolve_pin(args.pin) or getpass.getpass("PIN: ")
        cert = import_certificate(
            certificate=sys.stdin.buffer.read(),
            **kwargs,
        )
        print(f"Certificate imported to slot {args.slot}: {cert.subject.rfc4514_string()}")

    elif args.import_key:
        if not args.slot:
            parser.error(
                "--import requires --slot — choose AUTHENTICATION (9a) for the "
                "sign key or KEY_MANAGEMENT (9d) for the encrypt key."
            )
        pem_data = sys.stdin.buffer.read()
        if args.passphrase:
            pem_password = getpass.getpass("PEM passphrase: ").encode()
            key = load_pem_private_key(pem_data, password=pem_password)
            pem_data = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        kwargs = dict(slot=args.slot, serial=args.serial)
        if args.mgmt_key:
            kwargs["mgmt_key"] = bytes.fromhex(_resolve_pin(args.mgmt_key))
        if _resolve_pin(args.pin):
            kwargs["pin"] = _resolve_pin(args.pin)
        import_private_key(pem_data, **kwargs)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
