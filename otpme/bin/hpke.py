#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
"""Standalone HPKE encrypt/decrypt CLI.

Thin wrapper around cryptography.hpke for use from shell scripts
(notably key_script.sh) -- avoids the heavy OTPme bootstrap. Wire
format matches otpme.lib.encryption.x25519.X25519Key.encrypt/decrypt
(HPKE Base mode, KEM=X25519, KDF=HKDF-SHA256, AEAD=AES-256-GCM).
"""
import os
import sys
import argparse

# When run via symlink, resolve the real script location and add the
# project root (two levels up) to sys.path.
_script_dir = os.path.dirname(os.path.realpath(__file__))
_project_root = os.path.dirname(os.path.dirname(_script_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
if os.path.exists(PYTHONPATH_FILE):
    with open(PYTHONPATH_FILE, "r") as fd:
        for x in fd:
            x = x.rstrip("\n")
            if x and x not in sys.path:
                sys.path.insert(0, x)

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Suite + info-string must match otpme.lib.encryption.x25519.X25519Key
# verbatim so blobs are interchangeable between Python callers and
# shell callers. Hardcoded here to keep this CLI standalone (importing
# x25519.py would pull in otpme.lib.config and require full bootstrap).
HPKE_SUITE = hpke.Suite(
    hpke.KEM.X25519,
    hpke.KDF.HKDF_SHA256,
    hpke.AEAD.AES_256_GCM,
)
HPKE_INFO_DEFAULT = b"otpme-hpke-x25519-v1"


def _read_key(arg, mode):
    """ Read a PEM from --key <path> or stdin. mode is "pub" or "priv". """
    if arg == "-" or arg is None:
        data = sys.stdin.buffer.read()
    else:
        with open(arg, "rb") as fd:
            data = fd.read()
    if mode == "pub":
        return load_pem_public_key(data)
    return load_pem_private_key(data, password=None)


def main():
    parser = argparse.ArgumentParser(
        description="HPKE (X25519+HKDF-SHA256+AES-256-GCM) encrypt/decrypt"
    )
    parser.add_argument(
        "--info", default=HPKE_INFO_DEFAULT.decode(),
        help=f"HPKE info string (default: {HPKE_INFO_DEFAULT.decode()})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt",
        help="Read plaintext from stdin, write HPKE blob to stdout")
    enc.add_argument("--recipient-pub", required=True,
        help="Recipient X25519 public-key PEM file ('-' for stdin)")

    dec = sub.add_parser("decrypt",
        help="Read HPKE blob from stdin, write plaintext to stdout")
    dec.add_argument("--recipient-priv", required=True,
        help="Recipient X25519 private-key PEM file ('-' for stdin)")

    args = parser.parse_args()
    info = args.info.encode()

    if args.cmd == "encrypt":
        pub = _read_key(args.recipient_pub, "pub")
        plaintext = sys.stdin.buffer.read()
        blob = HPKE_SUITE.encrypt(plaintext, pub, info)
        sys.stdout.buffer.write(blob)
    elif args.cmd == "decrypt":
        priv = _read_key(args.recipient_priv, "priv")
        ciphertext = sys.stdin.buffer.read()
        plaintext = HPKE_SUITE.decrypt(ciphertext, priv, info)
        sys.stdout.buffer.write(plaintext)


if __name__ == "__main__":
    main()
