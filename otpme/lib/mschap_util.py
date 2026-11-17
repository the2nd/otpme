# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import hmac

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import mschap
from otpme.lib.encoding.base import encode

# The hex here is decoded with bytes.fromhex(), not encoding.base.decode():
# that one hands back a str wherever the bytes happen to be valid UTF-8,
# which an 8 byte challenge is about once in a hundred, and DES refuses a
# str with a TypeError.

def verify(password_hash, challenge, response):
    """ Verify MSCHAP challenge/response with given pw_hash. """
    # Decode challenge.
    challenge_bin = bytes.fromhex(challenge)
    # Decode pass hash.
    password_hash_bin = bytes.fromhex(password_hash)
    # Create response.
    my_response_bin = mschap.challenge_response(challenge_bin, password_hash_bin)
    # Encode response.
    my_response = encode(my_response_bin, "hex")
    if hmac.compare_digest(my_response, response):
        # Generate NT_KEY we need to return.
        nt_key_bin = mschap.hash_nt_password_hash(password_hash_bin)
        # Encode and uppercase NT_KEY.
        nt_key = encode(nt_key_bin, "hex").upper()
        # Return status and NT_KEY.
        return True, nt_key
    return False, False

def generate(username, password_hash):
    """ Generate MSCHAP challenge/response and NT_KEY. """
    if not isinstance(username, bytes):
        username = username.encode("ascii")
    # Decode password hash.
    password_hash_bin = bytes.fromhex(password_hash)
    # Generate random challenges.
    peer_challenge_bin = os.urandom(16)
    auth_challenge_bin = os.urandom(16)
    # Generate NT password hash.
    nt_key_bin = mschap.hash_nt_password_hash(password_hash_bin)
    # Generate challenge.
    challenge_bin = mschap.challenge_hash(peer_challenge_bin,
                                            auth_challenge_bin,
                                            username)
    # Generate response.
    response_bin = mschap.challenge_response(challenge_bin, password_hash_bin)
    # Encode challenge.
    challenge = encode(challenge_bin, "hex")
    # Encode response.
    response = encode(response_bin, "hex")
    # Encode NT_KEY uppercase.
    nt_key = encode(nt_key_bin, "hex").upper()
    return nt_key, challenge, response
