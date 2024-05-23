# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import random

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import mschap
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

def verify(password_hash, challenge, response):
    """ Verify MSCHAP challenge/response with given pw_hash. """
    # Decode challenge.
    challenge_bin = decode(challenge, "hex")
    # Decode pass hash.
    password_hash_bin = decode(password_hash, "hex")
    # Create response.
    my_response_bin = mschap.challenge_response(challenge_bin, password_hash_bin)
    # Encode response.
    my_response = encode(my_response_bin, "hex")
    if my_response == response:
        # Generate NT_KEY we need to return.
        nt_key_bin = mschap.hash_nt_password_hash(password_hash_bin)
        # Encode and uppercase NT_KEY.
        nt_key = encode(nt_key_bin, "hex").upper()
        # Return status and NT_KEY.
        return True, nt_key
    return False, False

def generate(username, password_hash):
    """ Generate MSCHAP challenge/response and NT_KEY. """
    from builtins import range
    if not isinstance(username, bytes):
        username = username.encode("ascii")
    # Decode password hash.
    password_hash_bin = decode(password_hash, "hex")
    # Generate randmon challenges.
    peer_challenge_bin = "".join(chr(random.randrange(0, 255)) for i in range(16))
    auth_challenge_bin = "".join(chr(random.randrange(0, 255)) for i in range(16))
    peer_challenge_bin = peer_challenge_bin.encode()
    auth_challenge_bin = auth_challenge_bin.encode()
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
