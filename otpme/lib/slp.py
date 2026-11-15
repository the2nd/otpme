# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff

# The length of the session logout password (SLP) and the session
# refresh password (SRP, see srp.py). Fixed, not a config file
# parameter any more: the agent on a host works out the SRP itself and
# the node checks it with its own, so a value that differed between
# them made every session refresh fail.
LOGOUT_PASS_LEN = 6

def gen(password_hash):
    """ Generate session logout password. """
    # Build logout pass hash.
    logout_pass_hash = stuff.gen_sha256(f"Logout:{password_hash}")
    # Get SLP.
    logout_pass = logout_pass_hash[0:LOGOUT_PASS_LEN]
    return logout_pass
