# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib.slp import LOGOUT_PASS_LEN

def gen(password_hash):
    """ Generate session refresh password """
    # Build refresh pass hash.
    refresh_pass_hash = stuff.gen_sha256(f"Refresh:{password_hash}")
    # Get SRP. Same length as the SLP, see slp.py.
    refresh_pass = refresh_pass_hash[0:LOGOUT_PASS_LEN]
    return refresh_pass
