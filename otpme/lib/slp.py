# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import stuff

def gen(password_hash):
    """ Generate session logout password. """
    # Build logout pass hash.
    logout_pass_hash = stuff.gen_md5(f"Logout:{password_hash}")
    # Get SLP.
    logout_pass = logout_pass_hash[0:config.logout_pass_len]
    return logout_pass
