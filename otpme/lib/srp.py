# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import stuff

def gen(password_hash):
    """ Generate session refresh password """
    # Build refresh pass hash.
    refresh_pass_hash = stuff.gen_md5(f"Refresh:{password_hash}")
    # Get SRP..
    refresh_pass = refresh_pass_hash[0:config.logout_pass_len]
    return refresh_pass
