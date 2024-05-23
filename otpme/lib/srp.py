# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import stuff

def gen(password_hash):
    """ Generate session refresh password """
    # Build refresh pass hash.
    refresh_pass_hash = stuff.gen_md5("Refresh:%s" % password_hash)
    # Get SRP..
    refresh_pass = refresh_pass_hash[0:config.logout_pass_len]
    return refresh_pass
