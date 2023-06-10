# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import sys

# Add otpme dir to path.
otpme_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
otpme_dir = os.path.dirname(otpme_dir)
sys.path.append(otpme_dir)

# Add PYTHONPATH.
PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
if os.path.exists(PYTHONPATH_FILE):
    fd = open(PYTHONPATH_FILE, "r")
    try:
        for x in fd.readlines():
            x = x.replace("\n", "")
            if x in sys.path:
                continue
            sys.path.append(x)
    finally:
        fd.close()

# Load OTPme config.
from otpme.lib.otpme_config import OTPmeConfig
config = OTPmeConfig(tool_name=u"pam_otpme", quiet=True)

from otpme.lib import pam

# Debug stuff.
#config.raise_exceptions = True
#config.print_tracebacks = True
#config.reload()

# Entry points we handle.
def pam_sm_authenticate(pamh, flags, argv):
    #return pamh.PAM_SUCCESS
    logger = config.logger
    logger.debug("Starting authenticate()...")
    try:
        pam_handler = pam.PamHandler(pamh, argv)
    except Exception as e:
        msg = "Error loading pam handler: %s" % e
        logger.critical(msg)
        config.raise_exception()
        return pamh.PAM_SYSTEM_ERR
    try:
        retval = pam_handler.authenticate()
    except Exception as e:
        msg = ("pam_sm_authenticate: Error in pam_otpme.py: %s" % e)
        logger.critical(msg, exc_info=True)
        retval = pamh.PAM_SYSTEM_ERR
    return retval

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    logger = config.logger
    logger.debug("Starting open_session()...")
    try:
        pam_handler = pam.PamHandler(pamh, argv)
    except Exception as e:
        msg = "Error loading pam handler: %s" % e
        logger.critical(msg)
        config.raise_exception()
        return pamh.PAM_SYSTEM_ERR
    try:
        retval = pam_handler.open_session()
    except Exception as e:
        msg = ("pam_sm_open_session: Error in pam_otpme.py: %s" % e)
        logger.critical(msg, exc_info=True)
        return pamh.PAM_SYSTEM_ERR
    return retval

def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
