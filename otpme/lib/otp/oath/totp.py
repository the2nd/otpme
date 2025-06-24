# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pyotp

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

def generate_totp(epoch_time, secret):
    """ Generate an TOTP from the given secret and time. """
    totp = pyotp.TOTP(secret)
    try:
        otp = totp.at(epoch_time)
    except Exception as e:
        raise Exception("Error generating TOTP: %s" % e)
    return otp


def verify_totp(epoch_time, secret, otp):
    """ Verify TOTP for an given time. """
    totp = pyotp.TOTP(secret)
    try:
        totp_status = totp.verify(otp=otp, for_time=epoch_time)
    except Exception as e:
        raise OTPmeException("Error verifying TOTP: %s" % e)
    return totp_status
