# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pyotp

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except:
    pass

from otpme.lib.exceptions import *

def generate_totp(epoch_time, secret):
    """ Generate an TOTP from the given secret and time. """
    totp = pyotp.TOTP(secret)
    try:
        otp = totp.at(epoch_time)
    except Exception as e:
        msg = _("Error generating TOTP: {e}")
        msg = msg.format(e=e)
        raise Exception(msg)
    return otp


def verify_totp(epoch_time, secret, otp):
    """ Verify TOTP for an given time. """
    totp = pyotp.TOTP(secret)
    try:
        totp_status = totp.verify(otp=otp, for_time=epoch_time)
    except Exception as e:
        msg = _("Error verifying TOTP: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg)
    return totp_status
