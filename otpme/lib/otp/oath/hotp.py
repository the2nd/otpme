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

def generate_hotp(counter, secret):
    """ Generate an HOTP from the given secret and token counter. """
    hotp = pyotp.HOTP(secret)
    try:
        otp = hotp.at(counter)
    except Exception as e:
        raise Exception("Error generating HOTP: %s" % e)
    return otp


def verify_hotp(counter_start, counter_end, secret, otp):
    """ Verify HOTP for an given counter range. """
    hotp = pyotp.HOTP(secret)
    for i in range(counter_start, counter_end):
        hotp_status = False
        try:
            hotp_status = hotp.verify(otp, i)
        except Exception as e:
            raise OTPmeException("Error verifying HOTP: %s" % e)
        if hotp_status is True:
            last_used_count = i
            return True, last_used_count
    return False, ""
