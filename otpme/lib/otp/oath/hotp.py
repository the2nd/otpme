# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
from oath import _hotp as hotp

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

def generate_hotp(counter, secret, format):
    """ Generate an HOTP from the given secret and token counter. """
    # Prevent "decode method has been disabled in newst".
    secret = secret
    try:
        otp = hotp.hotp(key=secret, counter=counter, format=format)
    except Exception as e:
        raise Exception("Error generating HOTP: %s" % e)
    return otp


def verify_hotp(counter_start, counter_end, secret, otp, format):
    """ Verify HOTP for an given counter range. """
    # Prevent "decode method has been disabled in newst".
    secret = secret
    for i in range(counter_start, counter_end):
        hotp_status = False
        try:
            hotp_status, \
            hotp_count = hotp.accept_hotp(key=secret,
                                        response=otp,
                                        counter=i,
                                        format=format,
                                        drift=0,
                                        backward_drift=0)
        except Exception as e:
            raise OTPmeException("Error verifying HOTP: %s" % e)
        if hotp_status == True:
            # Because we store the last used token counter instead of the next
            # valid token counter we decrease by 1.
            last_used_count = hotp_count - 1
            return True, last_used_count
    return False, ""
