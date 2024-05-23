# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from oath import _totp as totp

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

def generate_totp(epoch_time, secret, period, format):
    """ Generate an TOTP from the given secret and time period. """
    secret = decode(secret, "base32")
    secret = encode(secret, "hex")
    try:
        otp = totp.totp(key=secret, period=period, t=epoch_time, format=format)
    except Exception as e:
        raise Exception("Error generating TOTP: %s" % e)
    return otp


def verify_totp(epoch_time, secret, period, otp,
    format, backward_drift, forward_drift, drift=0):
    """ Verify TOTP for an given time period. """
    secret = decode(secret, "base32")
    secret = encode(secret, "hex")
    otp = otp
    try:
        totp_status, \
        totp_drift = totp.accept_totp(key=secret,
                                    response=otp,
                                    period=period,
                                    t=epoch_time,
                                    format=format,
                                    backward_drift=backward_drift,
                                    forward_drift=forward_drift,
                                    drift=drift)
    except Exception as e:
        raise OTPmeException("Error verifying TOTP: %s" % e)
    return totp_status, totp_drift
