# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from datetime import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import stuff
from otpme.lib.exceptions import *

def generate(secret, pin=None, otp_count=1, otp_len=None, epoch_time=None):
    """ Generate a list of valid OTPs. """
    if otp_len is None:
        msg = "Need <otp_len>."
        raise OTPmeException(msg)
    # Get epoch time in 10 second timestep.
    if not epoch_time:
        epoch_time = int(str(int(time.time()))[:-1])
    # If we got a PIN append it to our secret (e.g. when used from MOTP token)
    if pin:
        secret += str(pin)
    # Calculate OTP for each otp_count second in the future.
    i = 0
    otps = []
    while i < otp_count:
        # Generate OTP.
        otp = stuff.gen_md5(str(epoch_time)+str(secret))[0:otp_len]
        # Add new OTP to list.
        otps.append(otp)
        epoch_time = epoch_time + 1
        i += 1
    # Return list with calculated OTPs or just one.
    if len(otps) > 1:
        return otps
    return otps[0]


def verify(validity_range, secret, otp, pin=None, otp_len=None, epoch_time=None):
    """ Verify OTP for an given time range. """
    # Get epoch time in 10 second timestep.
    if not epoch_time:
        epoch_time = int(str(int(time.time()))[:-1])

    for o in generate(secret=secret,
                    otp_count=validity_range,
                    otp_len=otp_len,
                    epoch_time=epoch_time,
                    pin=pin):
        if otp == o:
            return True

    return False


def get_validity_times(validity_time, timedrift_tolerance=0,
    offset=0, epoch_time=None, full_epoch_time=None):
    """ Calculate validity start/end time, timestamps etc. """
    # Get epoch time in 10 second timestep.
    if not epoch_time and not full_epoch_time:
        epoch_time = int(str(int(time.time()))[:-1])
    if full_epoch_time:
        otp_epoch_time = int(int(full_epoch_time) - validity_time + offset)
    else:
        otp_epoch_time = int((epoch_time * 10) - validity_time + offset)
    start_timestamp = otp_epoch_time - timedrift_tolerance
    end_timestamp = otp_epoch_time + validity_time + timedrift_tolerance
    if full_epoch_time:
        otp_validity_range = ((end_timestamp - start_timestamp) * 2)
    else:
        otp_validity_range = (((end_timestamp - start_timestamp) / 10) * 2)
    if epoch_time:
        epoch_time = int(otp_epoch_time[:-1])
    start_time = datetime.fromtimestamp(start_timestamp)
    end_time = datetime.fromtimestamp(end_timestamp)
    start_time = str(start_time)
    end_time = str(end_time)
    return (otp_epoch_time,
            otp_validity_range,
            start_timestamp,
            end_timestamp,
            start_time,
            end_time)
