# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from datetime import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
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
        secret += pin
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


def get_validity_times(validity_time,
    timedrift_tolerance=0, offset=0, epoch_time=None):
    """ Calculate validity start/end time, timestamps etc. """
    # Get epoch time in 10 second timestep.
    if not epoch_time:
        epoch_time = int(str(int(time.time()))[:-1])
    # Calculate epoch time to verify OTP:
    #   - epoch time must be reduced by timedrift_tolerance to allow clock
    #     timedrifts of the client in the past.
    #   - offset (e.g. timezone) must be multiplied with 6 (offset is in minutes,
    #     timestep is 10 seconds) and added to epoch time.
    otp_epoch_time = epoch_time - timedrift_tolerance + (offset * 6)
    # Add (timedrift_tolerance * 2) to validity_range because we had to
    # substract if from epoch_time to allow backward timedrifts and also
    # want to allow forward timedrifts.
    otp_validity_range = validity_time + (timedrift_tolerance * 2)
    # Calculate times and timestamps of OTP validity start/end times.
    start_timestamp = float(str(otp_epoch_time) + "0")
    end_timestamp = float(str(otp_epoch_time + otp_validity_range) + "0")
    start_time = str(datetime.fromtimestamp(start_timestamp))
    end_time = str(datetime.fromtimestamp(end_timestamp))
    return otp_epoch_time, \
            otp_validity_range, \
            start_timestamp, \
            end_timestamp, \
            start_time, \
            end_time
