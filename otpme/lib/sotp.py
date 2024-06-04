# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import stuff
from otpme.lib import mschap_util
from otpme.lib.otp.otpme import otpme
from otpme.lib.encryption import hash_password

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = [
                #"otpme.lib.classes.token",
                "otpme.lib.encryption.pbkdf2",
                ]

def register():
    register_config()

def register_config():
    """ Register config stuff. """
    # SOTP len (used by otpme-agent when generating SOTP)
    config.register_config_var("sotp_len", int, 16)
    # An SOTP is verified 30 seconds in the past and the future (timestep is in 10
    # seconds)
    config.register_config_var("sotp_timedrift_tolerance", int, 3)
    config.register_config_var("sotp_validity_time", int, 3)

def derive_rsp(secret, hash_type, salt, rsp_len=None):
    """ Derive RSP from secret. """
    if rsp_len is None:
        rsp_len = config.rsp_len
    result = hash_password(secret, hash_type=hash_type,
                            salt=salt,
                            iterations=1,
                            quiet=True)
    rsp = result['hash'][0:rsp_len]
    return rsp

def verify(password_hash, epoch_time=None, validity_range=None, reneg=False,
    password=None, challenge=None, response=None,
    sotp_len=None, access_group=None):
    """ Verify session OTP. """
    if sotp_len is None:
        sotp_len = config.sotp_len

    if not epoch_time:
        # Get epoch time (10 second timestep).
        epoch_time = int(str(int(time.time()))[:-1])

    if not validity_range:
        # Calculate SOTP validity times.
        validity_times = otpme.get_validity_times(
                        validity_time=config.sotp_validity_time,
                        timedrift_tolerance=config.sotp_timedrift_tolerance,
                        offset=0, epoch_time=epoch_time)
        # Get epoch time that honors timedrift values.
        epoch_time = validity_times[0]
        validity_range = validity_times[1]

    # Check for renegotiation OTP if needed
    if reneg:
        secret = "RENEG:%s" % password_hash
    elif access_group:
        secret = "%s:%s" % (access_group, password_hash)
    else:
        secret = password_hash

    # If we got a password from a clear-text request we have to verify it
    # against all possible SOTPs for the given validity range.
    if password:
        for o in otpme.generate(epoch_time=epoch_time, secret=secret,
                                otp_count=validity_range, otp_len=sotp_len):
            if o == password:
                return True
        return False
    else:
        # If we got a MSCHAP challenge/response pair we have to verify the hash
        # of all possible SOTPs for the given validity range.
        for o in otpme.generate(epoch_time=epoch_time, secret=secret,
                                otp_count=validity_range, otp_len=sotp_len):
            o_hash = stuff.gen_nt_hash(o)
            mschap_verify_status, nt_key = mschap_util.verify(o_hash,
                                                            challenge,
                                                            response)
            if mschap_verify_status:
                return mschap_verify_status, nt_key, o, o_hash
        return False, None, None, None

def gen(epoch_time=None, password_hash=None, sotp_len=None,
    reneg=False, rsp_hash_type=None, access_group=None):
    """ Generate session OTP. """
    if not epoch_time:
        # get epoch time (10 second timestep)
        epoch_time = int(str(int(time.time()))[:-1])

    if sotp_len is None:
        sotp_len = config.sotp_len

    # Generate renegotiation OTP if needed.
    if reneg:
        if not rsp_hash_type:
            msg = "Need <rsp_hash_type>."
            raise OTPmeException(msg)
        secret = "RENEG:%s" % password_hash
        reneg_salt = stuff.gen_secret(32)
    elif access_group:
        secret = "%s:%s" % (access_group, password_hash)
    else:
        secret = password_hash

    # Generate OTP.
    otp = otpme.generate(epoch_time=epoch_time, secret=secret,
                            otp_count=1, otp_len=sotp_len)
    if reneg:
        # Generate new RSP.
        new_pass = derive_rsp(secret=otp,
                    hash_type=rsp_hash_type,
                    salt=reneg_salt)
        return otp, reneg_salt, new_pass
    return otp
