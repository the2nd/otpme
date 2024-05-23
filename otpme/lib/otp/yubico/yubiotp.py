# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib.encryption import aes
from otpme.lib.encoding.base import decode

def hexdec(hex):
    return int(hex, 16)

def modhex2hex(string):
    hex = "0123456789abcdef"
    modhex = "cbdefghijklnrtuv"
    retVal = ''
    for i in range (0, len(string)):
            pos = modhex.find(string[i])
            if pos > -1:
                    retVal += hex[pos]
            else:
                msg = '"' + string[i] + '": Character is not a valid hex string'
                raise Exception(msg)
    return retVal

def gen_crc(string):
    crc = 0xffff;
    for i in range(0, 16):
            b = hexdec(string[i*2] + string[(i*2)+1])
            crc = crc ^ (b & 0xff)
            for j in range(0, 8):
                    n = crc & 1
                    crc = crc >> 1
                    if n != 0:
                            crc = crc ^ 0x8408
    return crc

def verify_crc(crc):
    return (crc == 0xf0b8)

def verify(otp, token_uid, token_counter, token_time, token_aeskey):
    otp = re.escape(otp)

    if (len(otp) <= 32) or (len(otp) > 48):
        raise Exception("OTP length mismatch.")

    match = re.search('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})', re.escape(otp))
    if match == None:
        raise Exception("OTP does not match expected syntax.")

    ## Try to get public id from received OTP.
    #try:
    #    otp_public_id = match.group(1)
    #except:
    #    raise Exception("Unable to get public id from OTP.")

    # Try to get encrypted message (token) from OTP.
    try:
        otp_aes_message = modhex2hex(match.group(2))
    except:
        raise Exception("Unable to get encrypted message from OTP.")

    try:
        otp_plaintext_message = decode(aes.decrypt(token_aeskey, otp_aes_message, "hex"))
    except:
        raise Exception("Error decrypting message from OTP.")

    otp_uid = otp_plaintext_message[:12]

    if (token_uid != otp_uid):
        raise Exception("UID mismatch: uid (private id) from the decrypted AES message of the OTP does not match the uid of this token (set with with ykpersonalize -ouid)")

    try:
        otp_crc = gen_crc(otp_plaintext_message)
    except:
        raise Exception("OTP CRC generation failed.")

    if not verify_crc(otp_crc):
        raise Exception("OTP CRC verification failed.")

    otp_counter = hexdec(otp_plaintext_message[14:16] + otp_plaintext_message[12:14] + otp_plaintext_message[22:24])
    otp_timestamp = hexdec(otp_plaintext_message[20:22] + otp_plaintext_message[18:20] + otp_plaintext_message[16:18])

    if (token_counter) >= (otp_counter):
        raise Exception("OTP already used.")

    if (token_time >= otp_timestamp) and ((token_counter >> 8) == (otp_counter >> 8)):
        raise Exception("Delayed OTP.")

    return True, otp_counter, otp_timestamp
