# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pyqrcode

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

class IO(object):
    """ Fake class to handle QR code without temporary file. """
    def __init__(self):
        self._data = []
    def write(self, data):
        self._data.append(data)
    def __bytes__(self):
        data = bytes()
        for x in self._data:
            data += x
        return data

def gen_qrcode(data, fmt="svg", scale=8):
    """ Generate QR code image. """
    if fmt != "terminal":
        img_data = IO()
    pass_qrcode = pyqrcode.create(data)
    if fmt == "terminal":
        qrcode_data = pass_qrcode.terminal()
    elif fmt == "svg":
        pass_qrcode.svg(img_data, scale=scale)
        qrcode_data = bytes(img_data)
    elif fmt == "png":
        pass_qrcode.png(img_data, scale=scale)
        qrcode_data = bytes(img_data)
    else:
        msg = "Unknown format: %s" % fmt
        raise OTPmeTypeError(msg)
    return qrcode_data
