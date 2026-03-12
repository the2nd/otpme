# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import struct

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib.exceptions import *

def send(socket_handler, data):
    """ Function to handle data sending through socket connection. """
    # Build header with data length to send.
    header = struct.pack(">I", len(data))
    totalsent = socket_handler.raw_sendall(header + data)
    return totalsent

def sendall(socket_handler, data):
    """ Actually send all data. """
    try:
        socket_handler.raw_sendall(data)
    except Exception as e:
        msg = _("Broken connection while sending data: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg)

def recv(socket_handler, **kwargs):
    """ Function to handle data receiving through socket connection. """
    # Get header with data length from peer.
    header = socket_handler.raw_recv(4)
    if not header:
        return b""
    # Get data length.
    data_len = struct.unpack(">I", header)[0]
    # Receive into pre-allocated buffer to avoid copies.
    buf = memoryview(bytearray(data_len))
    bytes_recvd = 0
    while bytes_recvd < data_len:
        chunk = socket_handler.raw_recv(data_len - bytes_recvd)
        if not chunk:
            msg = ("Broken connection while receiving data.")
            raise OTPmeException(msg)
        chunk_len = len(chunk)
        buf[bytes_recvd:bytes_recvd + chunk_len] = chunk
        bytes_recvd += chunk_len
    return bytes(buf)
