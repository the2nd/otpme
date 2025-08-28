# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import struct

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
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
        msg = "Broken connection while sending data: %s" % e
        raise OTPmeException(msg)

def recv(socket_handler, **kwargs):
    """ Function to handle data receiving through socket connection. """
    # Get header with data length from peer.
    header = socket_handler.raw_recv(4)
    if not header:
        return b""
    # Get data length.
    data_len = struct.unpack(">I", header)[0]
    # Set receive buffer depending on data length.
    if data_len > 16384:
        recv_buffer = data_len
    elif data_len > 8192:
        recv_buffer = 8192
    elif data_len > 4096:
        recv_buffer = 4096
    else:
        recv_buffer = 2048
    # Now receive data.
    # https://docs.python.org/2/howto/sockets.html
    chunks = []
    bytes_recvd = 0
    while bytes_recvd < data_len:
        _recv_buff = min(data_len - bytes_recvd, recv_buffer)
        chunk = socket_handler.raw_recv(_recv_buff)
        if not chunk:
            msg = ("Broken connection while receiving data.")
            raise OTPmeException(msg)
        chunks.append(chunk)
        bytes_recvd = bytes_recvd + len(chunk)
    # Join chunks.
    received = b''.join(chunks)
    return received
