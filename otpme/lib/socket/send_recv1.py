# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

def send(socket_handler, data):
    """ Function to handle data sending through socket connection. """
    # Get length of data to send.
    data_len = len(data)
    # Send length of data to peer.
    request = "req_len:" + str(data_len)
    sent = socket_handler.raw_send(request)
    # Check if command was sent successful.
    if sent != len(request):
        msg = ("Error while data len negotiation.")
        raise OTPmeException(msg)
    # Get response.
    response = socket_handler.raw_recv(1024)
    # Check if we got ACK from peer.
    if response != "ack_len:%s" % data_len:
        msg = (_("Unknown acknowledge message from peer: %s") % response)
        raise OTPmeException(msg)
    # Now send data.
    totalsent = socket_handler.raw_send(data)
    return totalsent

def sendall(socket_handler, data):
    """ Actually send all data. """
    try:
        socket_handler.raw_sendall(request)
    except Exception as e:
        msg = "Broken connection while sending data: %s" % e
        raise OTPmeException(msg)

def recv(socket_handler, recv_buffer=4096):
    """ Function to handle data receiving through socket connection. """
    # Get data from peer.
    data = socket_handler.raw_recv(recv_buffer)
    # Try to get data length from peer.
    try:
        data_len = int(data.split(":")[1])
    except Exception as e:
        response = (_("Error: Unable to get data len from request: %s") % data)
        socket_handler.raw_send(response)
        raise OTPmeException(response)
    # Build ACK response message.
    response = "ack_len:" + str(data_len)
    # Try to send ACK.
    try:
        socket_handler.raw_send(response)
    except Exception as e:
        msg = (_("Error while data len negotiation: %s") % e)
        raise OTPmeException(msg)
    # Set receive buffer depending on data length.
    if data_len > 16384:
        recv_buffer = 16384
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
        if chunk == '':
            msg = ("Broken connection while receiving data.")
            raise OTPmeException(msg)
        chunks.append(chunk)
        bytes_recvd = bytes_recvd + len(chunk)
    # Relace tailing newline.
    received = ''.join(chunks).replace("\n", "")
    return received
