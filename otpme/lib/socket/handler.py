# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import ssl
import socket
import errno

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.socket.send_recv1 import send
from otpme.lib.socket.send_recv1 import recv
from otpme.lib.socket.send_recv1 import sendall

from otpme.lib.exceptions import *

SOCKET_PROTOS = {
                    '1' : {
                            'send'      : send,
                            'recv'      : recv,
                            'sendall'   : sendall,
                        },
                    #'2' : {
                    #        'send'     : send,
                    #        'recv'     : recv,
                    #        'sendall'  : sendall,
                    #    },
                }

class SocketProtoHandler(object):
    def __init__(self, side, connection):
        self.send_handler = None
        self.recv_handler = None
        self.sendall_handler = None
        self.connection = connection
        self.side = side

    def encode_data_for_sending(self, data, encode="utf-8"):
        """ Encode data for sending. """
        # We need to send data as bytes().
        encode_data = False
        if isinstance(data, str):
            encode_data = True

        if encode_data:
            data = data.encode(encode)

        if not isinstance(data, bytes):
            msg = (_("Unable to encode data for sending: %s") % type(data))
            raise OTPmeException(msg)
        return data

    def raw_send(self, data):
        """ Actually send data. """
        # https://docs.python.org/2/howto/sockets.html
        totalsent = 0
        first_loop = True
        data = self.encode_data_for_sending(data)
        data_len = len(data)
        while totalsent < data_len:
            try:
                sent = self.connection.send(data[totalsent:])
            except Exception as e:
                if first_loop:
                    msg = "Connection closed by peer"
                    first_loop = False
                else:
                    msg = "Connection closed while sending data"
                raise ConnectionQuit(msg)
            if sent == 0:
                raise OTPmeException("Broken connection while sending data.")
            totalsent = totalsent + sent
        return totalsent

    def raw_recv(self, recv_buffer=config.socket_receive_buffer):
        """ Actually receive data. """
        # Restart data receiving on EINTR.
        # https://stackoverflow.com/questions/14136195/what-is-the-proper-way-to-handle-in-python-ioerror-errno-4-interrupted-syst
        try:
            data = self.connection.recv(recv_buffer)
        except socket.timeout as e:
            raise ConnectionTimeout(_("Connection timed out."))
        except ssl.SSLError as e:
            if e.errno != errno.EINTR:
                raise OTPmeException(_("SSL error: %s") % e)
            data = self.connection.recv(recv_buffer)
        except socket.error as e:
            if e.errno != errno.EINTR:
                raise
            data = self.connection.recv(recv_buffer)
        except IOError as e:
            if e.errno != errno.EINTR:
                raise
            data = self.connection.recv(recv_buffer)
        # Handle socket quit command (see listen.py/connect.py).
        if len(data) == 4:
            try:
                command = data.decode()
            except UnicodeDecodeError:
                command = None
            if command:
                command = command.strip()
                if command == "quit":
                    msg = "Remote site closed connection."
                    raise ConnectionQuit(msg)
        return data

    def raw_sendall(self, data):
        """ Actually send all data. """
        data = self.encode_data_for_sending(data)
        self.connection.sendall(data)

    def negotiate_socket_protocol_client(self):
        """ Negotiate socket protocol. """
        # Send supported protocols to peer.
        request = "socket_protos:%s" % ",".join(SOCKET_PROTOS)
        try:
            self.raw_send(request)
        except Exception as e:
            msg = ("Error sending socket protocol negotiation: %s" % e)
            raise OTPmeException(msg)
        # Get response.
        try:
            response = self.raw_recv()
        except Exception as e:
            msg = ("Error receiving socket protocol negotiation: %s" % e)
            raise OTPmeException(msg)
        response = response.decode()
        # Handle quit message (e.g. remote site wants to close connection).
        if len(response) == 4:
            try:
                command = response.decode()
            except UnicodeDecodeError:
                command = None
            if command:
                command = command.strip()
                if command == "quit":
                    msg = (_("Socket protocol negotiation ended by peer."))
                    raise ConnectionQuit(msg)
        # Check if we got ACK from peer.
        if not response.startswith("socket_proto:"):
            msg = (_("Unknown socket protocol response from peer: %s") % response)
            raise OTPmeException(msg)
        # Set handler.
        try:
            socket_proto = response.split(":")[1]
            self.send_handler = SOCKET_PROTOS[socket_proto]['send']
            self.recv_handler = SOCKET_PROTOS[socket_proto]['recv']
            self.sendall_handler = SOCKET_PROTOS[socket_proto]['sendall']
        except:
            msg = "Received invalid socket protocol from peer: %s" % response
            raise OTPmeException(msg)

    def negotiate_socket_protocol_server(self):
        """ Negotiate socket protocol. """
        # Receive protocol negotiation request
        try:
            proto_neg_req = self.raw_recv()
        except Exception as e:
            msg = ("Failed to receive protocol negotiation.")
            raise OTPmeException(msg)
        proto_neg_req = proto_neg_req.decode()
        try:
            client_socket_protos = proto_neg_req.split(":")[1].split(",")
        except:
            msg = "Received invalid protocol string."
            raise ConnectionQuit(msg)
        socket_proto = None
        for x in sorted(SOCKET_PROTOS):
            if x in client_socket_protos:
                socket_proto = x
        if socket_proto is None:
            request = "quit"
            try:
                self.raw_send(request)
            except Exception as e:
                msg = ("Failed to send protocol negotiation quit command.")
                raise OTPmeException(msg)
            msg = "Socket protocol negotiation failed."
            raise ConnectionQuit(msg)
        # Send protocol to use to peer.
        request = "socket_proto:%s" % socket_proto
        try:
            self.raw_send(request)
        except Exception as e:
            msg = ("Failed to send protocol negotiation.")
            raise OTPmeException(msg)
        try:
            self.send_handler = SOCKET_PROTOS[socket_proto]['send']
            self.recv_handler = SOCKET_PROTOS[socket_proto]['recv']
            self.sendall_handler = SOCKET_PROTOS[socket_proto]['sendall']
        except:
            msg = "Failed to load socket protocol."
            raise OTPmeException(msg)

    def send(self, data):
        """ Function to handle data sending through socket connection. """
        # Get socket protocol handler.
        if not self.send_handler:
            if self.side == "client":
                self.negotiate_socket_protocol_client()
        # Now send data.
        if config.debug_level("net_traffic") > 0:
            print("SEND: %s" % data)
        if self.send_handler:
            return self.send_handler(self, data)
        return self.raw_send(data)

    def sendall(self, data):
        """ Function to handle data sending through socket connection. """
        # Get socket protocol handler.
        if not self.sendall_handler:
            if self.side == "client":
                self.negotiate_socket_protocol_client()
        # Now send data.
        if config.debug_level("net_traffic") > 0:
            print("SEND: %s" % data)
        if self.sendall_handler:
            return self.sendall_handler(self, data)
        return self.raw_sendall(data)

    def recv(self, **kwarg):
        """ Function to handle data receiving through socket connection. """
        if not self.recv_handler:
            if self.side == "server":
                self.negotiate_socket_protocol_server()
        if self.recv_handler:
            received = self.recv_handler(self, **kwarg)
        else:
            received = self.raw_recv(**kwarg)
        if config.debug_level("net_traffic") > 0:
            print("RECV: %s" % received)
        return received
