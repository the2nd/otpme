# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Reaching the daemon the two sides of a session meet at.

Used by both of them: the host that was given a remote_access job, and
whoever asked for the shell. Both say which job they are here for, and
both get the same thing back -- a socket that carries bytes to the
other one.

The connection stops being an OTPme connection at that point. The
answer to "meet" is the last frame either side reads, and everything
after it is the session. That works because recv() takes the length
from the header and then exactly that many bytes (socket/send_recv1.py)
-- it never reads ahead, so nothing of the session is swallowed by the
framing on its way out.
"""
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-rac-1.0"

def register():
    config.register_otpme_protocol("racd", PROTOCOL_VERSION)


class OTPmeRacP1(OTPmeClient1):
    """ Class that implements client for protocol OTPme-rac-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "racd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super().__init__(self.daemon, **kwargs)

    def meet(self, key, role):
        """ Say which job we are here for and take the socket over.

        Returns the socket the other side is at the far end of. From
        then on this connection is no longer ours to speak on: what
        goes through it is the session.
        """
        command_args = {
                    'key'   : key,
                    'role'  : role,
                    }
        status, \
        status_code, \
        response, \
        binary_data = self.connection.send("meet", command_args)
        if not status:
            msg = _("No session: {response}")
            msg = msg.format(response=response)
            raise OTPmeException(msg)
        # The socket under the connection, which is where the other
        # side is now. Two steps down, because self.connection is the
        # client object we were made by, and the socket it was given
        # sits under that one.
        sock = self.connection.connection._socket
        # And from here on it is the session's, not ours. Said out loud
        # in two places, because both of them would otherwise take the
        # session down without knowing it was there: the cache would hand
        # this connection to whoever asks for one next, who would ping it
        # and close it when no "pong" came back, and closing it sends
        # "quit" on it and shuts it down -- four bytes in the middle of
        # somebody's session, and then no session.
        from otpme.lib import connections
        connections.forget(self.connection)
        self.connection.connection.hand_over()
        return sock
