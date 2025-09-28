# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import ssl
import socket
import logging
from relppy.log_handler import RelpHandler
from tlssysloghandler import TLSSysLogHandler

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib.multiprocessing import register_atfork_method
from otpme.lib.multiprocessing import register_cleanup_method

from otpme.lib.exceptions import *

active_log_handlers = []

def clear_log_handlers():
    global active_log_handlers
    active_log_handlers.clear()
register_atfork_method(clear_log_handlers)

def close_log_handlers():
    global active_log_handlers
    for handler in list(active_log_handlers):
        try:
            handler.close()
        except:
            pass
    active_log_handlers.clear()
register_cleanup_method(close_log_handlers)

def get_reconnecting_handler(handler_class):
    # https://stackoverflow.com/questions/40091456/python-sysloghandler-over-tcp-handling-connection-loss
    class ReconnectingSysLogHandler(handler_class):
        """Syslog handler that reconnects if the socket closes

        If we're writing to syslog with TCP and syslog restarts, the old TCP socket
        will no longer be writeable and we'll get a socket.error of type 32.  When
        than happens, use the default error handling, but also try to reconnect to
        the same host/port used before.  Also make 1 attempt to re-send the
        message.
        """
        def __init__(self, *args, facility="LOCAL7", spool_method=None, exception_on_emit=False, **kwargs):
            global active_log_handlers
            facility_id = f"LOG_{facility}"
            try:
                facility = getattr(logging.handlers.SysLogHandler, facility_id)
            except:
                msg = _("Unknown facility: {facility}")
                msg = msg.format(facility=facility)
                raise OTPmeException(msg)
            try:
                super(ReconnectingSysLogHandler, self).__init__(*args, **kwargs)
            except Exception as e:
                # We ignore socket errors because SysLogHandler calls createSocket()
                # and we dont want the log handler to fail on __init__() because we
                # want to spool records an failure.
                if not isinstance(e, socket.error):
                    raise
            self._is_retry = False
            self.spool_method = spool_method
            self.exception_on_emit = exception_on_emit
            active_log_handlers.append(self)

        def _reconnect(self):
            """Make a new socket that is the same as the old one"""
            # close the existing socket before getting a new one to the same host/port
            if self.socket:
                self.socket.close()
                self.socket = None
            super(ReconnectingSysLogHandler, self).createSocket()

        def handleError(self, record):
            # use the default error handling (writes an error message to stderr)
            super(ReconnectingSysLogHandler, self).handleError(record)

            # If we get an error within a retry, just return.  We don't want an
            # infinite, recursive loop telling us something is broken.
            # This leaves the socket broken.
            if self._is_retry:
                # If resend failed spool record.
                if self.spool_method:
                    try:
                        self.spool_method(record)
                    except Exception as e:
                        msg = _("Failed to spool record: {e}")
                        msg = msg.format(e=e)
                        print(msg)
                return

            # Set the retry flag and begin deciding if this is a closed socket, and
            # trying to reconnect.
            self._is_retry = True
            try:
                __, exception, __ = sys.exc_info()
                # If the error is a broken pipe exception (32)
                # or ssl EOF error (8) or connection refused (111),
                # get a new socket.
                if isinstance(exception, socket.error) and (exception.errno == 111 or exception.errno == 32 or exception.errno == 8):
                    try:
                        self._reconnect()
                    except:
                        if self.exception_on_emit:
                            raise
                    # Make an effort to rescue the record.
                    self.emit(record)
            finally:
                self._is_retry = False

        def close(self):
            global active_log_handlers
            # Perform graceful SSL shutdown before closing
            if self.socket:
                # Attempt graceful SSL shutdown
                if hasattr(self.socket, 'unwrap'):
                    self.socket.unwrap()
            super(ReconnectingSysLogHandler, self).close()
            try:
                active_log_handlers.remove(self)
            except ValueError:
                pass

    return ReconnectingSysLogHandler

def get_log_handler(address="/dev/log", use_ssl=False, ca_cert_file=None,
    client_cert_file=None, client_key_file=None, facility=None,
    relp=False, spool_method=None, exception_on_emit=False):
    from otpme.lib import config
    global active_log_handlers
    logger = config.logger
    if facility is None:
        facility = config.syslog_facility
    if use_ssl:
        if not ca_cert_file:
            msg = _("Need <ca_cert_file> with use_ssl=True.")
            raise OTPmeException(msg)
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=ca_cert_file,
        )
        if client_cert_file and client_key_file:
            # Load client cert/key.
            context.load_cert_chain(certfile=client_cert_file,
                                    keyfile=client_key_file)
        address = address.split(":")
        if len(address) < 2:
            msg = _("Invalid syslog address: {address}")
            msg = msg.format(address=address)
            raise OTPmeException(msg)
        if relp:
            log_handler = RelpHandler(address=address,
                                    facility=facility,
                                    context=context,
                                    resend_size=32,
                                    logger=logger,
                                    spool_method=spool_method,
                                    exception_on_emit=exception_on_emit,
                                    active_log_handlers=active_log_handlers)
        else:
            reconnecting_handler = get_reconnecting_handler(TLSSysLogHandler)
            log_handler = reconnecting_handler(address=address,
                                            socktype=socket.SOCK_STREAM,
                                            secure=context,
                                            facility=facility,
                                            spool_method=spool_method,
                                            exception_on_emit=exception_on_emit)
    else:
        if relp:
            address = address.split(":")
            log_handler = RelpHandler(address=address,
                                    facility=facility,
                                    resend_size=32,
                                    logger=logger,
                                    spool_method=spool_method,
                                    exception_on_emit=exception_on_emit,
                                    active_log_handlers=active_log_handlers)
        else:
            if len(address.split(":")) < 2:
                socktype = socket.SOCK_DGRAM
            else:
                socktype = socket.SOCK_STREAM
            reconnecting_handler = get_reconnecting_handler(logging.handlers.SysLogHandler)
            log_handler = reconnecting_handler(address=address,
                                            socktype=socktype,
                                            facility=facility,
                                            spool_method=spool_method,
                                            exception_on_emit=exception_on_emit)

    formatter = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
    log_handler.setFormatter(formatter)

    return log_handler
