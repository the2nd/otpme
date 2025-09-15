# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import ssl
import time
import socket
import logging
#import logging.handlers
from relppy.client import RelpTlsClient
from relppy.client import RelpTCPClient
from tlssysloghandler import TLSSysLogHandler

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

active_log_handlers = []

def close_log_handlers():
    global active_log_handlers
    for handler in list(active_log_handlers):
        try:
            handler.close()
        except:
            pass
    active_log_handlers.clear()

class RelpHandler(logging.handlers.SysLogHandler):
    def __init__(self, address, facility, context=None, resend_size=32):
        from otpme.lib import config
        global active_log_handlers
        self.address = address
        self.context = context
        self.facility = facility
        self.relp_client = None
        self.resend_size = resend_size
        logging.Handler.__init__(self)
        active_log_handlers.append(self)
        self.connection_broken = False
        self.logger = config.logger

    def createSocket(self):
        try:
            if self.context:
                self.relp_client = RelpTlsClient(address=self.address,
                                                context=self.context,
                                                resend_size=self.resend_size,
                                                server_hostname=self.address[0])
            else:
                self.relp_client = RelpTCPClient(address=self.address,
                                                resend_size=self.resend_size)
        except Exception as e:
            msg = ("Failed to connect to relp log server: %s: %s"
                    % (self.address, e))
            self.logger.warning(msg)
            raise

    def close(self):
        global active_log_handlers
        self.acquire()
        try:
            if self.relp_client:
                self.relp_client.close()
                self.relp_client = None
            logging.Handler.close(self)
            try:
                active_log_handlers.remove(self)
            except ValueError:
                pass
        finally:
            self.release()

    def emit(self, record):
        try:
            msg = self.format(record)
            if self.ident:
                msg = self.ident + msg
            if self.append_nul:
                msg += '\000'

            # We need to convert record level to lowercase, maybe this will
            # change in the future.
            prio = '<%d>' % self.encodePriority(self.facility,
                                                self.mapPriority(record.levelname))
            prio = prio.encode('utf-8')
            # Message is a string. Convert to bytes as required by RFC 5424
            msg = msg.encode('utf-8')
            msg = prio + msg

            if not self.relp_client:
                self.createSocket()
            self.relp_client.send_command(b"syslog", msg)
            self.connection_broken = False
        except Exception as e:
            spool_message = False
            # On socket error try to resend message.
            if isinstance(e, socket.error):
                if self.connection_broken:
                    spool_message = True
                else:
                    # Wait a moment for RELP client to reconnect.
                    time.sleep(0.3)
                    # Resend message.
                    try:
                        self.relp_client.send_command(b"syslog", msg)
                    except Exception as e:
                        self.connection_broken = True
                        spool_message = True
            else:
                spool_message = True
            # FIXME: Here we should spool not transmitted records.
            if spool_message:
                #print("sss", record.levelname, record.msg)
                self.handleError(record)

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
        def __init__(self, *args, **kwargs):
            global active_log_handlers
            super(ReconnectingSysLogHandler, self).__init__(*args, **kwargs)
            self._is_retry = False
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
                return

            # Set the retry flag and begin deciding if this is a closed socket, and
            # trying to reconnect.
            self._is_retry = True
            try:
                __, exception, __ = sys.exc_info()
                # If the error is a broken pipe exception (32) or ssl EOF error (8), get a new socket.
                if isinstance(exception, socket.error) and (exception.errno == 32 or exception.errno == 8):
                    try:
                        self._reconnect()
                    except:
                        pass
                    else:
                        # Make an effort to rescue the record..
                        self.emit(record)
                # On any other socket error spool the record for later delivery.
                elif isinstance(exception, socket.error):
                    # FIXME: Here we should spool not transmitted records.
                    pass
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
    client_cert_file=None, client_key_file=None, facility=None, relp=False):
    from otpme.lib import config
    from otpme.lib.multiprocessing import register_cleanup_method
    register_cleanup_method(close_log_handlers)
    #logging.raiseExceptions = True
    if facility is None:
        facility = config.syslog_facility
    facility_id = "LOG_%s" % facility
    try:
        facility = getattr(logging.handlers.SysLogHandler, facility_id)
    except:
        msg = "Unknown facility: %s" % facility
        raise OTPmeException(msg)
    if use_ssl:
        if not ca_cert_file:
            msg = "Need <ca_cert_file> with use_ssl=True."
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
            msg = "Invalid syslog address: %s" % address
            raise OTPmeException(msg)
        if relp:
            log_handler = RelpHandler(address=address,
                                    facility=facility,
                                    context=context,
                                    resend_size=32)
        else:
            reconnecting_handler = get_reconnecting_handler(TLSSysLogHandler)
            log_handler = reconnecting_handler(address=address,
                                        socktype=socket.SOCK_STREAM,
                                        secure=context,
                                        facility=facility)
    else:
        if relp:
            address = address.split(":")
            log_handler = RelpHandler(address=address,
                                    facility=facility,
                                    resend_size=32)
        else:
            if len(address.split(":")) < 2:
                socktype = socket.SOCK_DGRAM
            else:
                socktype = socket.SOCK_STREAM
            reconnecting_handler = get_reconnecting_handler(logging.handlers.SysLogHandler)
            log_handler = reconnecting_handler(address=address,
                                            socktype=socktype,
                                            facility=facility)

    formatter = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
    log_handler.setFormatter(formatter)

    return log_handler
