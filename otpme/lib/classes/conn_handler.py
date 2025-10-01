# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.protocols.request import decode_request
from otpme.lib.protocols.response import build_response

from otpme.lib.exceptions import *

class ConnHandler(object):
    """
    Class to handle connections and
    start the needed protocol handlers.
    """
    def __init__(self, protocols, connection=None,
        client=None, peer_cert=None, logger=None,
        **handler_args):
        self.connection = connection
        self.client = client
        self.peer_cert = peer_cert
        self.pkg_count = 0
        self.protocol = None
        self.proto_handler = None
        self.protocols = protocols
        self.proto_neg_finished = False
        # Arguments we will pass on to protocol handler
        self.handler_args = handler_args
        if logger:
            self.logger = logger
        else:
            self.logger = config.logger

    def run(self):
        """ Run handler loop. """
        final_response = None
        while True:
            # Count packets for this connection
            self.pkg_count += 1
            # Receive data from peer.
            try:
                data = self.connection.recv(timeout=None)
                #data = self.connection.recv()
            except ConnectionTimeout:
                continue
            except ConnectionQuit:
                self.connection._close()
                if config.debug_level() > 3:
                    log_msg = _("Client closed connection.", log=True)[1]
                    self.logger.debug(log_msg)
                break
            except Exception as e:
                log_msg = _("Failed to receive data from client: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                self.connection.close()
                break

            if len(data) == 0:
                log_msg = _("Received null data from client, closing connection: {client}", log=True)[1]
                log_msg = log_msg.format(client=self.client)
                self.logger.warning(log_msg)
                break

            # If we already have a protocol handler use it
            response = None
            use_handler = True
            final_response = None
            handler_response = None
            if self.proto_handler and self.proto_neg_finished:
                try:
                    handler_response = self.proto_handler.process(data)
                    status = True
                except ServerQuit as e:
                    final_response = f"{e}"
                    status = status_codes.SERVER_QUIT
                    break
                except ClientQuit as e:
                    final_response = f"{e}"
                    status = status_codes.CLIENT_QUIT
                    break
                except Exception as e:
                    log_msg = _("Exception in protocol handler: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg, exc_info=True)
                    final_response = _("Internal server error")
                    status = status_codes.SERVER_QUIT
                    config.raise_exception()
                    break
            else:
                # Get command from request.
                try:
                    if self.proto_handler and self.proto_neg_finished:
                        try:
                            command, \
                            command_args, \
                            binary_data = self.proto_handler.decode_request(data)
                        except Exception as e:
                            log_msg = _("Failed to decode request with protocol handler: {proto_handler}: {error}", log=True)[1]
                            log_msg = log_msg.format(proto_handler=self.proto_handler, error=e)
                            self.logger.critical(log_msg, exc_info=True)
                            final_response = _("Internal server error")
                            status = status_codes.SERVER_QUIT
                            config.raise_exception()
                            break
                    else:
                        try:
                            command, command_args, binary_data = decode_request(data)
                        except Exception as e:
                            log_msg = _("Failed to decode request: {proto_handler}: {error}", log=True)[1]
                            log_msg = log_msg.format(proto_handler=self.proto_handler, error=e)
                            self.logger.critical(log_msg, exc_info=True)
                            final_response = _("Internal server error")
                            status = status_codes.SERVER_QUIT
                            config.raise_exception()
                            break
                except OTPmeException as e:
                    raise

                if self.pkg_count == 1 \
                and command != "helo" \
                and command != "quit":
                    final_response = _("Polite people say helo :)")
                    status = status_codes.SERVER_QUIT
                    break
                elif command == "helo":
                    # If we got a client helo try to get protocol version
                    try:
                        client_supported_protocols = command_args['supported_protocols']
                    except:
                        final_response = _("Client supported protocols missing in request.")
                        status = status_codes.SERVER_QUIT
                        break
                    # Try to find best protocol to use.
                    proto = None
                    for x in self.protocols:
                        if x in client_supported_protocols:
                            proto = x
                            break
                    if proto is None:
                        final_response = _("Protocol negotiation failed.")
                        status = status_codes.SERVER_QUIT
                        break
                    self.protocol = proto
                    client_ip = self.client.split(":")[0]
                    from otpme.lib import protocols
                    proto_class = protocols.server.get_class(self.protocol)
                    # Load protocol handler.
                    try:
                        self.proto_handler = proto_class(client=self.client,
                                                        peer_cert=self.peer_cert,
                                                        connection=self.connection,
                                                        logger=self.logger,
                                                        **self.handler_args)
                    except Exception as e:
                        log_msg = _("Failed to load protocol handler: {proto_class}: {error}", log=True)[1]
                        log_msg = log_msg.format(proto_class=proto_class, error=e)
                        self.logger.critical(log_msg, exc_info=True)
                        final_response = _("Internal server error.")
                        status = status_codes.SERVER_QUIT
                        break
                    # Init protocol handler.
                    try:
                        self.proto_handler.init()
                        response = "Welcome, using protocol: {protocol}"
                        response = response.format(protocol=self.protocol)
                        status = True
                    except CertVerifyFailed as e:
                        log_msg = _("Client certificate verification failed: {client_ip}: {error}", log=True)[1]
                        log_msg = log_msg.format(client_ip=client_ip, error=e)
                        self.logger.warning(log_msg)
                        final_response = f"{e}"
                        status = status_codes.SERVER_QUIT
                        break
                    except Exception as e:
                        log_msg = _("Unknown exception in protocol handler: {proto_class}: {error}", log=True)[1]
                        log_msg = log_msg.format(proto_class=proto_class, error=e)
                        self.logger.critical(log_msg, exc_info=True)
                        final_response = _("Internal server error.")
                        status = status_codes.SERVER_QUIT
                        #config.raise_exception()
                        break
                    if config.debug_level() > 3:
                        log_msg = _("Using protocol {protocol} for client: {client_ip}", log=True)[1]
                        log_msg = log_msg.format(protocol=self.protocol, client_ip=client_ip)
                        self.logger.debug(log_msg)

                elif command == "use_proto":
                    # Get proto the client uses.
                    try:
                        client_proto = command_args['client_proto']
                    except:
                        final_response = _("Client protocol missing in request.")
                        status = status_codes.SERVER_QUIT
                        break
                    if self.protocol != client_proto:
                        final_response = _("Client protocol missmatch.")
                        status = status_codes.SERVER_QUIT
                        break
                    use_handler = False
                    self.proto_neg_finished = True
                    status = True
                    response = client_proto
                elif command == "quit":
                    final_response = _("Bye bye...")
                    status = status_codes.CLIENT_QUIT
                    break
                elif command == "ping":
                    response = "pong"
                    status = True
                else:
                    response = _("{error_code} Unknown command: {command}\n")
                    response = response.format(error_code=status_codes.ERR, command=command)
                    status = False
            # Set response.
            if handler_response is not None:
                response = handler_response
            else:
                if self.proto_handler and self.proto_neg_finished and use_handler:
                    response = self.proto_handler.build_response(status, response)
                else:
                    response = build_response(status, response)
            # Send response to peer.
            try:
                self.connection.send(response, timeout=config.connection_timeout)
            except ConnectionQuit:
                self.connection._close()
                log_msg = _("Client closed connection while sending data.", log=True)[1]
                self.logger.debug(log_msg)
                break
            except Exception as e:
                log_msg = _("Failed to send response: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                break

        # Send final response to peer.
        if final_response is not None:
            if self.proto_handler:
                final_response = self.proto_handler.build_response(status, final_response)
            else:
                final_response = build_response(status, final_response)
            try:
                self.connection.send(final_response)
            except ConnectionQuit:
                self.connection._close()
                log_msg = _("Client closed connection while sending final response.", log=True)[1]
                self.logger.debug(log_msg)
            except Exception as e:
                log_msg = _("Failed to send final response: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

        # Close connection.
        self.connection.close()
        # Mulitprocessing cleanup.
        multiprocessing.cleanup(keep_queues=True)

    def cleanup(self):
        """ Is called on client disconnect. """
        if not self.proto_handler:
            return
        self.proto_handler.close()
        self.proto_handler.cleanup()
