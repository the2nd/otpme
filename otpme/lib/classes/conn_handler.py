# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import config
#from otpme.lib import multiprocessing
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
        client=None, peer_cert=None, **handler_args):
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
                    msg = "Client closed connection."
                    self.logger.debug(msg)
                break
            except Exception as e:
                msg = "Failed to receive data from client: %s" % e
                self.logger.warning(msg)
                self.connection.close()
                break

            if len(data) == 0:
                msg = ("Received null data from client, closing connection: %s"
                        % self.client)
                self.logger.warning(msg)
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
                    final_response = "%s" % e
                    status = status_codes.SERVER_QUIT
                    break
                except ClientQuit as e:
                    final_response = "%s" % e
                    status = status_codes.CLIENT_QUIT
                    break
                except Exception as e:
                    msg = ("Exception in protocol handler: %s" % e)
                    self.logger.critical(msg, exc_info=True)
                    final_response = "Internal server error"
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
                            msg = ("Failed to decode request with protocol handler: %s: %s"
                                    % (self.proto_handler, e))
                            self.logger.critical(msg, exc_info=True)
                            final_response = "Internal server error"
                            status = status_codes.SERVER_QUIT
                            config.raise_exception()
                            break
                    else:
                        try:
                            command, command_args, binary_data = decode_request(data)
                        except Exception as e:
                            msg = ("Failed to decode request: %s: %s"
                                    % (self.proto_handler, e))
                            self.logger.critical(msg, exc_info=True)
                            final_response = "Internal server error"
                            status = status_codes.SERVER_QUIT
                            config.raise_exception()
                            break
                except OTPmeException as e:
                    raise

                if self.pkg_count == 1 \
                and command != "helo" \
                and command != "quit":
                    final_response = "Polite people say helo :)"
                    status = status_codes.SERVER_QUIT
                    break
                elif command == "helo":
                    # If we got a client helo try to get protocol version
                    try:
                        client_supported_protocols = command_args['supported_protocols']
                    except:
                        final_response = "Client supported protocols missing in request."
                        status = status_codes.SERVER_QUIT
                        break
                    # Try to find best protocol to use.
                    proto = None
                    for x in self.protocols:
                        if x in client_supported_protocols:
                            proto = x
                            break
                    if proto is None:
                        final_response = "Protocol negotiation failed."
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
                                                        **self.handler_args)
                    except Exception as e:
                        msg = ("Failed to load protocol handler: %s: %s"
                                % (proto_class, e))
                        self.logger.critical(msg, exc_info=True)
                        final_response = "Internal server error."
                        status = status_codes.SERVER_QUIT
                        break
                    # Init protocol handler.
                    try:
                        self.proto_handler.init()
                        response = "Welcome, using protocol: %s" % self.protocol
                        status = True
                    except CertVerifyFailed as e:
                        msg = ("Client certificate verification failed: "
                                "%s: %s" % (client_ip, e))
                        self.logger.warning(msg)
                        final_response = "%s" % e
                        status = status_codes.SERVER_QUIT
                        break
                    except Exception as e:
                        msg = ("Unknown exception in protocol handler: %s: %s"
                                % (proto_class, e))
                        self.logger.critical(msg, exc_info=True)
                        final_response = "Internal server error."
                        status = status_codes.SERVER_QUIT
                        #config.raise_exception()
                        break
                    if config.debug_level() > 3:
                        msg = ("Using protocol %s for client: %s"
                                % (self.protocol, client_ip))
                        self.logger.debug(msg)

                elif command == "use_proto":
                    # Get proto the client uses.
                    try:
                        client_proto = command_args['client_proto']
                    except:
                        final_response = "Client protocol missing in request."
                        status = status_codes.SERVER_QUIT
                        break
                    if self.protocol != client_proto:
                        final_response = "Client protocol missmatch."
                        status = status_codes.SERVER_QUIT
                        break
                    use_handler = False
                    self.proto_neg_finished = True
                    status = True
                    response = client_proto
                elif command == "quit":
                    final_response = "Bye bye..."
                    status = status_codes.CLIENT_QUIT
                    break
                elif command == "ping":
                    response = "pong"
                    status = True
                else:
                    response = "%s Unknown command: %s\n" % (status_codes.ERR, command)
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
                msg = "Client closed connection while sending data."
                self.logger.debug(msg)
                break
            except Exception as e:
                msg = "Failed to send response: %s" % e
                self.logger.warning(msg)
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
                msg = "Client closed connection while sending final response."
                self.logger.debug(msg)
            except Exception as e:
                msg = "Failed to send final response: %s" % e
                self.logger.warning(msg)

        # Close connection.
        self.connection.close()
        # FIXME: do we stil need this here? It closes mqueues which results in malfunction of e.g. otpme-agent.
        #multiprocessing.cleanup()

    def cleanup(self):
        """ Is called on client disconnect. """
        if not self.proto_handler:
            return
        self.proto_handler.close()
        self.proto_handler.cleanup()
