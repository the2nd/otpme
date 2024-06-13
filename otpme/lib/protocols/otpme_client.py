# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# FIXME: We should use re2 anywhere but currently it seems like re2 is not
#        compatible to re in every case. The code below demonstrates one issue.
#        import re2 as re
#        string = "para1: val1\0val2"
#        vals = re.sub('^para1: ([^ ]*).*', r'\1', string)
#        print(vals)
#        import re
#        string = "para1: val1\0val2"
#        vals = re.sub('^para1: ([^ ]*).*', r'\1', string)
#        print(vals)
import re
import os
import sys
import time
import pprint
import select
import signal
import hashlib
import inspect

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import cli
from otpme.lib import oid
from otpme.lib import ssh
from otpme.lib import sotp
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import otpme_pass
from otpme.lib import connections
from otpme.lib import jwt as _jwt
from otpme.lib import multiprocessing
from otpme.lib.pki.cert import SSLCert
from otpme.lib.messages import message
from otpme.lib.encryption.ec import ECKey
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.messages import error_message
from otpme.lib.protocols import status_codes
from otpme.lib.register import register_module
from otpme.lib.socket.connect import ConnectSocket
from otpme.lib.protocols.request import build_request
from otpme.lib.socket.handler import SocketProtoHandler
from otpme.lib.protocols.response import decode_response

from otpme.lib.exceptions import *

DEBUG_SLOT = "client"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.encryption.fernet",
                "otpme.lib.encryption.hkdf",
                "otpme.lib.encryption.ec",
                "otpme.lib.encoding.base",
                #"otpme.lib.compression.base",
                "otpme.lib.offline_token",
                "otpme.lib.connections",
                "otpme.lib.sotp",
                ]

def register():
    register_config()
    register_module("otpme.lib.smartcard")

def register_config():
    """ Register config stuff. """
    # Do not show login prompt if user is not logged in?
    config.register_config_var("no_auth", bool, False)
    # RSP len. We use 65 because the initial RSP generated via DH key exchange is
    # of length 65.
    config.register_config_var("rsp_len", int, 65)
    config.register_config_var("client_protocol", str, None)

class OTPmeClientBase(object):
    """ Class that implements OTPme client base methods. """
    def __init__(self, daemon, socket_uri=None, endpoint=True,
        auth_type=None, interactive=False, print_messages=None,
        handle_response=None, message_method=None,
        error_message_method=None, use_agent=False,
        site_cert=None, compress_request=True, **kwargs):

        # Make sure we got connect infos.
        if not daemon and not socket_uri:
            msg = (_("Need at least one of 'daemon' or 'socket_uri'!"))
            raise OTPmeException(msg)

        if daemon is not None:
            daemon_proto = "%s1" % daemon[:-1]
            client_proto_module = "otpme.lib.protocols.client.%s" % daemon_proto
            try:
                register_module(client_proto_module)
            except Exception as e:
                msg = ("Failed to register client protocol: %s: %s"
                    % (daemon_proto, e))
            if config.use_api:
                daemon_proto = "%s1" % daemon[:-1]
                server_proto_module = "otpme.lib.protocols.server.%s" % daemon_proto
                try:
                    register_module(server_proto_module)
                except Exception as e:
                    msg = ("Failed to register server protocol: %s: %s"
                        % (daemon_proto, e))

        # Set daemon we will connect to.
        self.daemon = daemon
        # Socket we will connect to.
        self.socket_uri = socket_uri
        self.endpoint = endpoint
        # Auth type to send to server.
        self.auth_type = auth_type
        # Get logger.
        self.logger = config.logger
        # Indicates if we should handle user questions.
        self.interactive = interactive
        # Indicates if we should proxy commands through a running otpme-agent
        # that handles auth stuff etc.
        self.use_agent = use_agent
        # Will hold certificate of site we connect to.
        self.site_cert = site_cert
        # Will hold the session secret generated via DH.
        self.session_key = None
        # Compress request?
        self.compress_request = compress_request
        # Methods to send user messages (e.g. via PAM)
        self.message_method = message_method
        self.error_message_method = error_message_method
        # Set default message methods.
        if self.message_method is None:
            self.message_method = message
        if self.error_message_method is None:
            self.error_message_method = error_message

        if handle_response is None:
            self.handle_response = self.interactive
        else:
            self.handle_response = handle_response

        # Indicates if we should print out messages received from peer.
        if print_messages is None:
            # If print_messages as not explicitly set enable it when interactive
            # mode is requested.
            self.print_messages = self.interactive
        else:
            self.print_messages = print_messages
        self.combined_responses = []

    def print_response(self, command_dict, ignore_escape_chars=False):
        """ Print response message to users terminal. """
        # Get job message.
        try:
            message = command_dict['message']
        except:
            return

        if message is None:
            return

        # Decode messages.
        msg_err = False
        msg_type = message[0]
        if msg_type is False:
            msg_err = True
        msg = message[1]
        if self.print_messages:
            #if msg is None or isinstance(msg, bool):
            #    return
            if len(str(msg)) == 0:
                self.logger.warning("Received null length message.")
                return
            if ignore_escape_chars:
                sys.stdout.write(msg)
            else:
                self.print_msg(msg, error=msg_err)
        else:
            self.combined_responses.append(msg)

    def print_msg(self, msg, error=False):
        """ Print message to console. """
        if error:
            self.error_message_method(msg)
        else:
            self.message_method(msg)

class OTPmeClient(OTPmeClientBase):
    """ Class that implements OTPme client. """
    def __init__(self, daemon, use_ssl=True, verify_server=True,
        connect_timeout=None, timeout=None, client=None, username=None,
        autoconnect=True, auto_auth=True, auto_preauth=False, do_preauth=None,
        use_dns=False, local_socket=False, site_ident=False,
        site_ident_digest="sha256", trust_site_cert=False,
        trust_site_cert_fp=None, encrypt_session=True,
        quiet_autoconnect=False, realm=None, site=None, **kwargs):
        # Init parent class.
        super(OTPmeClient, self).__init__(daemon, **kwargs)

        # Set signal handler.
        if self.interactive:
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)

        # Set args to be passed on to protocol handler.
        self.proto_handler_args = dict(kwargs)

        if self.use_agent:
            if do_preauth is True:
                msg = "do_preauth=True conflicts with use_agent=True"
                raise OTPmeException(msg)
            if auto_auth is True:
                msg = "auto_auth=True conflicts with use_agent=True"
                raise OTPmeException(msg)
            if auto_preauth is True:
                msg = "auto_preauth=True conflicts with use_agent=True"
                raise OTPmeException(msg)
        else:
            if do_preauth is None:
                do_preauth = True
            self.proto_handler_args['do_preauth'] = do_preauth

        if not local_socket:
            # Set default realm and site if needed.
            if not realm:
                realm = config.connect_realm
            if not site:
                site = config.connect_site

            if site and not realm:
                realm = config.realm

            if site and not realm:
                msg = (_("Need <realm> when <site> is given."))
                raise OTPmeException(msg)

        # realm/site we connect to.
        self.realm = realm
        self.site = site
        # Use DNS to get site address?
        self.use_dns = use_dns
        # Indicates that we should use SSL.
        self.use_ssl = use_ssl
        # Will hold cert of daemon we will connect to.
        self.peer_cert = None
        # Will hold peer cert CN.
        self.peer_cn = None
        # Indicates that we should verify server certificate.
        self.verify_server = verify_server
        # Indicates that we should autoconnect to our peer.
        self.autoconnect = autoconnect
        # Ask user to identify site by cert fingerprint.
        self.site_ident = site_ident
        self.site_ident_digest = site_ident_digest
        self.trust_site_cert = trust_site_cert
        self.trust_site_cert_fp = trust_site_cert_fp
        # Indicates if we should start authentication with daemon on connect.
        self.auto_auth = auto_auth
        # Indicates if we should do preauth check with daemon on connect.
        self.auto_preauth = auto_preauth
        # The protocol this connection uses.
        self.protocol = None
        self.proto_handler = None
        # Agent protocol and handler to use.
        self.agent_protocol = None
        self.agent_proto_handler = None
        # Indicates if we need a session secret to encrypt communication.
        self.encrypt_session = encrypt_session
        # The user we will authenticate as.
        self.username = username
        # The client that sends this request.
        self.client = client
        self.stop_job = False

        # Will hold our current job ID.
        self.jobs = {}
        # Set status.
        self.connected = False

        # Connect timeout.
        self.connect_timeout = connect_timeout
        #if connect_timeout is None:
        #    self.connect_timeout = config.connect_timeout
        # Connection timeout.
        self.timeout = timeout
        #if timeout is None:
        #    self.timeout = config.connection_timeout

        # There are no real connections in API mode.
        if config.use_api:
            self.use_agent = False

        if self.use_agent:
            self.use_ssl = False
            login_status = self.get_login_status()
            if not login_status:
                if self.use_agent is True:
                    self.cleanup()
                    raise OTPmeException(_("Not logged in."))
                else:
                    self.use_agent = False

        # Get connection.
        if config.use_api and self.daemon:
            from otpme.lib import protocols
            # Get default daemon protocol.
            try:
                daemon_protocol = config.get_otpme_protocols(self.daemon)[0]
            except:
                msg = "Unknown protocol for daemon: %s" % self.daemon
                raise OTPmeException(msg)
            proto_class = protocols.server.get_class(daemon_protocol)
            self.connection = proto_class()
        else:
            cert = None
            key = None
            ca_data = None
            if self.use_ssl:
                # Try to get SSL stuff of our host.
                try:
                    cert = config.host_data['cert']
                except:
                    pass
                try:
                    key = config.host_data['key']
                except:
                    pass
                try:
                    ca_data = config.host_data['ca_data']
                except:
                    if self.verify_server:
                        raise OTPmeException(_("Host CA data missing."))

            # Create connect socket.
            self.connection = ConnectSocket(socket_uri=self.socket_uri,
                                            socket_handler=SocketProtoHandler,
                                            use_ssl=self.use_ssl,
                                            cert=cert,
                                            key=key,
                                            ca_data=ca_data,
                                            verify_server=self.verify_server)
        # Handle autoconnect.
        if self.autoconnect:
            try:
                self.connect(quiet=quiet_autoconnect)
            except:
                self.close()
                self.cleanup()
                raise

    def __getattr__(self, name):
        """ Map to protocol handler attributes. """
        try:
            method = self.__getattribute__(name)
            return method
        except:
            pass
        if self.proto_handler is None:
            return
        method = getattr(self.proto_handler, name)
        return method

    def __str__(self):
        if config.use_api:
            name = "API"
        else:
            name = self.socket_uri
        if self.protocol:
            name = "%s: %s" % (name, self.protocol)
        return name

    def signal_handler(self, _signal, frame):
        """ Handle signals. """
        if _signal == 2:
            self.logger.warning("Exiting on Ctrl+C")
        if _signal == 15:
            self.logger.warning("Exiting on 'SIGTERM'.")
        self.stop_job = True
        if self.jobs:
            return
        self.close()
        self.cleanup()
        os._exit(0)

    @property
    def job(self):
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)
        caller_id = calframe[1][0]
        try:
            job_dict = self.jobs[caller_id]
        except KeyError:
            job_dict = None
        return job_dict

    @job.setter
    def job(self, job_dict):
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)
        caller_id = calframe[1][0]
        if job_dict is None:
            try:
                self.jobs.pop(caller_id)
            except KeyError:
                pass
            return
        self.jobs[caller_id] = job_dict

    def set_proto_handler(self):
        """ Set protocol handler. """
        # Try to get protocol class.
        from otpme.lib import protocols
        try:
            proto_class = protocols.client.get_class(self.protocol)
        except Exception as e:
            msg = "Failed to load protocol: %s: %s" % (self.protocol, e)
            self.logger.critical(msg)
            raise OTPmeException(msg)
        # Try to init protocol.
        try:
            self.proto_handler = proto_class(connection=self,
                                            username=self.username,
                                            client=self.client,
                                            **self.proto_handler_args)
        except Exception as e:
            msg = "Failed to init protocol: %s: %s" % (self.protocol, e)
            self.logger.critical(msg)
            raise OTPmeException(msg)

    @property
    def supported_protocols(self):
        """ Protocols we support. """
        if not self.daemon:
            msg = "Unable to get supported protocols without daemon we connect to."
            raise OTPmeException(msg)
        # Protocols we support.
        supported_protocols = config.get_otpme_protocols(self.daemon)
        return supported_protocols

    def get_login_status(self):
        """ Get login status of user. """
        try:
            agent_conn = connections.get("agent",
                            user=self.otpme_agent_user)
            login_status = agent_conn.get_status()
        except Exception as e:
            login_status = False
        return login_status

    def connect(self, connect_timeout=None, timeout=None,
        auto_auth=None, auto_preauth=None, quiet=False):
        """ Connect to daemon and do protocol negotiation. """
        if not self.supported_protocols:
            msg = ("Unable to connect: %s: Missing client supported protocols."
                    % self.socket_uri)
            raise OTPmeException(msg)
        # In API mode we have no connection.
        if config.use_api:
            # Set status.
            self.connected = True
            # Set protocol version from fake API connection.
            self.protocol = self.connection.protocol
            config.client_protocol = self.protocol
            self.set_proto_handler()
            return True

        # Set timeouts.
        if connect_timeout is None:
            connect_timeout = self.connect_timeout
        if timeout is None:
            timeout = self.timeout

        if auto_auth is None:
            auto_auth = self.auto_auth

        if auto_preauth is None:
            auto_preauth = self.auto_preauth

        # Connect to peer.
        try:
            self.connection.connect(connect_timeout=connect_timeout,
                                        timeout=timeout,
                                        quiet=quiet)
        except Exception as e:
            msg = (_("Daemon connection failed: %s: %s") % (self.socket_uri, e))
            if not config.file_logging and not config.debug_enabled:
                msg = "%s Try '-dd' for debug output." % msg
            raise ConnectionError(msg)

        # Get cert info of peer.
        if self.use_ssl:
            self.peer_cert = self.connection.peer_cert

        # Get get peer cert CN.
        if self.peer_cert:
            for i in self.peer_cert['subject']:
                if i[0][0] == 'commonName':
                    self.peer_cn = i[0][1]
                    break

        # Start protocol negotiation.
        helo_command = "helo"
        if self.use_agent:
            # Agent protocols we support.
            agent_protos = config.get_otpme_protocols("agent")
            helo_args = {'supported_protocols' : agent_protos}
        else:
            helo_args = {'supported_protocols' : self.supported_protocols}

        # Send helo command.
        try:
            status, \
            status_code, \
            response = self.send(command=helo_command,
                            command_args=helo_args,
                            encrypt_request=False,
                            encode_request=True,
                            handle_response=False,
                            handle_auth=False,
                            use_agent=False,
                            timeout=timeout)
        except Exception as e:
            msg = (_("Error sending 'helo': %s") % e)
            self.cleanup()
            config.raise_exception()
            raise ConnectionError(msg)

        if status_code != status_codes.OK:
            msg = (_("Peer does not like our helo: %s") % response)
            self.cleanup()
            raise OTPmeException(msg)

        if not response:
            msg = "Got no helo response."
            self.cleanup()
            raise OTPmeException(msg)

        if not response.startswith("Welcome,"):
            msg = (_("Error while protocol negotiation: %s") % response)
            self.logger.warning(msg)
            self.cleanup()
            raise OTPmeException(msg)

        # Send auth command to otpme-agent.
        if self.use_agent:
            try:
                login_session_id = os.environ['OTPME_LOGIN_SESSION']
            except KeyError:
                login_session_id = None

            if login_session_id:
                command_args = {
                                'login_session_id'  : login_session_id,
                            }
                auth_status, \
                auth_status_code, \
                auth_response = self.send(command="auth",
                                command_args=command_args,
                                encrypt_request=False,
                                encode_request=True,
                                handle_response=False,
                                handle_auth=False,
                                use_agent=False,
                                timeout=timeout)

                if auth_status_code != status_codes.OK:
                    self.cleanup()
                    msg = (_("Authentication with otpme-agent failed: %s" % auth_response))
                    raise OTPmeException(msg)

        # Get server protocol via agent from peer.
        if self.use_agent:
            exception = None
            # Set agent protocol we negotiated.
            self.agent_protocol = response.split(":")[1].replace(" ", "")
            if config.debug_level(DEBUG_SLOT) > 3:
                msg = ("Agent supports protocol version: %s" % self.agent_protocol)
                self.logger.debug(msg)
            # Try to get agent protocol class.
            from otpme.lib import protocols
            try:
                proto_class = protocols.client.get_class(self.agent_protocol)
            except Exception as e:
                msg = ("Failed to load agent protocol: %s: %s"
                        % (self.agent_protocol, e))
                self.logger.critical(msg)
                raise OTPmeException(msg)
            # Try to init protocol.
            try:
                self.agent_proto_handler = proto_class()
            except Exception as e:
                msg = ("Failed to init agent protocol: %s: %s"
                        % (self.protocol, e))
                self.logger.critical(msg)
                raise OTPmeException(msg)
            # Get server protocol via agent.
            try:
                status, \
                status_code, \
                response = self.send('get_proto',
                                use_agent=True,
                                handle_response=False,
                                encode_request=True,
                                encrypt_request=False,
                                handle_auth=False,
                                timeout=timeout)
            except Exception as e:
                msg = (_("Error while protocol negotiation via agent: %s") % e)
                self.logger.warning(msg)
                self.cleanup()
                raise ConnectionError(msg)

            if status_code == status_codes.NEED_USER_AUTH:
                exception = AuthFailed
            elif status_code == status_codes.NEED_HOST_AUTH:
                exception = AuthFailed
            elif status_code != status_codes.OK:
                exception = Exception

            if exception:
                msg = (_("Failed to connect via agent: %s") % response)
                raise exception(msg)

        if self.site_ident:
            self.ident_site()

        # Set server protocol we negotiated.
        self.protocol = response.split(":")[1].replace(" ", "")
        config.client_protocol = self.protocol
        if config.debug_level(DEBUG_SLOT) > 3:
            msg = ("Server supports protocol version: %s" % self.protocol)
            self.logger.debug(msg)
        self.set_proto_handler()

        if auto_auth:
            self.authenticate()
        elif auto_preauth:
            self.preauth_check()

        # Set status.
        self.connected = True

        return True

    def ident_site(self, digest=None):
        """ Identify site cert by fingerprint. """
        if not self.interactive:
            msg = "Cannot use <ident_site> with <interactive=False>."
            raise OTPmeException(msg)
        if digest is None:
            digest = self.site_ident_digest
        try:
            self.site_cert = self.request_site_cert()
        except Exception as e:
            msg = "Failed to request site cert: %s" % e
            raise ConnectionError(msg)
        self.proto_handler_args['site_cert'] = self.site_cert
        site_fingerprint = self.site_cert.fingerprint(digest)
        if self.trust_site_cert:
            msg = ("Accepted site certificate fingerprint: %s"
                    % site_fingerprint)
            if config.debug_level(DEBUG_SLOT) > 0:
                self.logger.debug(msg)
            return
        if self.trust_site_cert_fp:
            if site_fingerprint == self.trust_site_cert_fp:
                msg = ("Accepted site certificate fingerprint: %s"
                        % site_fingerprint)
                if config.debug_level(DEBUG_SLOT) > 0:
                    self.logger.debug(msg)
                return
            msg = ("Rececived wrong site certificate fingerprint: %s"
                    % site_fingerprint)
            raise OTPmeException(msg)
        msg = (_("Trust the following site certificate? %s:%s [y/n] ")
                % (digest, site_fingerprint))
        paras = { 'prompt':msg, 'input_prefill':None }
        answer = self.ask(paras)
        if answer.lower() != "y":
            msg = "Aborted by user."
            raise OTPmeException(msg)

    def request_site_cert(self):
        """ Request site cert from peer. """
        ident_challenge = stuff.gen_secret(len=32)
        command = "ident"
        command_args = {'ident_challenge':ident_challenge}
        try:
            status, \
            status_code, \
            response = self.send(command=command,
                            command_args=command_args,
                            encrypt_request=False,
                            handle_response=False,
                            handle_auth=False)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error sending ident command: %s") % e)
            raise ConnectionError(msg)
        if not status:
            msg = "Ident request failed: %s" % response
            raise OTPmeException(msg)
        try:
            _site_cert = response['site_cert']
        except:
            msg = "Invalid ident response: No site cert found"
            raise OTPmeException(msg)
        try:
            ident_response = response['ident_response']
        except:
            msg = "Invalid ident response: No response found"
            raise OTPmeException(msg)
        _site_cert = SSLCert(cert=_site_cert)
        try:
            response_status = _site_cert.verify(data=ident_challenge,
                                        signature=ident_response,
                                        encoding="base64")
        except Exception as e:
            msg = "Error verifying ident response: %s" % e
            self.logger.critical(msg)
            response_status = False
        if not response_status:
            msg = "Failed to verify ident response."
            raise OTPmeException(msg)
        return _site_cert

    def send(self, command, command_args={}, handle_auth=True,
        handle_response=None, blocking=None, timeout=None, **kwargs):
        """ Send command requests to daemon and handle response. """
        if self.proto_handler:
            if self.proto_handler.redirect_connection:
                return self.proto_handler.redirect_connection.send(command=command,
                                                                command_args=command_args,
                                                                handle_auth=handle_auth,
                                                                handle_response=handle_response,
                                                                blocking=blocking,
                                                                timeout=timeout,
                                                                **kwargs)
        if handle_response is None:
            handle_response = self.handle_response
        # Send command.
        status_code, response = self._send(command=command,
                                        command_args=command_args,
                                        blocking=blocking,
                                        timeout=timeout,
                                        **kwargs)

        if handle_auth and self.auto_auth:
            if status_code == status_codes.NEED_USER_AUTH \
            or status_code == status_codes.NEED_HOST_AUTH:
                self.authenticate()
                # Resend command.
                status_code, \
                response = self._send(command=command,
                                command_args=command_args,
                                blocking=blocking,
                                timeout=timeout,
                                **kwargs)
        # Handle response.
        if handle_response:
            status_code, \
            response = self._handle_response(command=command,
                                command_args=command_args,
                                response=response,
                                status_code=status_code,
                                blocking=blocking,
                                timeout=timeout)

        # At this point a probably job has finished.
        self.job = None

        # Connection redirects are handled by otpme-agent.
        if status_code == status_codes.CONNECTION_REDIRECT:
            raise ConnectionRedirect(response)

        # Handle status code.
        if status_code == status_codes.OK:
            status = True
        elif status_code == status_codes.ABORT:
            status = None
        else:
            status = False

        return status, status_code, response

    def _send(self, command, command_args={}, use_agent=None,
        encode_request=True, encrypt_request=None, blocking=None, timeout=None):
        """ Convert command args and actually send command to daemon. """
        if self.proto_handler:
            if self.proto_handler.redirect_connection:
                return self.proto_handler.redirect_connection._send(command=command,
                                                                command_args=command_args,
                                                                use_agent=use_agent,
                                                                encode_request=encode_request,
                                                                encrypt_request=encrypt_request,
                                                                blocking=blocking,
                                                                timeout=timeout,
                                                                **kwargs)
        enc_key = None
        enc_mod = None
        if use_agent is None:
            use_agent = self.use_agent

        # Check if we have to encrypt the request.
        if encrypt_request is None:
            if self.encrypt_session:
                encrypt_request = True

        # No need to encrypt in API mode.
        if config.use_api:
            encrypt_request = False

        # Allow unencrypted ping command.
        if command == "ping":
            encrypt_request = False

        # Set encryption type and key used for en- and decryption.
        if self.session_key:
            enc_mod = self.session_enc_mod
            enc_key = self.session_key

        # Build proxy request when using otpme-agent.
        if use_agent:
            if not self.agent_proto_handler:
                msg = "Missing agent protocol handler."
                raise OTPmeException(msg)
            if self.job:
                realm = self.job['realm']
                site = self.job['site']
            else:
                realm = self.realm
                site = self.site
            # Build agent proxy request.
            request = self.agent_proto_handler.build_request(self.daemon,
                                        command, command_args=command_args,
                                        realm=realm, site=site,
                                        encode_request=encode_request,
                                        encrypt_request=encrypt_request,
                                        use_dns=config.use_dns)
        else:
            # Build request.
            if encode_request:
                if encrypt_request:
                    if self.session_key is None:
                        msg = (_("Cannot encrypt request without session key."))
                        raise OTPmeException(msg)
                try:
                    request = build_request(command=command,
                                            command_args=command_args,
                                            encryption=enc_mod,
                                            enc_key=enc_key,
                                            compress=self.compress_request)
                except Exception as e:
                    msg = (_("Faild to build request: %s") % e)
                    raise OTPmeException(msg)
            else:
                if encrypt_request:
                    msg = (_("Need <encode_request=True> with <encrypt_request>."))
                    raise OTPmeException(msg)
                if command_args:
                    msg = (_("Cannot send unencoded request with "
                            "<command_args>."))
                    raise OTPmeException(msg)
                request = command

        #if config.debug_enabled:
        #    if not encrypt_request:
        #        print("SENDING_UNENCRYPTED", request)

        response = None
        # Set default timeout.
        if timeout is None:
            timeout = self.timeout
        # Send request.
        try:
            self.connection.send(request, blocking=blocking, timeout=timeout)
        except Exception as e:
            config.raise_exception()
            raise ConnectionError(_("Error while sending: %s") % e)

        # Receive response.
        try:
            response = self.connection.recv(blocking=blocking, timeout=timeout)
        except Exception as e:
            config.raise_exception()
            raise ConnectionError(_("Error while receiving: %s") % e)

        # Decode response.
        status_code, response = decode_response(response,
                                        encryption=enc_mod,
                                        enc_key=enc_key)
        if status_code == status_codes.SERVER_QUIT:
            self.connected = False
            msg = "Connection closed by server: %s" % response
            raise ConnectionError(msg)

        return status_code, response

    def ask(self, command_dict):
        """ Ask user for some input. """
        # Get prompt.
        prompt = command_dict['prompt']
        input_prefill = command_dict['input_prefill']

        if not self.interactive:
            raise OTPmeException("User interaction required.")

        try:
            response = cli.user_input(prompt=prompt,
                                    prefill=input_prefill)
        except Exception as e:
            raise OTPmeException(_("Error reading user input: %s") % e)

        return response

    def askpass(self, command_dict, null_ok=False):
        """ Ask user for password, PIN, OTP, etc. """
        pass_prompt = command_dict['prompt']
        # Try to get password from user.
        try:
            password = self.get_password(pass_prompt, null_ok=null_ok)
        except Exception:
            password = None

        return password

    def passauth(self, command_dict):
        """ Ask user to authenticate with password/OTP. """
        pass_len = command_dict['pass_len']
        pass_prompt = command_dict['prompt']

        if pass_len:
            pass_len = int(pass_len)

        if not self.password:
            # Try to get password from user.
            try:
                self.password = self.get_password(pass_prompt)
            except Exception as e:
                raise AuthFailed(str(e))

        # Check if we got an OTP len via ASKPASS and cut out a local
        # password (e.g. passphrase for yubikey/ssh key) if needed.
        # The local password MUST always be at the beginning of the
        # string!
        if isinstance(pass_len, int) and pass_len > 0:
            response = self.password[-pass_len:]
        else:
            response = self.password

        return response

    def sshauth(self, command_dict):
        """ Handle SSH authentication. """
        challenge = command_dict['challenge']
        otp_len = int(challenge.split(":")[1])

        if not self.use_ssh_agent:
            raise OTPmeException(_("SSH authentication requested but ssh-agent "
                                "usage disabled."))

        # Try to get password from user.
        if not self.password and self.need_ssh_key_pass:
            try:
                self.password = self.get_password("Password: ")
            except Exception as e:
                raise AuthFailed(_("Unable to get SSH key passphrase: %s") % e)

        # If we should use a running ssh-agent, got its PID and a password set
        # the key passphrase.
        if self.ssh_agent_pid and self.password:
            # Check if SSH token needs a OTP (second factor token enabled)
            if otp_len > 0:
                ssh_key_pass = self.password[:-otp_len]
            else:
                ssh_key_pass = self.password

            if config.debug_level(DEBUG_SLOT) > 3:
                self.logger.debug("Adding SSH key passphrase to agent...")
            # Add SSH key pass to agent.
            try:
                self.agent_conn.add_ssh_key_pass(ssh_agent_pid=self.ssh_agent_pid,
                                                ssh_key_pass=ssh_key_pass)
            except Exception as e:
                msg = (_("Error adding SSH key passphrase to agent: %s") % e)
                raise OTPmeException(msg)

        if config.debug_level(DEBUG_SLOT) > 3:
            self.logger.debug("Signing SSH challenge...")
        # Try to sign challenge with via running SSH agent.
        try:
            response = ssh.sign_challenge(challenge=challenge)
        except Exception as e:
            raise AuthFailed(_("Error signing SSH challenge: %s") % e)

        return response, challenge

    def get_jwt(self, command_dict):
        """ Get JWT from authd (e.g. authonaction policy). """
        from otpme.lib.classes.command_handler import CommandHandler
        username = command_dict['username']
        reason = command_dict['reason']
        challenge = command_dict['challenge']
        command_handler = CommandHandler()
        try:
            jwt = command_handler.get_jwt(username, challenge, reason)
        except Exception as e:
            msg = "JWT authentication failed: %s" % e
            self.logger.warning(msg)
            return
        return jwt

    def scauth(self, command_dict):
        """ Handle smartcard authentication. """
        # Get smartcard data.
        smartcard_type = command_dict['smartcard_type']
        smartcard_data = command_dict['smartcard_data']
        pass_required = smartcard_data['pass_required']

        # Get password from user.
        if pass_required:
            if not self.password:
                try:
                    self.password = self.get_password("Password: ")
                except Exception as e:
                    raise AuthFailed(str(e))

        # If we have no smartcard and not yet tried to detect
        # one do it now.
        if self.use_smartcard and self.smartcard is None:
            try:
                self.detect_smartcard(sc_types=[smartcard_type])
            except Exception as e:
                msg = (_("Error detecting smartcard: %s") % e)
                raise OTPmeException(msg)

        if not self.smartcard:
            msg = (_("Smartcard authentication requested but no smartcard "
                    "found."))
            raise OTPmeException(msg)

        if not smartcard_type in self.smartcard.otpme_auth_types:
            msg = (_("Authentication type '%s' not supported by "
                    "smartcard.") % smartcard_type)
            raise OTPmeException(msg)

        token_rel_path = smartcard_data['token_path']
        try:
            smartcard_client_handler = config.get_smartcard_handler(smartcard_type)[0]
        except NotRegistered:
            msg = "No smartcard client handler registered: %s" % smartcard_type
            raise OTPmeException(msg)
        self.smartcard_client_handler = smartcard_client_handler(sc_type=smartcard_type,
                                                                token_rel_path=token_rel_path,
                                                                message_method=self.message_method,
                                                                error_message_method=self.error_message_method)
        return self.smartcard_client_handler.handle_authentication(smartcard=self.smartcard,
                                                                    smartcard_data=smartcard_data,
                                                                    password=self.password,
                                                                    peer_time_diff=self.peer_time_diff)

    def gen_user_keys(self, command_dict):
        """ Handle generation of users private/public keys via key script. """
        from otpme.lib.classes.command_handler import CommandHandler
        # Get options.
        username = command_dict['username']
        key_len = command_dict['key_len']
        stdin_pass = command_dict['stdin_pass']

        # When not in interactive mode we cannot call key script.
        if not self.interactive:
            msg = (_("Cannot call key script in non-interactive mode."))
            raise OTPmeException(msg)

        password = None
        if stdin_pass:
            # Get password from stdin.
            timeout = 1
            rlist = select.select([sys.stdin], [], [], timeout)[0]
            if not rlist:
                msg = (_("Timeout reading password from stdin."))
                raise OTPmeException(msg)
            password = sys.stdin.readline().replace("\n", "")
            if not password:
                msg = (_("Got empty password."))
                raise OTPmeException(msg)

        command_handler = CommandHandler()
        try:
            user_private_key, \
            user_public_key = command_handler.gen_user_keys(username,
                                                            password=password,
                                                            key_len=key_len)
            status = True
            status_message = "Keys generated."
        except Exception as e:
            config.raise_exception()
            user_private_key = None
            user_public_key = None
            status = False
            status_message = str(e)

        response = {
                'status'        : status,
                'message'       : status_message,
                'private_key'   : user_private_key,
                'public_key'    : user_public_key,
                }

        return response

    def sign(self, command_dict):
        """ Handle signing via users key script. """
        # Get sign request.
        sign_request = command_dict['data']

        # When not in interactive mode we cannot call key script.
        if not self.interactive:
            msg = (_("Cannot call key script in non-interactive mode."))
            raise OTPmeException(msg)

        # Load sign data.
        try:
            sign_mode = sign_request['sign_mode']
            sign_info = sign_request['sign_info']
            sign_data = sign_request['sign_data']
        except Exception as e:
            msg = "Failed to decode sign request."
            raise OTPmeException(msg)

        # Ask user for confirmation.
        if not config.force:
            # Show info of data to be signed.
            if config.print_raw_sign_data:
                x = json.decode(sign_data, encoding="base64")
            else:
                x = sign_info
            x = pprint.pformat(x)
            msg = (_("Sign the following data?\n%s\n[y/n] ") % x)
            paras = { 'prompt':msg, 'input_prefill':None }
            answer = self.ask(paras)
            if answer.lower() != "y":
                return False

        # Write sign object to temp file. This is needed with the current
        # key script because it pipes the private key via stdin instead of
        # writing it to disk.
        sign_object_file = filetools.create_temp_file(content=sign_data,
                                            user=config.system_user(),
                                            mode=0o700)

        # Build key script command to sign data.
        script_command = [ "sign" ]
        if sign_mode == "server":
            script_command.append("--server-key")
        script_options = [ sign_object_file, '/dev/stdout' ]

        # Run key script.
        script_status, \
        script_stdout, \
        script_stderr, \
        script_pid = stuff.run_key_script(username=self.username, call=False,
                                        key_pass=config.stdin_pass,
                                        script_command=script_command,
                                        script_options=script_options)
        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()

        # Remove sign object file.
        os.remove(sign_object_file)

        if script_status != 0:
            msg = (_("Key script failed: %s") % script_stderr)
            raise OTPmeException(msg)

        if not script_stdout:
            msg = ("Got no signature from key script.")
            raise OTPmeException(msg)

        # Get signature from key script stdout
        #script_stdout = script_stdout.decode()
        for line in script_stdout.split("\n"):
            if line.startswith('SIGNATURE='):
                signature = re.sub('^SIGNATURE=["]+([^"]*)["]+$', r'\1', line)
                break

        return signature

    def encrypt(self, command_dict):
        """ Handle encryption via users key script. """
        # Get RSA flag.
        use_rsa_key = command_dict['use_rsa_key']
        # Get data to encrypt.
        data = command_dict['data']

        # When not in interactive mode we cannot call key script.
        if not self.interactive:
            msg = (_("Cannot call key script in non-interactive mode."))
            raise OTPmeException(msg)

        # Build key script command to encrypt data.
        script_command = [ "encrypt" , "--no-rsa", "--no-self-decrypt" ]
        script_options = [ "/dev/stdin", "/dev/stdout" ]

        if not use_rsa_key:
            script_options.insert(0, "--no-rsa")

        # Start key script.
        proc = stuff.run_key_script(username=self.username,
                                    aes_pass=self.aes_pass,
                                    script_command=script_command,
                                    script_options=script_options,
                                    return_proc=True, call=False)
        # Send data via stdin.
        data = data.encode()
        proc.stdin.write(data)
        proc.stdin.close()
        # Check script return code.
        script_stdout = proc.stdout.read()
        script_stderr = proc.stderr.read()
        ## Make sure script output is string.
        #if isinstance(script_stdout, bytes):
        #    script_stdout = script_stdout.decode()
        #if isinstance(script_stderr, bytes):
        #    script_stderr = script_stderr.decode()
        proc.wait()
        script_returncode = proc.returncode
        if script_returncode != 0:
            msg = (_("Key script failed: %s") % script_stderr)
            raise OTPmeException(msg)

        # Get encrypted data from stdout.
        aes_data = script_stdout
        # Encode encrypted data.
        response = encode(aes_data, "base64")

        return response

    def decrypt(self, command_dict):
        """ Handle decryption via users key script. """
        # FIXME: do we need this????
        ## Get RSA flag.
        #use_rsa_key = command_dict['use_rsa_key']
        # Get data to encrypt.
        data = command_dict['data']

        # When not in interactive mode we cannot call key script.
        if not self.interactive:
            msg = (_("Cannot call key script in non-interactive mode."))
            raise OTPmeException(msg)

        # Get AES data to decrypt.
        aes_data = decode(data, "base64")
        # Build key script command to decrypt data.
        script_command = [ "decrypt" ]
        script_options = [ "/dev/stdin", "/dev/stdout" ]

        # Start key script.
        proc = stuff.run_key_script(username=self.username,
                                    aes_pass=self.aes_pass,
                                    script_command=script_command,
                                    script_options=script_options,
                                    return_proc=True, call=False)
        # Send data via stdin.
        proc.stdin.write(aes_data)
        proc.stdin.close()
        # Check script return code.
        script_stdout = proc.stdout.read()
        script_stderr = proc.stderr.read()
        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()
        proc.wait()
        script_returncode = proc.returncode
        if script_returncode != 0:
            msg = (_("Key script failed: %s") % script_stderr)
            raise OTPmeException(msg)

        # Get decrypted data from stdout.
        response = script_stdout

        return response

    def move_objects(self, command_dict):
        """ Handle objects move. """
        # Get sign request.
        object_data = command_dict['object_data']
        objects = object_data['objects']
        src_realm = object_data['src_realm']
        src_site = object_data['src_site']
        dst_realm = object_data['dst_realm']
        dst_site = object_data['dst_site']
        jwt = object_data['jwt']
        cert = stuff.get_site_cert(realm=src_realm, site=src_site)
        if not cert:
            msg = "Unable to get site certificate."
            raise OTPmeException(msg)
        site_cert = SSLCert(cert=cert)
        try:
            jwt_key = RSAKey(key=site_cert.public_key())
        except Exception as e:
            msg = (_("Unable to get public key of site "
                    "certificate: %s: %s") % (self.site, e))
            raise OTPmeException(msg)
        try:
            jwt_data = _jwt.decode(jwt=jwt,
                                key=jwt_key,
                                algorithm='RS256')
        except Exception as e:
            msg = "JWT verification failed: %s" % e
            self.logger.warning(msg)

        if not config.force:
            x = pprint.pformat(jwt_data)
            msg = (_("Proceed with the following object move?\n%s\n[y/n] ") % x)
            paras = { 'prompt':msg, 'input_prefill':None }
            answer = self.ask(paras)
            if answer.lower() != "y":
                response = {'status':False, 'reply':'Object move aborted by user.'}
                return response

        username = self.username
        try:
            mgmt_conn = connections.get(daemon="mgmtd",
                                    username=username,
                                    auto_auth=False,
                                    realm=dst_realm,
                                    site=dst_site)
        except ConnectionError as e:
            msg = "Site connection failed: %s" % e
            print(msg)
            return
        except Exception as e:
            msg = (_("Unable to connect to mgmt daemon: %s") % e)
            print(msg)
            config.raise_exception()
            return

        command_args = {
                        'subcommand'    : 'user',
                        'src_realm'     : src_realm,
                        'src_site'      : src_site,
                        'objects'       : objects,
                        'jwt'           : jwt,
                    }

        status, \
        status_code, \
        reply = mgmt_conn.send(command="move_object",
                            command_args=command_args)

        mgmt_conn.close()

        response = {'status':status, 'reply':reply}

        return response

    def _handle_response(self, command, command_args,
        response, status_code, blocking=None, timeout=None):
        """ Handle response we got from peer. """
        while True:
            # Stop if we are not the connection endpoint
            # (e.g. when used from within otpme-agent).
            if not self.endpoint:
                break

            # Check if we got a OTPme command.
            if not isinstance(response, dict):
                break
            if not 'command' in response:
                break
            if not 'query_id' in response:
                break

            # Get command from dict.
            client_command = response['command']
            # Get response variable name.
            response_id = response['query_id']

            if not client_command.startswith("OTPME_"):
                msg = (_("Received invalid client command: %s")
                        % client_command)
                raise OTPmeException(msg)

            client_command = client_command.replace("OTPME_", "")

            request = None
            exception = None
            send_request = False
            if client_command == "ASK":
                send_request = True
                try:
                    request = self.ask(response)
                except Exception as e:
                    exception = e

            elif client_command == "ASKPASS":
                send_request = True
                null_ok = response['null_ok']
                try:
                    request = self.askpass(response, null_ok=null_ok)
                except Exception as e:
                    exception = e

            elif client_command == "PASSAUTH":
                send_request = True
                try:
                    request = self.passauth(response)
                except Exception as e:
                    exception = e

            elif client_command == "SSHAUTH":
                send_request = True
                try:
                    request, challenge = self.sshauth(response)
                    command_args['challenge'] = challenge
                except Exception as e:
                    exception = e

            elif client_command == "SCAUTH":
                send_request = True
                try:
                    request = self.scauth(response)
                except Exception as e:
                    exception = e

            elif client_command == "GET_JWT":
                send_request = True
                try:
                    request = self.get_jwt(response)
                except Exception as e:
                    exception = e

            elif client_command == "GEN_USER_KEYS":
                send_request = True
                try:
                    request = self.gen_user_keys(response)
                except Exception as e:
                    exception = e

            elif client_command == "SIGN":
                send_request = True
                try:
                    request = self.sign(response)
                except Exception as e:
                    exception = e

            elif client_command == "ENCRYPT":
                send_request = True
                try:
                    request = self.encrypt(response)
                except Exception as e:
                    exception = e

            elif client_command == "DECRYPT":
                send_request = True
                try:
                    request = self.decrypt(response)
                except Exception as e:
                    exception = e

            elif client_command == "JOB":
                # Set our current job UUID.
                job_uuid = response['query_id']
                self.job = {'job_uuid' : job_uuid}
                # Set job realm/site if we got redirected.
                self.job['realm'] = response['realm']
                self.job['site'] = response['site']

                # Send (keepalive) request to server.
                try:
                    status_code, response = self._send(command=command,
                                                    command_args=self.job,
                                                    blocking=blocking,
                                                    timeout=timeout)
                except Exception as e:
                    config.raise_exception()
                    raise ConnectionError(_("Communication error: %s") % e)

            elif client_command == "MSG":
                # Print message to users terminal.
                self.print_response(response)

                if self.stop_job:
                    x_id = list(self.jobs.keys())[0]
                    x_job_uuid = self.jobs[x_id]
                    command = "stop_job"
                    command_args = x_job_uuid

                # Send (keepalive) request to server.
                try:
                    status_code, response = self._send(command=command,
                                                    command_args=self.job,
                                                    blocking=blocking,
                                                    timeout=timeout)
                except Exception as e:
                    config.raise_exception()
                    raise ConnectionError(_("Communication error: %s") % e)

            elif client_command == "DUMP":
                # Dump message to users terminal.
                send_request = False
                self.print_response(response, ignore_escape_chars=True)
                # Send (keepalive) request to server.
                try:
                    status_code, response = self._send(command=command,
                                                    command_args=self.job,
                                                    blocking=blocking,
                                                    timeout=timeout)
                except Exception as e:
                    config.raise_exception()
                    raise ConnectionError(_("Communication error: %s") % e)

            elif client_command == "OBJECT_MOVE":
                send_request = True
                request = self.move_objects(response)

            # Send request
            if send_request:
                # Add job ID if we have one.
                if self.job:
                    command_args.update(self.job)
                command_args[response_id] = request
                try:
                    status_code, \
                    response = self._send(command=command,
                                    command_args=command_args,
                                    blocking=blocking,
                                    timeout=timeout)
                except Exception as e:
                    config.raise_exception()
                    raise ConnectionError(_("Communication error: %s") % e)

            # Handle exceptions.
            if exception:
                self.cleanup()
                config.raise_exception()
                raise exception

            # Clear command args (e.g. callbacks).
            command_args = {}

        # If we are the connection endpoint (e.g. not called from otpme-agent)
        # and should not print out received replies (e.g. RAPI) we have to
        # return a list with all replies if there is more than one response.
        if self.endpoint and not self.print_messages:
            if self.combined_responses:
                response = list(self.combined_responses)
                self.combined_responses = []
            else:
                # If there is just one response of type str() we return it.
                if not isinstance(response, str):
                    response = [response]

        return status_code, response

    def close(self):
        """ Close our connection. """
        if not self.connected:
            return
        # Set status.
        self.connected = False
        # In API mode we have no connection
        if config.use_api:
            return True
        # Close redirect connection.
        if self.redirect_connection:
            self.redirect_connection.close()
        # Close connection.
        if self.connection:
            self.connection.close()

    def cleanup(self):
        """ Prepare a clean exit. """
        if not self.proto_handler:
            return
        self.proto_handler.cleanup()

class OTPmeClient1(OTPmeClientBase):
    """ Class that implements OTPme client. """
    def __init__(self, daemon, connection, use_smartcard=False, use_ssh_agent=False,
        ssh_agent_method=None, endpoint=True, otpme_agent_user=None,
        start_otpme_agent=None, handle_user_auth=True, handle_host_auth=True,
        need_ssh_key_pass=False, aes_pass=None, client=None, username=None,
        jwt_method=None, rsp=None, srp=None, slp=None, login=False, unlock=False,
        login_interface="tty", logout=False, reneg=False, add_agent_acl=False,
        agent_acls=None, add_agent_session=None, add_login_session=None,
        login_session_id=None, cache_login_tokens=False, password_method=None,
        password=None, cleanup_method=None, check_offline_pass_strength=False,
        offline_iterations_by_score={}, offline_key_derivation_func=None,
        offline_key_func_opts=None, sync_token_data=False, request_jwt=None,
        verify_jwt=None, jwt_challenge=None, jwt_key=None, jwt_auth=False,
        check_login_status=True, allow_untrusted=False, do_preauth=True,
        check_connected_site=True, offline_session_key=None,
        verify_preauth=None, login_redirect=False, **kwargs):
        # Init parent class.
        super(OTPmeClient1, self).__init__(daemon, **kwargs)

        # Set args to be passed on to redirect connection.
        self.redirect_args = dict(kwargs)
        try:
            self.redirect_args.pop("socket_uri")
        except KeyError:
            pass

        # Get logger.
        self.logger = config.logger

        self.password = password
        self.password_method = password_method

        # Set connection.
        self.connection = connection
        # Get realm/site from connection.
        if connection:
            self.realm = connection.realm
            self.site = connection.site

        # The client that sends this request.
        self.client = client
        # The user we will authenticate as.
        self.username = username
        # The users UUID.
        self.user_uuid = None
        # RSP we should use for authentication.
        self.rsp = rsp
        # SRP we will use for session refresh.
        self.srp = srp
        # SLP we will use for session logout.
        self.slp = slp
        # RSP hash type we use.
        self.rsp_hash_type = "PBKDF2"
        # Set password to use when getting request to decrypt some AES data
        # (e.g. users private RSA key)
        self.aes_pass = aes_pass
        # Inidicates that we allow sending of authentication data (passwords etc.)
        # to untrusted sites.
        self.allow_untrusted = allow_untrusted
        # Do preauth with daemon?
        self.do_preauth = do_preauth
        # Check if we are connected to the correct site.
        self.check_connected_site = check_connected_site

        # ECDH curve to use.
        self.ecdh_curve = "SECP384R1"
        # ECDH handler to generage RSP.
        self.rsp_ecdh_key = None

        # Try to load encryption module.
        try:
            self.session_enc_mod = config.get_encryption_module("FERNET")
        except Exception as e:
            msg = "Failed to load session encryption: %s" % e
            raise OTPmeException(msg)
        self.session_key_hash_type = "HKDF"
        self.session_key_hash_algo = "SHA256"

        if start_otpme_agent is None:
            self.start_otpme_agent = True
        else:
            self.start_otpme_agent = start_otpme_agent

        # Indicates that we should start OTPme agent as different user.
        self.otpme_agent_user = otpme_agent_user
        # Indicates if we should add a received login session to OTPme agent
        # and save it to disk.
        self.add_login_session = add_login_session
        # Will hold the login session ID we get from OTPme agent on login (if
        # none is given)
        self.login_session_id = login_session_id

        # Indicates if we should add a empty session to OTPme agent using
        # login_session_id as session ID.
        self.add_agent_session = add_agent_session

        # Client JWT stuff.
        # Indicates if we should do cross-site authentication via JWT.
        self.jwt_auth = jwt_auth
        # Method to request a JWT to do authentication.
        self.jwt_method = jwt_method
        # JWT used to authenticate.
        self.jwt = None

        # Server JWT stuff.
        # Indicates if we should request a JWT.
        self.request_jwt = request_jwt
        # Indicates if we should verify a received JWT.
        self.verify_jwt = verify_jwt
        # JWT challenge we will sent to peer to be signed.
        self.jwt_challenge = jwt_challenge
        # JWT we get from peer on successful auth.
        self.jwt_string = None
        # The decoded JWT data from the received JWT.
        self.jwt_data = None
        # Key to verify JWT.
        self.jwt_key = jwt_key

        # Indicates if we should do a realm login.
        self.login = login
        if self.login:
            if self.add_login_session is None:
                self.add_login_session = True
            if self.add_agent_session is None:
                self.add_agent_session = True
            # By default we will request a JWT on login.
            if self.request_jwt is None:
                self.request_jwt = True
                self.verify_jwt = True
        # The interface the user loggs in (e.g. tty, gui, ssh).
        self.login_interface = login_interface
        # Indicates if we should send a screen unlock request.
        self.unlock = unlock
        if self.unlock:
            # By default we will request a JWT on screen unlock
            if self.request_jwt is None:
                self.request_jwt = True
                self.verify_jwt = True
        # Indicates if we should do a realm logout.
        self.logout = logout

        if (self.login or self.logout) and self.use_agent:
            msg = (_("Realm login/logout are not possible when using agent "
                    "connection."))
            raise OTPmeException(msg)

        if (self.login or self.logout) and not self.daemon == "authd":
            msg = (_("Realm login/logout only possible when connecting "
                    "to authd."))
            raise OTPmeException(msg)

        if self.login and not self.username:
            raise OTPmeException(_("Need username with login=True"))

        if self.logout and not self.username:
            raise OTPmeException(_("Need username with logout=True"))

        # realm/site of peer we are connected to.
        self.peer_realm = None
        self.peer_site = None
        # Indicates if we should verify site signature via preauth_response.
        self.verify_preauth = verify_preauth
        # Will hold peer we are connected to.
        self.peer = None
        # Indicates if we are the connection endpoint (e.g. we are not the
        # endpoint when called from otpme-agent that proxies commands).
        self.endpoint = endpoint
        # Time diff to our peer (filled in on preauth check)
        self.peer_time_diff = 0
        # Indicates if we should call hostd to sync token data after doing auth.
        self.sync_token_data = sync_token_data
        # Indicates if we should handle user authentication.
        self.handle_user_auth = handle_user_auth
        # If --no-auth is given we should not handle authentication, just fail.
        if config.no_auth:
            self.handle_user_auth = False
        # Indicates if we should handle host authentication.
        self.handle_host_auth = handle_host_auth
        # Will hold otpme-agent connection when doing login/logout.
        self.agent_conn = None
        # Indicates if we should try to login using a running ssh-agent.
        self.use_ssh_agent = use_ssh_agent
        # Will hold PID of started ssh-agent.
        self.ssh_agent_pid = None
        # Users SSH agent script.
        self.ssh_agent_script = None
        # Users SSH agent script UUID.
        self.ssh_agent_script_uuid = None
        # Users SSH agent script path.
        self.ssh_agent_script_path = None
        # Users SSH agent script options.
        self.ssh_agent_script_opts = None
        # Users SSH agent script signatures.
        self.ssh_agent_script_signs = None
        # Indicates that we should start the ssh-agent.
        self.start_ssh_agent = False
        # Method to start ssh-agent
        self.ssh_agent_method = ssh_agent_method
        # Indicates that we should ask for the SSH key pass if none was given.
        self.need_ssh_key_pass = need_ssh_key_pass
        # Delay ssh-agent start this amount of seconds (e.g. yubikey needs some
        # seconds to be detected by gpg-agent if it was used in HMAC-SHA1 mode
        # before)
        self.ssh_agent_start_delay = 0
        # Indicates if we should try to use a connected smartcard.
        self.use_smartcard = use_smartcard
        # Will hold smartcard instance.
        self.smartcard = None
        # Will hold the smartcard ID (e.g. yubikey serial)
        self.smartcard_id = None
        # Smartcard options we received from peer (e.g. yubikey slot number)
        self.smartcard_options = {}
        self.smartcard_client_handler = None
        # Indicates that we should check the login status of the user.
        self.check_login_status = check_login_status
        # Indicates if we should cache login tokens received from authd.
        self.cache_login_tokens = cache_login_tokens
        # Will hold class to handle offline tokens.
        self._offline_token = None
        # Will hold key to save offline sessions.
        self.offline_session_key = offline_session_key
        # Offline token key derivation function to use.
        if offline_key_derivation_func is None:
            self.offline_key_derivation_func = config.offline_token_hash_type
        else:
            self.offline_key_derivation_func = offline_key_derivation_func
        # Options for offline token key derivation function.
        self.offline_key_func_opts = offline_key_func_opts
        # Derive offline encryption key iterations based on password strength.
        self.check_offline_pass_strength = check_offline_pass_strength
        # Password strength score to iterations map.
        self.offline_iterations_by_score = offline_iterations_by_score
        # Old offline login sessions we will logout when doing a new realm login.
        self.old_sessions = {}
        # Method that should be run after we have finished. This method is
        # needed because a child process will be started to save offline tokens
        # and thus our caller cannot know if we are really finished after we
        # have returned.
        self.cleanup_method = cleanup_method

        # Indicates that this connection received a login redirect.
        self.login_redirect = login_redirect
        # Will be set true if login to users home site was successful.
        self.login_redirect_status = False
        self.redirect_connection = None

        # Indicates if we should start a session renegotiation.
        self.reneg = reneg

        # Add agent ACLs?.
        self.add_agent_acl = add_agent_acl
        # ACLs we will add to the otpme-agent session when doing a realm login.
        if agent_acls:
            self.agent_acls = agent_acls
        else:
            self.agent_acls = []

        # If we start the otpme-agent as a different user we have to add an ACL to
        # the agent to allow session access for this user.
        if self.otpme_agent_user:
            if self.otpme_agent_user != config.system_user():
                self.add_agent_acl = True

        # Add default agent ACL.
        if self.add_agent_acl:
            agent_acl = (username, 'all')
            if agent_acl not in self.agent_acls:
                self.agent_acls.append(agent_acl)

        # Will hold ssh-agent connection when doing login/logout.
        self.ssh_agent_conn = None
        # Preauth reply.
        self.preauth_reply = None
        # Auth reply.
        self.auth_reply = None

        if self.daemon == "hostd":
            self.verify_preauth = False
            self.request_jwt = False

    def get_peer_from_cert(self):
        """ Try to find OTPme object from peer infos. """
        if not self.connection.peer_cn:
            msg = ("Uuuuuh, we got no peer name (SSL certificate). "
                    "This should never happen. :(")
            self.logger.critical(msg)
            raise CertVerifyFailed("AUTH_SERVER_CERT_MISSING")

        # Try to get peer name etc.
        try:
            peer_fqdn = self.connection.peer_cn
            peer_name = peer_fqdn.split(".")[0]
            peer_site = peer_fqdn.split(".")[1]
            peer_realm = ".".join(peer_fqdn.split(".")[2:])
        except:
            msg = ("Got invalid client cert CN from client: %s"
                    % self.connection.peer_cert)
            self.logger.warning(msg)
            raise CertVerifyFailed("AUTH_INVALID_CERT_CN")

        # Try to find OTPme object of peer.
        for x in ['node', 'host']:
            result = backend.search(realm=peer_realm,
                                    site=peer_site,
                                    attribute="name",
                                    value=peer_name,
                                    object_type=x,
                                    return_type="instance")
            if result:
                peer = result[0]
                if peer.fqdn == self.connection.peer_cn:
                    return peer

        return None

    def cleanup(self):
        """ Prepare a clean exit. """
        # FIXME: leave SSH key pass in agent if its configured? (for the token?)
        # Remove ssh key pass from agent if needed.
        if self.use_ssh_agent \
        and self.agent_conn \
        and self.agent_conn.check_ssh_key_pass():
            if config.debug_level(DEBUG_SLOT) > 0:
                msg = ("Removing SSH key passphrase from agent...")
                self.logger.debug(msg)
            try:
                self.agent_conn.del_ssh_key_pass()
            except Exception as e:
                msg = ("Error removing SSH key passphrase from agent.")
                self.logger.warning(msg)

        # Close ssh-agent  connection
        if self.ssh_agent_conn:
            try:
                self.ssh_agent_conn.close()
            except:
                pass
            # Remove agent connection
            self.ssh_agent_conn = None

        # Remove session on logout and close otpme-agent connection
        if self.agent_conn:
            if self.logout:
                try:
                    # Remove login session from agent on logout
                    self.agent_conn.del_session()
                except:
                    pass
            # Remove agent connection
            self.agent_conn = None

        ## FIXME: do we need this?
        ## Workaround for http://bugs.python.org/issue24596
        #try:
        #    del self.smartcard
        #    self.smartcard = None
        #except:
        #    pass

        # Release offline token lock.
        if self._offline_token:
            self._offline_token.unlock()

        # Run cleanup method.
        if self.cleanup_method:
            try:
                self.cleanup_method()
            except Exception as e:
                msg = ("Error running cleanup method: %s" % e)
                self.logger.critical(msg)

    def get_hostd_conn(self):
        """ Get connection to hostd. """
        from otpme.lib import connections
        try:
            hostd_conn = connections.get("hostd")
            return hostd_conn
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to get connection to hostd: %s") % e)
            raise OTPmeException(msg)

    def get_password(self, prompt, null_ok=False):
        """ Ask user for password. """
        if self.password_method:
            try:
                password = self.password_method(prompt)
            except Exception as e:
                raise OTPmeException(_("Unable to get password: %s") % e)
        elif self.interactive:
            try:
                password = cli.read_pass(prompt)
            except Exception as e:
                msg = (_("Error reading password from stdin: %s") % e)
                raise OTPmeException(msg)
        else:
            raise AuthFailed(_("In non-interactive mode 'password' or "
                            "'password_method' is required."))
        if not password and not null_ok:
            raise AuthFailed(_("Got empty password."))
        return password

    def detect_smartcard(self, sc_types=None):
        """ Detect locally connected smartcard. """
        from otpme.lib.smartcard.utils import detect_smartcard
        # Try to detect smartcard.
        smartcard = detect_smartcard(sc_types)
        if not smartcard:
            # Set to False to indicate we searched for a smartcard
            # and havent found one.
            self.smartcard = False
            return False
        # If we found a valid smartcard set it.
        self.smartcard = smartcard
        return True

    def _verify_jwt(self, auth_reply):
        """ Verify JWT from auth reply. """
        # Try to get JWT from auth reply.
        try:
            self.jwt_string = auth_reply['jwt']
        except:
            raise OTPmeException(_("Malformed auth reply: Missing JWT"))

        if not self.jwt_string:
            msg = (_("Authentication reply does not contain JWT."))
            raise OTPmeException(msg)

        # Verify JWT.
        try:
            self.jwt_data = _jwt.decode(jwt=self.jwt_string,
                                key=self.jwt_key,
                                algorithm='RS256')
        except Exception as e:
            raise OTPmeException(_("JWT verification failed: %s") % e)

        # Get JWT challenge.
        try:
            jwt_challenge = self.jwt_data['challenge']
        except:
            raise OTPmeException(_("JWT data is missing challenge."))

        # Check JWT challenge.
        if jwt_challenge != self.jwt_challenge:
            raise OTPmeException(_("Received wrong JWT challenge."))

    def redirect_conn(self, realm, site, challenge, login=False):
        """ Redirect login to other site. """
        # Mark this connection as a login redirect.
        self.login_redirect = True

        conn_type = "connection"
        if login:
            conn_type = "login"

        msg = ("Starting redirected %s to: %s/%s" % (conn_type, realm, site))
        self.logger.info(msg)
        # Send login request to users home site.
        redirect_connection = connections.get(daemon=self.daemon,
                            #socket_uri=self.socket_uri,
                            use_ssl=self.connection.use_ssl,
                            verify_server=self.connection.verify_server,
                            #message_method=self.message_method,
                            #error_message_method=self.error_message_method,
                            connect_timeout=self.connection.connect_timeout,
                            timeout=self.connection.timeout,
                            auth_type=self.auth_type,
                            use_smartcard=self.use_smartcard,
                            use_ssh_agent=self.use_ssh_agent,
                            ssh_agent_method=self.ssh_agent_method,
                            #use_agent=self.use_agent,
                            use_dns=self.connection.use_dns,
                            endpoint=self.endpoint,
                            #handle_response=self.handle_response,
                            handle_user_auth=self.handle_user_auth,
                            handle_host_auth=self.handle_host_auth,
                            #interactive=self.interactive,
                            #print_messages=self.print_messages,
                            need_ssh_key_pass=self.need_ssh_key_pass,
                            aes_pass=self.aes_pass,
                            client=self.client,
                            username=self.username,
                            password=self.password,
                            password_method=self.password_method,
                            login_interface=self.login_interface,
                            rsp=self.rsp,
                            srp=self.srp,
                            slp=self.slp,
                            #login=self.login,
                            login=login,
                            unlock=self.unlock,
                            logout=self.logout,
                            reneg=self.reneg,
                            otpme_agent_user=self.otpme_agent_user,
                            add_agent_acl=self.add_agent_acl,
                            agent_acls=self.agent_acls,
                            add_agent_session=self.add_agent_session,
                            add_login_session=self.add_login_session,
                            login_session_id=self.login_session_id,
                            cache_login_tokens=self.cache_login_tokens,
                            cleanup_method=self.cleanup_method,
                            autoconnect=True,
                            check_offline_pass_strength=self.check_offline_pass_strength,
                            offline_iterations_by_score=self.offline_iterations_by_score,
                            offline_key_derivation_func=self.offline_key_derivation_func,
                            offline_key_func_opts=self.offline_key_func_opts,
                            auto_auth=False,
                            sync_token_data=self.sync_token_data,
                            request_jwt=self.request_jwt,
                            verify_jwt=self.verify_jwt,
                            jwt_challenge=challenge,
                            #jwt_key=self.jwt_key,
                            login_redirect=True,
                            realm=realm,
                            site=site,
                            **self.redirect_args)

        # Try to login user.
        auth_command = "auth"
        if login:
            auth_command = "login"
        try:
            redirect_connection.authenticate(command=auth_command)
        finally:
            # Close redirect connection.
            if login:
                redirect_connection.close()

        if not login:
            self.redirect_connection = redirect_connection
            return

        # If there was no exception we are logged in to users home site.
        self.login_redirect_status = True

        # On login redirect we have to change to JWT authentication for this
        # connection.
        self.jwt_auth = True
        # We will use the JWT we received from the redirected login connection
        # to authenticate to the realm/site we want to login to.
        self.jwt = redirect_connection.jwt_string
        # The redirect connection already added a agent session. We will use it
        # to add the RSP of our site too.
        self.login_session_id = redirect_connection.login_session_id
        self.offline_session_key = redirect_connection.offline_session_key

        # Disable stuff already done by the redirected login.
        self.use_ssh_agent = False
        self.use_smartcard = False
        self.sync_token_data = False
        self.add_agent_session = False
        self.need_ssh_key_pass = False
        self.check_login_status = False
        self.cache_login_tokens = False

    def preauth_check(self):
        """ Do preauth check with daemon. """
        preauth_args = {}
        need_token = False

        # Set requesting client.
        preauth_args['client'] = self.client

        # By default we will verify the preauth response.
        if self.verify_preauth is None:
            self.verify_preauth = True

        # Gen preauth challenge to be signed by remote site.
        if self.verify_preauth:
            preauth_challenge = stuff.gen_secret(len=32)
            preauth_args['preauth_challenge'] = preauth_challenge

        # Add JWT auth parameter to request JWT challenge.
        preauth_args['jwt_auth'] = self.jwt_auth

        # Add username if we have one.
        if self.username:
            preauth_args['username'] = self.username
            need_token = True

        if self.login:
            preauth_args['login'] = True
        else:
            preauth_args['login'] = False

        if self.logout:
            preauth_args['logout'] = True
        else:
            preauth_args['logout'] = False

        if self.reneg or self.rsp or self.srp or self.slp:
            need_token = False

        # Indicates if we need the preauth reply to include valid token
        # types that could be used to authenticate the user.
        preauth_args['need_token'] = need_token

        need_jwt_key = False
        need_site_cert = False

        # If verification of preauth response is enabled we need the site cert.
        if self.verify_preauth:
            need_site_cert = True
            if not self.realm or not self.site:
                msg = (_("Need <realm> and <site> to verfiy preauth reply."))
                raise OTPmeException(msg)

        # If no JWT key was given we need to get it from our site cert.
        if self.request_jwt and not self.jwt_key:
            need_jwt_key = True
            need_site_cert = True
            if not self.realm or not self.site:
                msg = (_("Need <realm> and <site> to get JWT key."))
                raise OTPmeException(msg)

        # When doing JWT authentication we also need the JWT key.
        if self.jwt_auth and not self.jwt_key:
            need_jwt_key = True
            need_site_cert = True
            if not self.realm or not self.site:
                msg = (_("Need <realm> and <site> to get JWT key."))
                raise OTPmeException(msg)

        # If we need to negotiation a session key we need the site cert to
        # encrypt the preauth request (key).
        if self.connection.encrypt_session:
            need_site_cert = True
            if not self.realm or not self.site:
                msg = (_("Need <realm> and <site> to negotiate session key."))
                raise OTPmeException(msg)

        # Load site cert.
        if need_site_cert and not self.site_cert:
            cert = stuff.get_site_cert(realm=self.realm, site=self.site)
            if not cert:
                msg = "Unable to get site certificate."
                raise OTPmeException(msg)
            self.site_cert = SSLCert(cert=cert)

        # Get JWT key from site certificate.
        if need_jwt_key:
            try:
                self.jwt_key = RSAKey(key=self.site_cert.public_key())
            except Exception as e:
                msg = (_("Unable to get public key of site "
                        "certificate: %s: %s") % (self.site, e))
                raise OTPmeException(msg)

        # Generate DH stuff for session key negotiation.
        enc_key = None
        enc_mod = None
        command_args = {}
        if self.connection.encrypt_session:
            # Set preauth encryption stuff.
            enc_mod = self.session_enc_mod
            enc_key = enc_mod.gen_key()
            # Load site key.
            if config.debug_level(DEBUG_SLOT) > 3:
                self.logger.debug("Loading site key.")
            try:
                site_key = RSAKey(key=self.site_cert.public_key())
            except Exception as e:
                config.raise_exception()
                msg = (_("Failed to load site key."))
                raise OTPmeException(msg)
            # Encrypt AES key with site public key.
            if config.debug_level(DEBUG_SLOT) > 3:
                self.logger.debug("Encrypting preauth key...")
            try:
                _enc_key = site_key.encrypt(enc_key)
            except Exception as e:
                msg = (_("Failed to encrypt preauth key: %s") % e)
                raise OTPmeException(msg)
            try:
                _enc_key = encode(_enc_key, "hex")
            except Exception as e:
                msg = (_("Failed to encode DH for session key: %s") % e)
                raise OTPmeException(msg)
            # Add encrypted AES key.
            command_args['enc_key'] = _enc_key
            # Generating DH parameters.
            if config.debug_level(DEBUG_SLOT) > 3:
                self.logger.debug("Generating DH parameters for session key...")
            try:
                ecdh_key = ECKey()
                ecdh_key.gen_key(curve=self.ecdh_curve)
            except Exception as e:
                msg = (_("Failed to generate DH parameters for session "
                        "key: %s") % e)
                raise OTPmeException(msg)
            # Add session key DH parameters to request args.
            preauth_args['ecdh_client_pub'] = ecdh_key.export_public_key()

        # Build preauth request.
        try:
            preauth_request = build_request(command="preauth_request",
                                            command_args=preauth_args,
                                            encryption=enc_mod,
                                            enc_key=enc_key,
                                            compress=self.compress_request)
        except Exception as e:
            msg = (_("Faild to build preauth request: %s") % e)
            raise OTPmeException(msg)

        # Add preauth request.
        command_args['preauth_request'] = preauth_request

        # Send preauth request.
        if self.socket_uri:
            msg = ("Sending preauth request to %s %s/%s (%s)..."
                    % (self.daemon, self.realm, self.site, self.socket_uri))
        else:
            msg = ("Sending preauth request to %s %s/%s..."
                    % (self.daemon, self.realm, self.site))
        if config.debug_level(DEBUG_SLOT) > 3:
            self.logger.debug(msg)
        try:
            status, \
            status_code, \
            response = self.connection.send(command="preauth_check",
                                        command_args=command_args,
                                        encrypt_request=False,
                                        handle_response=False,
                                        handle_auth=False)
        except Exception as e:
            msg = (_("Error sending command 'preauth_check': %s") % e)
            config.raise_exception()
            raise ConnectionError(msg)

        #msg = ("Received preauth response.")
        #if self.interactive:
        #    message(msg)
        #self.logger.debug(msg)
        if status_code == status_codes.ERR:
            raise AuthFailed(response)

        if status_code == status_codes.HOST_DISABLED:
            raise HostDisabled(response)

        if status_code == status_codes.CLUSTER_NOT_READY:
            raise ConnectionError(response)

        if status_code != status_codes.OK:
            msg = (_("Got unknown preauth reply code: %s") % status_code)
            raise OTPmeException(msg)

        if not isinstance(response, dict):
            msg = (_("Got wrong preauth reply: %s") % response)
            raise OTPmeException(msg)

        try:
            reply_type = response['type']
        except:
            msg = (_("Preauth reply misses <type>."))
            raise OTPmeException(msg)

        if reply_type != "preauth":
            msg = (_("Got wrong preauth reply type: %s") % reply_type)
            raise OTPmeException(msg)

        # Get inner preauth reply.
        preauth_reply = response['preauth_reply']

        if self.connection.encrypt_session:
            _enc_mod = None
            _reply_key = None
            try:
                reply_key = response['enc_key']
            except:
                reply_key = None
            try:
                host_key = config.host_data['auth_key']
            except:
                host_key = None
            if host_key:
                _enc_mod = enc_mod
                if not reply_key:
                    msg = (_("Preauth reply misses <enc_key>."))
                    raise OTPmeException(msg)
                # Load host private key.
                try:
                    host_key = RSAKey(key=host_key)
                except:
                    msg = (_("Failed to load host auth key."))
                    self.logger.warning(msg)
                    config.raise_exception()
                    raise OTPmeException(msg)
                # Decrypt reply key.
                try:
                    _reply_key = decode(reply_key, "hex")
                    _reply_key = host_key.decrypt(_reply_key)
                except Exception as e:
                    msg = (_("Failed to decrypt preauth reply key: %s" % e))
                    self.logger.warning(msg)
                    config.raise_exception()
                    raise OTPmeException(msg)
            # Decrypt preauth reply.
            try:
                preauth_reply = json.decode(preauth_reply,
                                            encoding="base64",
                                            encryption=_enc_mod,
                                            enc_key=_reply_key)
            except Exception as e:
                msg = (_("Failed to decrypt preauth reply: %s" % e))
                self.cleanup()
                config.raise_exception()
                raise OTPmeException(msg)

        # Set preauth reply.
        self.preauth_reply = preauth_reply

        try:
            preauth_status = self.preauth_reply['status']
        except:
            msg = (_("Malformed preauth reply: Missing status"))
            raise OTPmeException(msg)

        try:
            preauth_message = self.preauth_reply['status_message']
        except:
            msg = (_("Malformed preauth reply: Missing message"))
            raise OTPmeException(msg)

        try:
            preauth_response = self.preauth_reply['preauth_response']
        except:
            msg = (_("Malformed preauth reply: Missing preauth response"))
            raise OTPmeException(msg)

        if self.connection.encrypt_session:
            try:
                ecdh_server_pub_pem = self.preauth_reply['ecdh_server_pub']
            except:
                msg = (_("Malformed preauth reply: Missing server ECDH "
                        "public key."))
                raise OTPmeException(msg)

        # Set realm/site we are connected to.
        try:
            self.peer_realm = self.preauth_reply['realm']
            self.peer_site = self.preauth_reply['site']
        except:
            msg = (_("Malformed preauth reply: Missing peer realm/site"))
            raise OTPmeException(msg)

        if not preauth_status:
            raise AuthFailed(_("Preauth failed: %s") % preauth_message)

        # Make sure we are connected to the right realm/site.
        if self.check_connected_site:
            if self.site:
                if self.realm != self.peer_realm:
                    msg = (_("Connected to wrong realm: %s") % self.peer_realm)
                    raise OTPmeException(msg)
                if self.site != self.peer_site:
                    msg = (_("Connected to wrong site: %s") % self.peer_site)
                    raise OTPmeException(msg)

        # Verify site signature.
        if self.verify_preauth:
            try:
                self.site_cert.verify(data=preauth_challenge,
                                    signature=preauth_response,
                                    encoding="base64")
            except Exception as e:
                config.raise_exception()
                msg = (_("Site signature verification failed: %s: %s")
                        % (self.site_cert.get_cn(), e))
                raise AuthFailed(msg)
            if config.debug_level(DEBUG_SLOT) > 3:
                msg = ("Site signature verification successful: %s" % self.site)
                self.logger.debug(msg)

        if self.connection.encrypt_session:
            # Generate session key via DH.
            if config.debug_level(DEBUG_SLOT) > 3:
                self.logger.debug("Generating session key via DH.")
            try:
                ecdh_server_pub = ecdh_key.load_public_key(ecdh_server_pub_pem)
                dh_shared_secret = ecdh_key.dhexchange(ecdh_server_pub)
                # FIXME: Does we get any implications using the server DH public
                #       key as salt?
                session_key = self.session_enc_mod.derive_key(dh_shared_secret,
                                                    salt=ecdh_server_pub_pem,
                                                    hash_type=self.session_key_hash_type,
                                                    hash_algo=self.session_key_hash_algo)
                self.connection.session_key = session_key['key']
            except:
                msg = (_("Failed to generate session key."))
                self.logger.warning(msg)
                config.raise_exception()
                raise OTPmeException(msg)

        # Handle authentication redirects.
        if preauth_status == "redirect_auth":
            if self.login:
                # On realm login we have to redirect the login request to the
                # realm/site we got from the preauth reply and pass on the
                # redirect challenge to be signed by the users home site.
                auth_realm = self.preauth_reply['auth_realm']
                auth_site = self.preauth_reply['auth_site']
                auth_challenge = self.preauth_reply['auth_challenge']
                try:
                    self.redirect_conn(realm=auth_realm,
                                        site=auth_site,
                                        challenge=auth_challenge,
                                        login=True)
                except AuthFailed as e:
                    raise AuthFailed(_("Redirected login failed: %s") % e)
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Login redirect failed: %s") % e)
                    raise OTPmeException(msg)

            elif self.logout:
                # No need to redirect request on logout as its
                # done via SLP from otpme-agent.
                if config.debug_level(DEBUG_SLOT) > 3:
                    self.logger.debug("Doing cross-site logout.")

            elif preauth_status == "redirect_auth":
                # Redirect connection.
                auth_realm = self.preauth_reply['auth_realm']
                auth_site = self.preauth_reply['auth_site']
                auth_challenge = self.preauth_reply['auth_challenge']
                try:
                    self.redirect_conn(realm=auth_realm,
                                        site=auth_site,
                                        challenge=auth_challenge)
                except AuthFailed as e:
                    raise AuthFailed(_("Redirected authentication failed: %s") % e)
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Connection redirect failed: %s") % e)
                    raise OTPmeException(msg)

        if self.jwt_auth and preauth_status == "jwt_auth":
            # If we do JWT authentication we have to ensure that we have
            # a JWT.
            if not self.jwt_method:
                msg = (_("Need <jwt_method> with <jwt_auth>."))
                raise OTPmeException(msg)
            # Get challenge to be signed by the given <jwt_method>.
            auth_challenge = self.preauth_reply['auth_challenge']
            # Try to get JWT.
            try:
                self.jwt = self.jwt_method(auth_challenge)
            except Exception as e:
                msg = "JWT method failed: %s" % e
                self.logger.critical(msg)
                raise
            # When doing JWT authentication we must make sure that the JWT we will
            # send is for the realm/site we connect to.
            # Get users site certificate.
            hostd_conn = self.get_hostd_conn()
            user_site = hostd_conn.get_user_site(self.username)
            cert_pem = hostd_conn.get_site_cert(realm=config.realm, site=user_site)
            if not cert_pem:
                msg = (_("Unable to get certificate for site: ") % user_site)
                raise OTPmeException(msg)
            _cert = SSLCert(cert=cert_pem)
            # Get public key as JWT key.
            _jwt_key = _cert.public_key()
            _jwt_key = RSAKey(key=_jwt_key)
            # Decode outer JWT.
            try:
                jwt_data = _jwt.decode(jwt=self.jwt,
                                    key=_jwt_key,
                                    algorithm='RS256')
            except Exception as e:
                msg = (_("Unable to decode outer JWT: %s") % e)
                raise OTPmeException(msg)

            jwt_string = jwt_data['challenge']

            # Decode inner JWT.
            try:
                jwt_data = _jwt.decode(jwt=jwt_string,
                                    key=self.jwt_key,
                                    algorithm='RS256')
            except Exception as e:
                msg = (_("Unable to decode inner JWT: %s") % e)
                raise OTPmeException(msg)

            # Get inner JWT data.
            jwt_realm = jwt_data['realm']
            jwt_site = jwt_data['site']
            jwt_user = jwt_data['user']

            if jwt_realm != self.realm:
                raise AuthFailed(_("Will not send JWT with wrong realm: %s")
                                % jwt_realm)

            if jwt_site != self.site:
                raise AuthFailed(_("Will not send JWT with wrong site: %s")
                                % jwt_site)

            if jwt_user != self.username:
                raise AuthFailed(_("Will not send JWT with wrong username: %s")
                                % jwt_user)

        # Make sure we connect to a trusted (by the users site) realm/site. This
        # is to prevent sending of authentication data (e.g. password, RSP etc.)
        # to an untrusted site by mistake.
        check_site_trust = False
        if self.site and not self.allow_untrusted:
            check_site_trust = True

        # When doing JWT auth we do not need to check for a trusted site because
        # the JWT was checked to be valid for the realm/site we connect to above.
        if self.jwt_auth:
            check_site_trust = False

        # No need to check site trust status without username.
        if not self.username:
            check_site_trust = False

        if self.login_redirect:
            check_site_trust = False

        # Check site trust.
        if check_site_trust:
            try:
                stuff.get_site_trust_status(self.realm, self.site)
            except SiteNotTrusted as e:
                msg = str(e)
                raise OTPmeException(msg)

        # Get server time from preauth reply.
        try:
            peer_time = self.preauth_reply['time']
        except:
            msg = (_("Malformed preauth reply: Missing peer time"))
            raise OTPmeException(msg)

        # Try to get users agent script from preauth reply.
        if self.username:
            try:
                self.ssh_agent_script = self.preauth_reply['agent_script']
                self.ssh_agent_script_uuid = self.preauth_reply['agent_script_uuid']
                self.ssh_agent_script_path = self.preauth_reply['agent_script_path']
                self.ssh_agent_script_opts = self.preauth_reply['agent_script_options']
                self.ssh_agent_script_signs = self.preauth_reply['agent_script_signs']
            except Exception:
                self.logger.debug("Got no SSH agent script from peer.")

        self.peer_time_diff = time.time() - float(peer_time)
        if self.peer_time_diff > 15 or self.peer_time_diff < -15:
            msg = (_("Local system time differs (%s seconds) from peers system "
                    "time. You may experience login issues.")
                    % self.peer_time_diff)
            if self.interactive:
                msg = (_("WARNING: %s") % msg)
                self.print_msg(msg, error=True)
            else:
                self.logger.warning(msg)

        if self.username:
            # Get smartcard options from preauth reply.
            try:
                self.smartcard_options = self.preauth_reply['token_options']
            except:
                pass

    def authenticate(self, command=None):
        """ Handle authentication with daemon. """
        auth_message = None
        # In API mode we have no connection to authenticate
        if config.use_api:
            return True

        ## If using otpme-agent is requested make sure we are authorized to it.
        #if self.use_agent:
        #    if not self.login_session_id:
        #        return
        #    # If we got a login session ID try to auth with agent.
        #    if config.debug_level(DEBUG_SLOT) > 3:
        #        self.logger.debug("Using login session ID: %s"
        #                        % self.login_session_id)
        #    command_args = {
        #                    'login_session_id'  : self.login_session_id,
        #                }
        #    try:
        #        status, \
        #        status_code, \
        #        response = self.connection.send(command="auth",
        #                                    command_args=command_args,
        #                                    encrypt_request=False,
        #                                    handle_response=False,
        #                                    handle_auth=False,
        #                                    use_agent=False)
        #    except Exception as e:
        #        msg = (_("Error sending 'auth' command to otpme-agent: %s")
        #                % e)
        #        self.cleanup()
        #        raise OTPmeException(msg)

        #    if status_code != status_codes.OK:
        #        self.cleanup()
        #        msg = (_("Authentication with otpme-agent failed."))
        #        raise OTPmeException(msg)

        #    # When using otpme-agent we are done here.
        #    return

        # Try to get otpme-agent connection when doing realm login/logout or SSH
        # agent usage is requested.
        need_agent_conn = False
        if self.endpoint:
            if self.login or self.use_agent:
                need_agent_conn = True
            if self.logout:
                need_agent_conn = True

        # Without realm we cannot start OTPme agent (e.g. when joining realm).
        if not config.realm:
            need_agent_conn = False

        if need_agent_conn:
            # Make sure otpme-agent is running.
            if self.start_otpme_agent:
                try:
                    stuff.start_otpme_agent(user=self.otpme_agent_user,
                                            wait_for_socket=False)
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Unable to start otpme-agent: %s") % e)
                    raise OTPmeException(msg)

            # Wait for otpme-agent socket to appear.
            stuff.wait_for_agent_socket(user=self.otpme_agent_user, quiet=False)

            # Try to connect to otpme-agent.
            try:
                self.agent_conn = connections.get("agent",
                                    user=self.otpme_agent_user,
                                    login_session_id=self.login_session_id,
                                    autoconnect=False)
            except Exception as e:
                self.cleanup()
                msg = (_("Error getting agent connection: %s") % e)
                raise OTPmeException(msg)

            # Try to connect to agent
            try:
                self.agent_conn.connect()
            except UnknownLoginSession as e:
                # Remove session ID from agent connection to prevent
                # auth failure on add_session() below.
                self.agent_conn.login_session_id = None
            except Exception as e:
                self.cleanup()
                raise ConnectionError(str(e))

            if self.login and self.check_login_status:
                # Get agent user.
                agent_user = self.agent_conn.get_user()
                # Check login status.
                if self.agent_conn.get_status():
                    self.cleanup()
                    msg = (_("Already logged in as user: %s") % agent_user)
                    raise AlreadyLoggedIn(msg)
                # Remove empty agent/login session if needed.
                if agent_user:
                    try:
                        self.agent_conn.del_session()
                    except Exception as e:
                        self.cleanup()
                        msg = (_("Error removing empty session from "
                                "otpme-agent: %s") % e)
                        raise OTPmeException(msg)

            if self.add_agent_session:
                # (Re-)add new session.
                self.login_session_id = self.agent_conn.add_session(
                                            username=self.username,
                                            session_id=self.login_session_id)
                if not self.login_session_id:
                    self.cleanup()
                    raise OTPmeException("Error adding session to otpme-agent.")

                # Check if we need to add ACLs to the login session because the
                # login user is not the system user (e.g. pam_otpme).
                if self.agent_acls:
                    for i in self.agent_acls:
                        user = i[0]
                        acl = i[1]
                        self.agent_conn.add_acl(username=user, acl=acl)

        # Do preauth check.
        if self.do_preauth:
            try:
                self.preauth_check()
            except Exception as e:
                msg = (_("Error sending preauth request: %s") % e)
                raise
            self.do_preauth = False

        # For direct daemon connections we may handle auth stuff.
        command_args = {}
        if not command:
            if self.login:
                command = "login"
            elif self.logout:
                command = "logout"
            elif self.srp:
                command = "session_refresh"
            elif self.reneg:
                command = "session_reneg"
            else:
                command = "status"

        command_args['username'] = self.username
        # Send given command to server.
        try:
            status, \
            status_code, \
            response = self.connection.send(command=command,
                                        command_args=command_args,
                                        handle_response=False,
                                        handle_auth=False)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error sending auth command: %s") % e)
            raise ConnectionError(msg)

        # Handle errors.
        exception = None
        if status_code == status_codes.ERR:
            #exception = Exception
            exception = AuthFailed
        if status_code == status_codes.HOST_DISABLED:
            exception = HostDisabled

        if exception:
            if response.startswith("JSON{"):
                error = json.decode(response, encoding="base64")
                if config.debug_enabled:
                    msg = ("FIXME: Got unexpected JSON response: %s" % error)
                    error_message(msg)
            else:
                error = response
            raise exception(_("Connection error: %s") % error)

        # Try user auth if command needs authenticated user.
        if status_code == status_codes.NEED_USER_AUTH and self.handle_user_auth:
            try:
                auth_message = self.authenticate_user()
            except Exception as login_exception:
                config.raise_exception()
                if self.login_redirect and self.login_redirect_status:
                    self.logger.warning("Redirected login failed: %s"
                                        % login_exception)
                    # If this was a login redirect send logout request for
                    # users home site.
                    if config.debug_level(DEBUG_SLOT) > 0:
                        self.logger.debug("Logging user out from home site...")
                    try:
                        agent_conn = connections.get("agent",
                                        user=self.otpme_agent_user,
                                        login_session_id=self.login_session_id)
                        agent_conn.del_session()
                    except Exception as e:
                        self.logger.warning("Failed to logout user from home "
                                            "site: %s" % e)
                raise login_exception

        # Try host auth if command needs authenticated host.
        if status_code == status_codes.NEED_HOST_AUTH and self.handle_host_auth:
            auth_message = self.authenticate_host()

        return auth_message

    def authenticate_user(self):
        """ Authenticate user with daemon. """
        from paramiko.agent import Agent
        auth_message = None
        command_args = {}
        if not self.username:
            self.cleanup()
            raise OTPmeException("Cannot authenticate without username.")

        # Add login interface this request comes from (e.g. tty, gui, ...).
        command_args['login_interface'] = self.login_interface

        ## Check if we have to start SSH agent by the given method.
        #if self.peer_auth_types is not None and "ssh_key" in self.peer_auth_types:
        #    if self.ssh_agent_method:
        #        self.start_ssh_agent = True
        #elif self.peer_auth_types is not None:
        #    # If preauth check was done and peer does not offer SSH auth we
        #    # cannot continue if using of ssh-agent is requested.
        #    if self.use_ssh_agent is True:
        #        self.cleanup()
        #        raise AuthFailed("Peer does not offer SSH auth.")
        #    self.use_ssh_agent = False
        #    if config.debug_level(DEBUG_SLOT) > 0:
        #        msg = ("Not starting ssh-agent because no "
        #                "related auth type was offered by peer.")
        #        self.logger.debug(msg)

        # Check token/smartcard options for a supported smartcard type.
        if self.use_smartcard == "auto":
            sc_types = []
            pass_required = False
            self.use_smartcard = False
            for rel_path in self.smartcard_options:
                sc_type = self.smartcard_options[rel_path]['token_type']
                pass_required = self.smartcard_options[rel_path]['pass_required']
                try:
                    smartcard_client_handler = config.get_smartcard_handler(sc_type)[0]
                except NotRegistered:
                    continue
                self.smartcard_client_handler = smartcard_client_handler(sc_type=sc_type,
                                                                token_rel_path=rel_path,
                                                                token_options=self.smartcard_options[rel_path],
                                                                message_method=self.message_method,
                                                                error_message_method=self.error_message_method)
                self.use_smartcard = "auto"
                sc_types.append(sc_type)
                break
            if not self.use_smartcard:
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Not trying to detect smartcard because "
                            "no related auth type was offered by peer.")
                    self.logger.debug(msg)

        if self.use_smartcard:
            # Try to find local connected smartcard
            try:
                self.detect_smartcard(sc_types=sc_types)
            except Exception as e:
                self.logger.warning("Error detecting smartcard: %s" % e)

            # If smartcard usage was requested we have to fail if no smartcard
            # was found.
            if self.use_smartcard is True and not self.smartcard:
                self.cleanup()
                raise AuthFailed("No smartcard found.")

            if self.smartcard:
                if pass_required and not self.password:
                    try:
                        self.password = self.get_password("Password: ")
                    except Exception as e:
                        self.cleanup()
                        raise AuthFailed(str(e))
                smartcard_data = self.smartcard_client_handler.handle_preauth(smartcard=self.smartcard,
                                                                                password=self.password)
                command_args['smartcard_data'] = smartcard_data

            ## FIXME: Workaround to get gpg-agent detect yubikey after
            ##        it was used in HMAC-SHA1 mode.
            #if self.smartcard and self.smartcard.type == "yubikey":
            #    self.ssh_agent_start_delay = 3

        if self.login:
            if self.password is None:
                if not self.handle_response:
                    msg = "Login request without password needs handle_response=True"
                    raise OTPmeException(msg)

        if self.start_ssh_agent:
            # Delay start if needed.
            if self.ssh_agent_start_delay:
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Delaying start of ssh-agent by '%s' seconds."
                            % self.ssh_agent_start_delay)
                    self.logger.debug(msg)
                time.sleep(self.ssh_agent_start_delay)
            # Try to start ssh-agent via given method.
            try:
                self.ssh_agent_method(session_id=self.login_session_id,
                                script=self.ssh_agent_script,
                                script_uuid=self.ssh_agent_script_uuid,
                                script_path=self.ssh_agent_script_path,
                                script_options=self.ssh_agent_script_opts,
                                script_signatures=self.ssh_agent_script_signs)
            except Exception as e:
                self.cleanup()
                raise AuthFailed(str(e))

        # SSH agent PID that will be added to otpme-agent to check if a process
        # is authorized to access the ssh_key_pass.
        if self.use_ssh_agent:
            try:
                self.ssh_agent_pid = os.environ['SSH_AGENT_PID']
            except:
                pass

        # Make sure we pass on SLP of old session when sending login requests.
        if self.login:
            # Try to get users UUID.
            hostd_conn = self.get_hostd_conn()
            self.user_uuid = hostd_conn.get_user_uuid(self.username)
            if not self.user_uuid:
                self.cleanup()
                raise AuthFailed(_("Unknown user: %s") % self.username)

            # Load module to handle offline tokens and login session file.
            try:
                from otpme.lib.offline_token import OfflineToken
                # Get offline token handler.
                self._offline_token = OfflineToken()
            except Exception as e:
                msg = (_("Error loading offline token module: %s") % e)
                self.logger.critical(msg)
                self.cleanup()
                raise AuthFailed(msg)

            # Set login user to get path to cache directory etc.
            try:
                self._offline_token.set_user(user=self.username,
                                            uuid=self.user_uuid)
            except Exception as e:
                msg = (_("Error initializing offline tokens: %s") % e)
                self.logger.critical(msg)
                self.cleanup()
                raise AuthFailed(msg)

            # Get SLPs of old offline sessions we will try to logout.
            try:
                x = self._offline_token.get_old_offline_sessions(self.realm,
                                                                self.site)
                self.old_sessions = x
            except Exception as e:
                msg = str(e)
                self.logger.critical(msg)
                self.cleanup()
                raise AuthFailed(msg)

            if self.old_sessions:
                replace_sessions = []
                for session_id in self.old_sessions:
                    _slp = self.old_sessions[session_id]
                    replace_sessions.append(_slp)
                # Add old sessions we want to be logged out with this login request.
                if replace_sessions:
                    command_args['replace_sessions'] = replace_sessions

            # Encryption type for offline data (e.g. offline tokens).
            command_args['client_offline_enc_type'] = self._offline_token.enc_type

            # Generate DH stuff used to calculate RSP.
            if config.debug_level(DEBUG_SLOT) > 3:
                self.logger.debug("Generating DH key for RSP.")

            self.rsp_ecdh_key = ECKey()
            self.rsp_ecdh_key.gen_key(curve=self.ecdh_curve)
            command_args['rsp_ecdh_client_pub'] = self.rsp_ecdh_key.export_public_key()

        # Set password to use for authentication.
        if self.password:
            password = self.password
        elif self.reneg:
            rsp_hash = otpme_pass.gen_one_iter_hash(self.username,
                                            self.rsp,
                                            hash_type=self.rsp_hash_type)
            srotp, reneg_salt, self.new_rsp = sotp.gen(reneg=True,
                                                rsp_hash_type=self.rsp_hash_type,
                                                password_hash=rsp_hash)
            command_args['reneg'] = True
            command_args['reneg_salt'] = reneg_salt
            command_args['rsp_hash_type'] = self.rsp_hash_type
            password = srotp
        elif self.rsp:
            rsp_hash = otpme_pass.gen_one_iter_hash(self.username,
                                            self.rsp,
                                            hash_type=self.rsp_hash_type)
            password = sotp.gen(password_hash=rsp_hash,
                            rsp_hash_type=self.rsp_hash_type)
        elif self.srp:
            password = self.srp
        elif self.slp:
            password = self.slp
        else:
            password = None

        # Check if we can do SSH authentication.
        if self.use_ssh_agent:
            agent_keys = []
            public_keys = []

            if config.debug_level(DEBUG_SLOT) > 0:
                self.logger.debug("Trying to get keys from ssh-agent...")
            try:
                self.ssh_agent_conn = Agent()
                agent_keys = self.ssh_agent_conn.get_keys()
                self.ssh_agent_conn.close()
            except Exception as e:
                if self.use_ssh_agent is True:
                    self.cleanup()
                    raise AuthFailed(_("Unable to connect to ssh-agent: %s")
                                        % e)
                else:
                    self.use_ssh_agent = False

            ssh_key_count = len(agent_keys)
            if config.debug_level(DEBUG_SLOT) > 0:
                self.logger.debug("Got '%s' keys from ssh-agent." % ssh_key_count)

            if ssh_key_count == 0:
                if self.use_ssh_agent is True:
                    self.cleanup()
                    raise AuthFailed("Unable to get keys from ssh-agent.")
                else:
                    self.use_ssh_agent = False
            else:
                self.use_ssh_agent = True

        if self.auth_type is None:
            if self.use_smartcard:
                self.auth_type = "smartcard"
        if self.auth_type is None:
            if self.jwt_auth:
                self.auth_type = "jwt"
        if self.auth_type is None:
            self.auth_type = "clear-text"
        # If we got SSH keys from agent try SSH authentication.
        if self.use_ssh_agent:
            for key in agent_keys:
                public_key = key.get_base64()
                public_keys.append(public_key)
            if self.auth_type is None:
                self.auth_type = "ssh"
            # Set command args.
            command_args['public_keys'] = public_keys

        # Add JWT to do redirected authentication.
        elif self.jwt:
            command_args['redirect_response'] = self.jwt

        # Last but not least we can try OTP/password authentication.
        else:
            command_args['password'] = password

        command_args['auth_type'] = self.auth_type

        # Build auth command.
        if self.login:
            command = "auth_login"
            command_args['username'] = self.username
            command_args['rsp_hash_type'] = self.rsp_hash_type
        elif self.unlock:
            command = "auth_unlock"
            command_args['username'] = self.username
        elif self.logout:
            command = "auth_logout"
            command_args['username'] = self.username
        else:
            command = "do_auth"
            command_args['username'] = self.username
            command_args['client'] = self.client

        # Gen JWT challenge if needed.
        if self.request_jwt:
            if not self.jwt_challenge and not self.logout:
                self.jwt_challenge = stuff.gen_secret(len=32)
            # Add JWT challenge to request.
            command_args['jwt_challenge'] = self.jwt_challenge

        # Log request.
        if self.realm and self.site:
            req_dst = ("%s/%s (%s)"
                    % (self.realm, self.site,
                    self.connection.daemon))
        else:
            req_dst = "%s" % self.socket_uri

        req_type = "authentication"
        log_method = self.logger.info
        if self.login:
            req_type = "login"
        if self.logout:
            req_type = "logout"
        if self.srp:
            req_type = "session refresh"
            log_method = self.logger.debug
        if self.reneg:
            req_type = "session reneg"
            log_method = self.logger.debug

        log_method("Sending %s request: %s" % (req_type, req_dst))

        # Send auth command to daemon.
        status, \
        status_code, \
        response = self.connection.send(command, command_args, handle_auth=False)

        if self.endpoint and not self.print_messages:
            try:
                response = response[0]
            except:
                self.cleanup()
                msg = "Malformed auth response."
                raise OTPmeException(msg)

        if not status:
            raise OTPmeException(_("Error: %s") % response)

        try:
            response_type = response['type']
        except:
            self.cleanup()
            raise OTPmeException("Malformed auth response: Missing response type")

        if self.login:
            if config.debug_level(DEBUG_SLOT) > 0:
                self.logger.debug("Received login response from authd...")
        elif self.logout:
            if config.debug_level(DEBUG_SLOT) > 0:
                self.logger.debug("Received logout response from authd...")
        else:
            if config.debug_level(DEBUG_SLOT) > 0:
                self.logger.debug("Received auth response from authd...")

        # Set auth response.
        self.auth_reply = response

        # Verify auth type.
        if response_type != "auth":
            self.cleanup()
            msg = (_("Got wrong auth response type: %s") % response_type)
            raise OTPmeException(msg)

        # Try to get auth message from response.
        try:
            reply_message = self.auth_reply['message']
        except:
            self.cleanup()
            msg = (_("Malformed auth response: Missing response message"))
            raise OTPmeException(msg)

        # Try to get auth status from response.
        try:
            auth_status = self.auth_reply['status']
        except:
            self.cleanup()
            msg = (_("Malformed auth response: Missing response status"))
            raise OTPmeException(msg)

        if auth_status:
            # Verify JWT.
            if self.verify_jwt:
                try:
                    self._verify_jwt(self.auth_reply)
                except Exception as e:
                    msg = str(e)
                    self.logger.debug(msg)
                    self.cleanup()
                    raise AuthFailed(msg)
                if config.debug_level(DEBUG_SLOT) > 0:
                    self.logger.debug("JWT verification successful.")

            # Add SSH private key to agent.
            if 'ssh_private_key' in self.auth_reply:
                ssh_private_key = self.auth_reply['ssh_private_key']
            else:
                ssh_private_key = None

            if ssh_private_key:
                if config.debug_level(DEBUG_SLOT) > 0:
                    self.logger.debug("Adding SSH key to agent...")
                try:
                    ssh.add_agent_key(ssh_private_key)
                except Exception as e:
                    msg = (_("Unable to add key to SSH agent: %s") % e)
                    self.logger.warning(msg)

            # Remove old login sessions we logged out with this login request.
            if self.old_sessions:
                for x in self.old_sessions:
                    try:
                        self._offline_token.remove_session(x, force=True)
                    except NoOfflineSessionFound as e:
                        if config.debug_level(DEBUG_SLOT) > 0:
                            self.logger.debug(str(e))
                    except Exception as e:
                        msg = ("Error removing old session: %s" % x)
                        self.logged.critical(msg)

            # Set response message.
            if self.login:
                auth_message = (_("Realm login successful: %s: %s")
                                % (req_dst, reply_message))
            else:
                auth_message = (_("Authentication successful: %s: %s")
                                % (req_dst, reply_message))

            if self.login:
                # Calculate RSP.
                if config.debug_level(DEBUG_SLOT) > 3:
                    self.logger.debug("Generating RSP via ECDH...")
                rsp_ecdh_server_pub = self.auth_reply['ecdh_server_pub']
                server_pubkey = self.rsp_ecdh_key.load_public_key(rsp_ecdh_server_pub)
                dh_secret = self.rsp_ecdh_key.dhexchange(server_pubkey)
                self.rsp = sotp.derive_rsp(secret=dh_secret,
                                    hash_type=self.rsp_hash_type,
                                    salt=rsp_ecdh_server_pub)

            # If this is a realm login try to get offline tokens etc. from
            # response.
            if self.add_login_session:
                # Try to get session timeouts from auth response.
                try:
                    session_timeout = self.auth_reply['timeout']
                except:
                    self.cleanup()
                    msg = (_("Malformed auth response: Missing session timeout"))
                    raise OTPmeException(msg)
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Got session timeout from auth response: %s"
                            % session_timeout)
                    self.logger.debug(msg)
                try:
                    session_unused_timeout = self.auth_reply['unused_timeout']
                except:
                    self.cleanup()
                    msg = (_("Malformed auth response: Missing unused "
                            "session timeout"))
                    raise OTPmeException(msg)
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Got session unused timeout from auth response: %s"
                            % session_unused_timeout)
                    self.logger.debug(msg)

                offline_tokens = self.auth_reply['offline_tokens']
                if offline_tokens:
                    # Get offline session key (e.g. to be forwarded on login redirect).
                    self._offline_token.gen_session_key()
                    #self.offline_session_key = self._offline_token.session_key_public
                    self.offline_session_key = self._offline_token.session_key_private

                # Get SLP for this session.
                slp = self.auth_reply['slp']
                # Add login session to agent, handle offline tokens etc.
                self._add_login_session(slp)

            elif self.reneg:
                if reply_message == "AUTH_SESSION_RENEG_START":
                    # Send second auth request with new RSP to finish
                    # renegotiation.
                    command_args['password'] = self.new_rsp
                    status, \
                    status_code, \
                    response = self.connection.send(command=command,
                                                command_args=command_args,
                                                handle_response=False,
                                                handle_auth=False)
                    # Try to decode reneg response.
                    try:
                        reneg_reply = response
                        reply_message = reneg_reply['message']
                    except Exception as e:
                        reneg_reply = None
                        reply_message = "Invalid reneg reply."
                        msg = ("%s: %s" % (reply_message, e))
                        self.logger.critical(msg)

                    # Verify JWT.
                    if self.verify_jwt and reneg_reply:
                        try:
                            self._verify_jwt(reneg_reply)
                        except Exception as e:
                            msg = str(e)
                            self.logger.warning(msg)
                            self.cleanup()
                            raise AuthFailed(msg)

                    if reply_message == "AUTH_SESSION_RENEG_DONE":
                        auth_message = "Session renegotiation successful."
                        reneg_status = True
                    else:
                        reneg_status = False
                else:
                    reneg_status = False
                    reply_message = (_("Unknown reneg reply: %s")
                                    % reply_message)
                if not reneg_status:
                    msg = (_("Session renegotiation failed: %s")
                            % reply_message)
                    self.cleanup()
                    raise RenegFailed(msg)
            else:
                # Run cleanup after successful authentication.
                self.cleanup()
        else:
            # Run cleanup after failed authentication.
            self.cleanup()
            if self.login:
                msg = (_("Login failed for user %s: %s")
                        % (self.username, reply_message))
                raise AuthFailed(msg)
            elif self.logout:
                if reply_message != "REALM_LOGOUT_OK":
                    msg = (_("Logout failed: %s") % reply_message)
                    raise LogoutFailed(msg)
                auth_message = "Successfully logged out."
            elif self.reneg:
                # To prevent otpme-agent from removing offline sessions when
                # access was denied by a policy (e.g. login times) we raise no
                # AuthFailed() exception.
                if reply_message == "AUTH_DENIED_BY_POLICY":
                    msg = (_("Session renegotiation denied by policy: %s")
                            % reply_message)
                    raise OTPmeException(msg)
                else:
                    msg = (_("Session renegotiation failed: %s")
                            % reply_message)
                    raise AuthFailed(msg)
            elif self.rsp:
                msg = (_("Authentication failed: %s") % reply_message)
                raise AuthFailed(msg)
            elif self.srp:
                if reply_message != "AUTH_SESSION_REFRESH":
                    msg = (_("Session refresh failed: %s") % reply_message)
                    raise RefreshFailed(msg)
                auth_message = "Session refresh successful."
            else:
                msg = (_("Authentication failed for user %s: %s")
                        % (self.username, reply_message))
                raise AuthFailed(msg)

        log_method(auth_message)

        return auth_message

    def authenticate_host(self):
        """ Authenticate host/node with daemon. """
        host_fqdn = config.host_data['fqdn']

        # Try to get peer we are connected to.
        if not self.connection.peer_cn:
            msg = (_("Unable to do host authentication without peer cert."))
            self.cleanup()
            raise OTPmeException(msg)

        # Try to get peer we are connected to.
        self.peer = self.get_peer_from_cert()

        # Load our host.
        host_type = config.host_data['type']
        my_host = backend.get_object(object_type=host_type,
                                        uuid=config.uuid)
        # Generate server challenge.
        server_challenge = my_host.gen_challenge()

        command_args = {
                        'host_fqdn'         : host_fqdn,
                        'server_challenge'  : server_challenge,
                    }

        # Build auth command.
        command = "auth_host"

        status, \
        status_code, \
        response = self.connection.send(command=command,
                                command_args=command_args,
                                handle_response=False,
                                handle_auth=False)

        if status_code != status_codes.OK:
            msg = (_("Auth command failed: %s") % response)
            self.cleanup()
            raise AuthFailed(msg)

        try:
            client_challenge = response['client_challenge']
        except:
            msg = (_("Missing client challenge in auth response: %s")
                    % response)
            self.cleanup()
            raise AuthFailed(msg)

        try:
            server_response = response['server_response']
        except:
            msg = (_("Missing server response in auth response: %s")
                    % response)
            self.cleanup()
            raise AuthFailed(msg)

        # Verify server response.
        try:
            status = self.peer.verify_challenge(server_challenge,
                                                server_response)
        except Exception as e:
            msg = (_("Error verifying server response: %s") % e)
            self.cleanup()
            raise OTPmeException(msg)

        if not status:
            msg = (_("Failed to verify server response."))
            self.cleanup()
            raise AuthFailed(msg)

        # Sign client challenge.
        try:
            client_response = my_host.sign_challenge(client_challenge)
        except Exception as e:
            msg = (_("Error signing client challenge: %s") % e)
            self.cleanup()
            raise OTPmeException(msg)

        command_args = {
                        'client_response'  : client_response,
                    }

        # Send client response.
        status, \
        status_code, \
        response = self.connection.send(command=command,
                                    command_args=command_args,
                                    handle_response=False,
                                    handle_auth=False)

        if status_code != status_codes.OK:
            msg = (_("Auth command failed: %s") % response)
            self.cleanup()
            raise AuthFailed(msg)

        peer_type = self.peer.type[0].upper() + self.peer.type[1:].lower()
        response = (_("%s response verification successful: %s")
                                % (peer_type, self.peer.fqdn))
        if config.debug_level(DEBUG_SLOT) > 3:
            self.logger.debug(response)

        return response

    def _add_login_session(self, slp):
        """ Create login session file and add RSP to otpme-agent. """
        # Indicates if we have to cache offline tokens.
        cache_offline_tokens = False

        # Set login token to otpme-agent.
        login_token = self.auth_reply['login_token']
        login_pass_type = self.auth_reply['login_pass_type']
        try:
            self.agent_conn.set_login_token(login_token, login_pass_type)
        except Exception as e:
            msg = ("Error setting login token to otpme-agent: %s" % e)
            self.logger.critical(msg)

        # Get auth reply values.
        login_time = self.auth_reply['login_time']
        session_uuid = self.auth_reply['session']
        session_timeout = self.auth_reply['timeout']
        session_unused_timeout = self.auth_reply['unused_timeout']
        keep_offline_session = self.auth_reply['keep_session']

        # Do not add offline token on temp pass authentication.
        temp_pass_auth = self.auth_reply['temp_pass_auth']

        # Check for offline tokens if requested.
        if self.cache_login_tokens and not temp_pass_auth:
            # Get offline tokens from auth reply.
            offline_tokens = self.auth_reply['offline_tokens']
            login_token_uuid = self.auth_reply['login_token_uuid']
            if offline_tokens:
                self.logger.info("Caching of login tokens enabled and offline "
                                "tokens received.")
                cache_offline_tokens = True
                # Initialize offline token.
                self._offline_token.init()
                # Acquire offline token lock.
                self._offline_token.lock()

        # Clear old offline tokens.
        if cache_offline_tokens:
            try:
                self._offline_token.clear()
            except Exception as e:
                msg = ("Error clearing cached offline tokens: %s" % e)
                self.logger.critical(msg)
                cache_offline_tokens = False
                keep_offline_session = False

            # Set login token before adding/decoding offline tokens. This is
            # required to get second factor tokens loaded.
            self._offline_token.set_login_token(login_token_uuid, session_uuid)

        # Decode offline tokens.
        if cache_offline_tokens:
            try:
                token_instances = self.decode_offline_token(login_token_uuid,
                                                            offline_tokens)
            except Exception as e:
                msg = ("Error decoding offline token: %s" % e)
                self.logger.critical(msg, exc_info=True)
                cache_offline_tokens = False
                keep_offline_session = False
                config.raise_exception()

        # Load session key.
        try:
            key = RSAKey(key=self.offline_session_key)
        except Exception as e:
            msg = (_("Failed to load offline session key: %s") % e)
            raise OTPmeException(msg)

        # Sign RSP to be verified by otpme-agent.
        rsp_signature = key.sign(self.rsp, encoding="hex")

        # Add RSP to otpme-agent.
        agent_conn = connections.get("agent",
                        user=self.otpme_agent_user)
        try:
            agent_conn.add_rsp(realm=self.realm,
                            site=self.site,
                            rsp=self.rsp,
                            slp=slp,
                            rsp_signature=rsp_signature,
                            session_key=self.offline_session_key,
                            login_time=login_time,
                            timeout=session_timeout,
                            unused_timeout=session_unused_timeout,
                            offline=keep_offline_session)
        except Exception as e:
            msg = ("Error adding RSP to otpme-agent: %s" % e)
            self.logger.critical(msg)

        # Create offline session file.
        if keep_offline_session and (cache_offline_tokens or self.offline_session_key):
            # Save RSP to disk. This will be used to add a session to
            # otpme-agent when doing offline logins and to logout an old
            # session (via SLP) when doing a normal login.
            try:
                self._offline_token.save_rsp(session_id=self.login_session_id,
                                realm=self.realm,
                                site=self.site,
                                rsp=self.rsp,
                                login_time=login_time,
                                session_uuid=session_uuid,
                                session_timeout=session_timeout,
                                session_unused_timeout=session_unused_timeout,
                                offline_session=keep_offline_session,
                                offline_tokens=cache_offline_tokens,
                                session_key=self.offline_session_key)
            except Exception as e:
                msg = ("Error saving RSP: %s" % e)
                self.logger.critical(msg)

        # Handle offline tokens and save user scripts.
        if cache_offline_tokens:
            # Save users SSH/GPG agent script to disk.
            try:
                self._offline_token.save_script(script_id="ssh-agent",
                                    script=self.ssh_agent_script,
                                    script_uuid=self.ssh_agent_script_uuid,
                                    script_path=self.ssh_agent_script_path,
                                    script_options=self.ssh_agent_script_opts,
                                    script_signs=self.ssh_agent_script_signs)
            except Exception as e:
                msg = ("Error saving agent script: %s" % e)
                self.logger.warning(msg)

            # Save users key script to disk.
            try:
                key_script = self.auth_reply['key_script']
                key_script_uuid = self.auth_reply['key_script_uuid']
                key_script_path = self.auth_reply['key_script_path']
                key_script_opts = self.auth_reply['key_script_opts']
                key_script_signs = self.auth_reply['key_script_signs']
            except:
                key_script = None
                config.raise_exception()
                msg = "Invalid auth reply: Failed to get key script"
                self.logger.warning(msg)

            if key_script:
                # Verify key script at login time to prevent signature
                # verification issues when being offline.
                try:
                    stuff.verify_key_script(username=self.username,
                                        key_script=key_script,
                                        key_script_path=key_script_path,
                                        signatures=key_script_signs)
                    verify_status = True
                except Exception as e:
                    self.logger.warning("Error verifying key script: %s" % e)
                    verify_status = False

                if verify_status:
                    try:
                        self._offline_token.save_script(script_id="key",
                                            script=key_script,
                                            script_uuid=key_script_uuid,
                                            script_path=key_script_path,
                                            script_options=key_script_opts,
                                            script_signs=key_script_signs)
                    except Exception as e:
                        msg = ("Error saving key script: %s" % e)
                        self.logger.warning(msg)

            # Save users login script to disk.
            try:
                login_script = self.auth_reply['login_script']
                login_script_uuid = self.auth_reply['login_script_uuid']
                login_script_path = self.auth_reply['login_script_path']
                login_script_opts = self.auth_reply['login_script_opts']
                login_script_signs = self.auth_reply['login_script_signs']
            except:
                login_script = None
                config.raise_exception()
                msg = "Invalid auth reply: Failed to get login script"
                self.logger.warning(msg)

            if login_script:
                try:
                    self._offline_token.save_script(script_id="login",
                                        script=login_script,
                                        script_uuid=login_script_uuid,
                                        script_path=login_script_path,
                                        script_options=login_script_opts,
                                        script_signs=login_script_signs)
                except Exception as e:
                    msg = ("Error saving login script: %s" % e)
                    self.logger.warning(msg)

            # Cache offline tokens.
            try:
                self.handle_offline_token(token_instances, session_uuid)
            except Exception as e:
                msg = ("Error caching offline tokens: %s" % e)
                self.logger.critical(msg, exc_info=True)

        # Release offline token lock
        self._offline_token.unlock()

        if self.interactive:
            return

        # Stop agent connections etc.
        self.cleanup()
        # Handle multiprocessing stuff.
        multiprocessing.cleanup()

    def decode_offline_token(self, login_token_uuid, offline_tokens):
        """ Decode offline token from auth reply. """
        token_instances = {}
        login_token = None
        need_encryption = False

        # Decode offline token.
        for object_config in offline_tokens:
            token_oid = object_config['OID']
            token_oid = oid.get(object_id=token_oid)
            object_config.pop('OID')

            # Check if one of the offline tokens needs to be encrypted.
            if not need_encryption:
                try:
                    need_encryption = object_config['NEED_OFFLINE_ENCRYPTION']
                except:
                    # If token config is missing encryption setting set default.
                    need_encryption = True

            # Add token config to offline tokens.
            self._offline_token.add(object_id=token_oid,
                                    object_config=object_config)

        offline_tokens = self._offline_token.get()
        for token_uuid in offline_tokens:
            # Get token instance.
            instance = offline_tokens[token_uuid]

            msg = "Loaded offline token: %s" % instance.oid
            self.logger.info(msg)

            if instance.uuid == login_token_uuid:
                login_token = instance
                token_instances['login_token'] = instance
            else:
                token_instances[instance.uuid] = instance

        if not login_token:
            raise OTPmeException("Unable to get login token from response.")

        # Enable offline token encryption if needed.
        if need_encryption:
            self._offline_token.need_encryption = True

        # FIXME: maybe we want to add a policy that denies saving
        #        of unencrypted session keys (e.g. for notebooks)!?!!
        # Check if login token has session keeping enabled.
        if login_token.keep_session:
            self._offline_token.keep_session = True

        return token_instances

    def handle_offline_token(self, offline_tokens, session_uuid):
        """ Remove old offline tokens and add new ones if needed. """
        from paramiko.agent import Agent
        enc_pass = None
        enc_challenge = None

        # Set key to encrypt used OTPs/token counters.
        offline_data_key = self.auth_reply['offline_data_key']
        self._offline_token.offline_data_key = offline_data_key

        try:
            login_token = offline_tokens['login_token']
        except:
            raise OTPmeException("Need login token to cache offline tokens.")

        # Make sure we use destination token for linked tokens.
        if login_token.destination_token:
            try:
                verify_token = offline_tokens[login_token.destination_token]
            except:
                msg = (_("Unable to find destination token: %s")
                        % login_token.destination_token)
                raise OTPmeException(msg)
        else:
            verify_token = login_token

        sftoken = None
        if verify_token.second_factor_token:
            sftoken = offline_tokens[verify_token.second_factor_token]

        found_smartcard = False
        if verify_token.pass_type == "smartcard":
            found_smartcard = True
        if sftoken and sftoken.pass_type == "smartcard":
            found_smartcard = True

        # Split off password, OTP and PIN.
        result = verify_token.split_password(self.connection.password)
        pin = result['pin']
        static_pass = result['pass']
        # Build static password part from password and PIN if given.
        static_pass_part = static_pass
        if pin:
            static_pass_part += pin

        # Try to get encryption passphrase from token if needed.
        if self._offline_token.need_encryption:
            if found_smartcard:
                enc_challenge = stuff.gen_secret(len=16)
                enc_pass = self.smartcard_client_handler.handle_offline_token_challenge(smartcard=self.smartcard,
                                                                                        password=self.password,
                                                                                        enc_challenge=enc_challenge)
            if not enc_pass:
                if verify_token.pass_type == "static":
                    enc_pass = static_pass_part

                elif verify_token.pass_type == "otp":
                    if not verify_token.pin_enabled:
                        msg = (_("One of the offline tokens requires "
                                "encryption but the login token '%s' "
                                "does not support it.")
                                % login_token.rel_path)
                        raise OTPmeException(msg)
                    # Set encryption passphrase to static part of the password.
                    enc_pass = static_pass_part

                elif verify_token.pass_type == "ssh_key":
                    # Try to get SSH private key.
                    try:
                        ssh_private_key = self.auth_reply['ssh_private_key']
                    except:
                        ssh_private_key = None

                    if ssh_private_key:
                        enc_pass = static_pass_part
                    else:
                        # Get SSH public key from login token.
                        login_key = verify_token.ssh_public_key
                        # Derive AES key to encrypt offline
                        # tokens using users/tokens SSH key.
                        enc_challenge = stuff.gen_secret(len=16)
                        # Open new ssh-agent connection. When re-using
                        # connection from parent process we get "error
                        # accessing card: Conflicting use"
                        try:
                            self.ssh_agent_conn = Agent()
                        except Exception as e:
                            msg = (_("Unable to get ssh-agent connection: %s") % e)
                            raise OTPmeException(msg)

                        agent_keys = self.ssh_agent_conn.get_keys()
                        for key in agent_keys:
                            if login_key == key.get_base64():
                                # Derive AES passphrase from challenge+static_pass_part
                                # using ssh-agent signing.
                                # https://github.com/paramiko/paramiko/issues/507
                                try:
                                    ssh_challenge = "%s%s" % (enc_challenge,
                                                            static_pass_part)
                                    ssh_response = key.sign_ssh_data(ssh_challenge)
                                    sha256 = hashlib.sha512(ssh_response)
                                    enc_pass = sha256.hexdigest()
                                except Exception as e:
                                    msg = (_("Error signing challenge for "
                                            "offline token caching via "
                                            "ssh-agent: %s") % e)
                                    raise OTPmeException(msg)
                                break
                        # Close ssh-agent connection
                        self.ssh_agent_conn.close()

                else:
                    msg = (_("Unable to generate AES key for token offline "
                            "caching from token '%s': Unsupported token type: %s")
                            % (verify_token.rel_path, verify_token.token_type))
                    raise OTPmeException(msg)

            # Finally set offline token encryption passphrase.
            self._offline_token.set_enc_passphrase(passphrase=enc_pass,
                                key_function=self.offline_key_derivation_func,
                                key_function_opts=self.offline_key_func_opts,
                                iterations_by_score=self.offline_iterations_by_score,
                                check_pass_strength=self.check_offline_pass_strength,
                                challenge=enc_challenge)
            del enc_pass
            del static_pass_part

        # Save offline tokens to disk. We do this after we have set the
        # encryption passphrase above.
        self._offline_token.save()

        # Trigger OTP/counter sync (e.g. push current HOTP counter to server)
        if self.sync_token_data:
            hostd_conn = self.get_hostd_conn()
            hostd_conn.trigger_token_data_sync()
