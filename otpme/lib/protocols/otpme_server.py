# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import signal
import functools
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import jwt
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
#from otpme.lib import encryption
from otpme.lib import multiprocessing
from otpme.lib.pki.utils import check_crl
from otpme.lib.encryption.ec import ECKey
from otpme.lib.encoding.base import decode
from otpme.lib.protocols import status_codes
#from otpme.lib.protocols.utils import scauth
from otpme.lib.protocols.utils import sshauth
from otpme.lib.protocols.utils import passauth
from otpme.lib.protocols.request import decode_request
from otpme.lib.protocols.response import build_response
from otpme.lib.daemon.clusterd import check_cluster_status

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.encryption.fernet",
                "otpme.lib.encryption.hkdf",
                "otpme.lib.encryption.ec",
                "otpme.lib.encoding.base",
                #"otpme.lib.compression.base",
                "otpme.lib.sotp",
                ]

def register():
    register_config()

def register_config():
    """ Register config stuff. """
    config.register_config_var("server_protocol", str, None)

class OTPmeServer1(object):
    """
    Generic OTPme server protocol class that handles authentication of user,
    node or host
    """
    def __init__(self, client=None, peer_cert=None,
        comm_handler=None, connection=None, **kwargs):
        # Our client connection.
        self.connection = connection
        # Marks connection as new.
        self.new_connection = True

        # Get queues to communicate with daemon main process..
        self.comm_handler = comm_handler

        if config.use_api:
            client = "API"

        if not client:
            raise OTPmeException("Need 'client'.")

        # Set server protocol (e.g. check_rapi_opts()).
        config.server_protocol = self.protocol

        # User we authenticate.
        try:
            self.user
        except:
            self.user = None

        # The access group we authenticate users against.
        try:
            self.access_group
        except:
            self.access_group = None

        # Indicates that we need to negotiate session key via DH.
        try:
            self.encrypt_session
        except:
            self.encrypt_session = True

        # Indicates that we need to check for a valid client cert.
        try:
            self.require_client_cert
        except:
            self.require_client_cert = True

        try:
            self.verify_host
        except:
            self.verify_host = True
        try:
            self.require_master_node
        except:
            self.require_master_node = True

        try:
            self.require_cluster_status
        except:
            self.require_cluster_status = True

        try:
            self.allow_sotp_reuse
        except:
            self.allow_sotp_reuse = False

        self.session_reneg = False

        # Client infos.
        self.client = client
        self.client_name = client
        # Get process infos from unix socket client.
        if self.client.startswith("socket://"):
            self.client_proc = re.sub('^socket://([^:]*):([^:]*):([^:]*):([^:]*)$', r'\1',
                                    self.client)
            self.client_pid = re.sub('^socket://([^:]*):([^:]*):([^:]*):([^:]*)$', r'\2',
                                    self.client)
            self.client_user = re.sub('^socket://([^:]*):([^:]*):([^:]*):([^:]*)$', r'\3',
                                    self.client)
            self.require_preauth = False
            self.encrypt_session = False
            self.require_client_cert = False

        self.peer_cert = peer_cert
        self.client_cn = None
        self.token = None
        self.token_challenges = {}
        self.redirect_challenge = None
        self.preauth_status = None
        self._sign_key = None

        # Reconfigure logger to add new PID.
        self.logger = config.setup_logger(banner=config.log_name, pid=True,
                                        existing_logger=config.logger)
        if config.use_api:
            # No preauth in API mode.
            self.preauth_status = True
            # No encryption in API mode
            self.encrypt_session = False

        # Make sure we got a client certificate.
        if self.require_client_cert and not self.peer_cert:
            # Unix sockets do not use SSL.
            if not self.client.startswith("socket://") \
            and not config.use_api:
                msg = (_("Client does not offer a certificate: %s")
                        % self.client)
                raise CertVerifyFailed(msg)

        # Some env infos.
        self.proctitle = None
        self.host_type = None
        self.host_name = None
        self.host_realm = None
        self.host_site = None
        self.host_fqdn = None
        self._site_cert = None
        self._my_host = None

        # Infos about authenticated client (user, node, host ...)
        self.authenticated = False
        self.username = None
        self.peer_challenge = None
        self.session_key = None
        self.can_encrypt = False
        self.ecdh_curve = "SECP384R1"
        # Try to load encryption module.
        try:
            self.session_enc_mod = config.get_encryption_module("FERNET")
        except Exception as e:
            msg = "Failed to load session encryption: %s" % e
            raise OTPmeException(msg)
        self.session_key_hash_type = "HKDF"
        self.session_key_hash_algo = "SHA256"
        self.peer = None
        self.smartcard_handlers = {}
        self.compresss_response = True

    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        # Close our connection.
        self.connection.close()
        # Handle multiprocessing cleanup().
        multiprocessing.cleanup()
        # Call protocol handler close().
        self.close()
        os._exit(0)

    @property
    def site_key(self):
        """ Load JWT signing key. """
        if self._sign_key is not None:
            site_key = self._sign_key
        else:
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            site_key = my_site._key
            self._sign_key = site_key
        return site_key

    def init(self):
        """ Init the server (e.g. verify client certificate). """
        # Set our signal handler before pre init to allow the
        # protocol handler to set its own.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        # Call child class method.
        self._pre_init()

        # Check client certificate.
        if self.peer_cert:
            # Get certs common name.
            self.client_cn = self.peer_cert['cn']
            self.client_name = self.client_cn
            # Verify certificate.
            cert_issuer = self.peer_cert['issuer']
            cert_serial = self.peer_cert['serial_number']
            result = backend.search(object_type="ca",
                                    attribute="path",
                                    value=cert_issuer,
                                    return_type="instance")
            if not result:
                msg = (_("Client certificated issued by "
                        "unknown CA: %s: %s")
                        % (cert_issuer, self.client_cn))
                raise CertVerifyFailed(msg)

            issuer_ca = result[0]
            try:
                cert_revoked = check_crl(issuer_ca.crl, cert_serial)
            except Exception as e:
                msg = "Error checking CRL %s: %s" % (issuer_ca, e)
                self.logger.critical(msg, exc_info=True)
                raise
            if cert_revoked:
                msg = (_("Certificate revoked by "
                        "CA: %s: %s")
                        % (cert_issuer, self.client_cn))
                raise CertVerifyFailed(msg)

            if not self.client.startswith("socket://") \
            and not self.client_cn \
            and not config.use_api:
                msg = (_("Client certificate does not offer a "
                        "common name: %s") % self.client)
                raise CertVerifyFailed(msg)

        # Set host stuff.
        try:
            self.host_type = config.host_data['type']
            self.host_name = config.host_data['name']
            self.host_realm = config.host_data['realm']
            self.host_site = config.host_data['site']
            self.host_fqdn = "%s.%s.%s" % (self.host_name,
                                            self.host_site,
                                            self.host_realm)
        except:
            if config.realm and not config.use_api:
                msg = ("Missing host data (e.g. realm/site).")
                raise OTPmeException(msg)

        # Save proctitle for later use (e.g. when user is authenticated).
        self.proctitle = setproctitle.getproctitle()

        # Call child class method.
        self._post_init()

    def _send_daemon_msg(self, daemon, command,
        data=None, timeout=None, autoclose=False):
        """ Send message to main daemon process. """
        if config.use_api:
            return
        self.comm_handler.send(recipient=daemon,
                                command=command,
                                data=data,
                                timeout=timeout,
                                autoclose=autoclose)

    def close(self):
        """ Handle connection close. """
        # Call child class method.
        self._close()

    def send(self, command, **kwargs):
        """
        Just an alias for interoperability when using this class as replacement
        for a real connection.
        """
        return self.process(command)

    def recv(self, **kwargs):
        """
        Just an alias for interoperability when using this class as replacement
        for a real connection.
        """
        # Just return the last response.
        return self.last_response

    def _pre_init(self, *args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _post_init(self, *args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _close(self, *args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _start_processing(self, *args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _stop_processing(self, *args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _start_preauth(self, command, command_args):
        """ Override in protocol handler. """
        pass

    def _preauth_check(self, preauth_args):
        """ Override in protocol handler. """
        pass

    def _end_preauth(self, command, command_args, preauth_result):
        """ Override in protocol handler. """
        pass

    def _start_host_auth(self, command, command_args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _end_host_auth(self, command, command_args, auth_status, auth_reply):
        """ Override in protocol handler. """
        pass

    def _start_user_auth(self, command, command_args, **kwargs):
        """ Override in protocol handler. """
        pass

    def _end_user_auth(self, command, command_args, auth_status, auth_reply):
        """ Override in protocol handler. """
        pass

    def _get_site_cert(self):
        """ Load site certificate. """
        if self._site_cert:
            return self._site_cert
        if config.debug_level() > 3:
            self.logger.debug("Loading site certificate.")
        own_site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)
        self._site_cert = own_site._cert
        return self._site_cert

    def _get_host(self):
        """ Load host object. """
        if self._my_host:
            return self._my_host
        self._my_host = backend.get_object(object_type=self.host_type,
                                            uuid=config.uuid)
        return self._my_host

    def _ident_site(self, ident_challenge):
        """ Identify host/node/site via challenge/response. """
        my_host = self._get_host()
        if my_host.type != "node":
            msg = "Only nodes can process ident site requests."
            raise OTPmeException(msg)
        # Sing challenge with site cert.
        site_cert = self._get_site_cert()
        if config.debug_level() > 3:
            self.logger.debug("Signing ident challenge.")
        try:
            ident_response = site_cert.sign(data=ident_challenge,
                                            encoding="base64")
        except Exception as e:
            config.raise_exception()
            msg = (_("Failed to sign ident challenge: %s") % e)
            raise OTPmeException(msg)
        ident_reply = {}
        ident_reply['site_cert'] = site_cert.cert
        ident_reply['ident_response'] = ident_response
        return ident_reply

    def check_cluster_status(self):
        check_cluster_status()

    def handle_start_stop(method):
        """ Handle calling of _start_processing()/_stop_processing(). """
        def wrapper(self, *args, **kwargs):
            # Run child class pre method.
            self._start_processing(*args, **kwargs)
            # Start original method.
            result = method(self, *args, **kwargs)
            # Run child class post method.
            self._stop_processing(*args, **kwargs)
            return result

        # Update func/method.
        functools.update_wrapper(wrapper, method)
        if not hasattr(wrapper, '__wrapped__'):
            # Python 2.7
            wrapper.__wrapped__ = method

        return wrapper

    @handle_start_stop
    def process(self, data):
        """ Process command. """
        #if len(data) == 0:
        #    msg = ("Client '%s' closed connection." % self.client)
        #    self.logger.warning(msg)
        #    message = "Bye bye..."
        #    raise ClientQuit(message)
        if not config.use_api:
            if config.host_type == "node":
                if self.new_connection:
                    if self.require_master_node:
                        try:
                            current_master_node = multiprocessing.master_node['master']
                        except:
                            current_master_node = None
                        if current_master_node != config.host_data['name']:
                            message = "Please connect to master node."
                            status = status_codes.CLUSTER_NOT_READY
                            return self.build_response(status, message, encrypt=False)
                    if self.require_cluster_status:
                        try:
                            self.check_cluster_status()
                        except Exception as e:
                            message = str(e)
                            status = status_codes.CLUSTER_NOT_READY
                            return self.build_response(status, message, encrypt=False)
                    # Check if host is enabled.
                    result = backend.search(object_type="node",
                                            attribute="uuid",
                                            value=config.uuid,
                                            return_attributes=['uuid', 'enabled'])
                    enabled = result[config.uuid]['enabled'][0]
                    if not enabled:
                        status = status_codes.NO_CLUSTER_SERVICE
                        message = "No cluster serivce on this node."
                        return self.build_response(status, message, encrypt=False)
                    self.new_connection = False

        # Make sure peer is not disabled.
        if self.peer and not self.peer.enabled:
            status = status_codes.HOST_DISABLED
            message = "%s is disabled: %s" % (self.peer.type, self.peer.fqdn)
            #self.logger.warning(message)
            return self.build_response(status, message, encrypt=False)

        enc_key = None
        enc_mod = None

        need_encryption = self.encrypt_session
        if config.use_api:
            need_encryption = False

        if need_encryption:
            enc_key = self.session_key
            enc_mod = self.session_enc_mod

        # Decode request.
        try:
            command, \
            command_args, \
            binary_data = self.decode_request(data,
                                        encryption=enc_mod,
                                        enc_key=enc_key)
        except Exception as e:
            config.raise_exception()
            msg = "Received invalid request: %s" % e
            self.logger.warning(msg)
            raise ServerQuit(msg)

        # Try to get peer object from client cert.
        if self.client_cn and not self.peer and not config.use_api:
            try:
                self.peer = self.get_peer_from_cert()
            except Exception as e:
                config.raise_exception()
                msg = "Unable to get peer from certificate CN: %s" % e
                self.logger.warning(msg)
                raise ServerQuit(msg)

            if not self.peer:
                msg = "Unknown node/host: %s" % self.client_cn
                self.logger.warning(msg)
                raise ServerQuit(msg)
            msg = ("Found valid peer %s: %s" % (self.peer.type, self.peer.name))
            if config.debug_level() > 3:
                self.logger.debug(msg)

        # Allow "quit" also for disabled hosts.
        if command == "quit":
            msg = "Bye bye..."
            raise ClientQuit(msg)

        if command == 'get_proto':
            message = "Using protocol: %s" % self.protocol
            status = True
            return self.build_response(status, message, encrypt=False)

        if command == "ping":
            message = "pong"
            status = True
            return self.build_response(status, message, encrypt=False)

        if command == "ident":
            try:
                ident_challenge = command_args['ident_challenge']
            except:
                message = "Invalid ident request: Challenge missing"
                status = False
                return self.build_response(status, message)
            # Make sure challenge is "bytes".
            ident_challenge = ident_challenge.encode()
            try:
                ident_reply = self._ident_site(ident_challenge)
                ident_status = True
            except Exception as e:
                config.raise_exception()
                message = "Ident command failed: Internal server error"
                msg = ("Error in OTPmeServer1._ident_site(): %s" % e)
                self.logger.critical(msg)
                status = False
                return self.build_response(status, message, encrypt=False)
            return self.build_response(ident_status, ident_reply, encrypt=False)

        if command == "preauth_check":
            msg = ("Processing 'preauth_check' command for client: %s"
                    % self.client_name)
            if config.debug_level() > 3:
                self.logger.debug(msg)
            try:
                self.encrypt_session = command_args['encrypt_session']
            except KeyError:
                self.encrypt_session = False
            try:
                enc_key = command_args['enc_key']
            except KeyError:
                enc_key = None
            try:
                self.session_reneg = command_args['reneg']
            except KeyError:
                pass
            try:
                preauth_request = command_args['preauth_request']
            except KeyError:
                msg = (_("Protocol violation: Missing preauth request"))
                raise ServerQuit(msg)

            # Notify protocol handler about the preauth start.
            try:
                self._start_preauth(command, command_args)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in OTPmeServer1._start_preauth(): %s" % e)
                self.logger.critical(msg)

            # Do preauth.
            preauth_result = self.handle_preauth(preauth_request, enc_key=enc_key)

            # Notify protocol handler about the preauth end.
            try:
                self._end_preauth(command, command_args, preauth_result)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in OTPmeServer1._end_preauth(): %s" % e)
                self.logger.critical(msg)
            # Return result.
            return preauth_result

        # Make sure preauth check was successful.
        if self.require_preauth:
            if self.preauth_status is None:
                msg = "Protocol violation: Preauth check required"
                raise ServerQuit(msg)

            if self.preauth_status is False:
                msg = "Preauth check failed"
                raise ServerQuit(msg)

        # Make sure we have a session key.
        if self.encrypt_session:
            if not self.session_key:
                msg = "Protocol violation: Encryption required"
                raise ServerQuit(msg)

        # Any response below should be encrypted!
        if command == "auth":
            if self.authenticated and self.username:
                message = (_("Successfully authenticated as user '%s'.")
                            % self.username)
                status = True
            else:
                message = "Not authenticated."
                status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if command == "auth_verify":
            message = "Please send auth request with password."
            status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if command == "session_refresh":
            message = "Please send auth request with SRP as password."
            status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if command == "session_reneg":
            self.session_reneg = True
            message = "Please send auth request with SROTP as password."
            status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if command == "logout":
            message = "Please send auth request with SLP as password."
            status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if command == "login":
            if self.authenticated and self.username:
                message = (_("Successfully logged in as user '%s'.")
                            % self.username)
                status = True
            else:
                message = "Not logged in."
                status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if command == "status":
            if self.authenticated and self.username:
                message = (_("Logged in as user '%s'.") % self.username)
                status = True
            elif self.authenticated:
                message = "Authenticated: %s" % self.peer
                status = True
            else:
                if self.require_auth == "user":
                    message = "Not logged in."
                    status = status_codes.NEED_USER_AUTH
                elif self.require_auth == "host":
                    message = "Peer not authenticated."
                    status = status_codes.NEED_HOST_AUTH
                else:
                    message = "No auth required"
                    status = True
            return self.build_response(status, message)

        if command == "auth_host":
            # Notify protocol handler about the host auth start.
            try:
                self._start_host_auth(command, command_args)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in OTPmeServer1._start_host_auth(): %s" % e)
                self.logger.critical(msg)
            # Try to authenticate the host.
            try:
                host_auth_reply = self.authenticate_host(command, command_args)
                auth_status = True
            except Exception as e:
                auth_status = False
                host_auth_reply = str(e)
            # Notify protocol handler about the host auth status.
            try:
                self._end_host_auth(command,
                                    command_args,
                                    auth_status,
                                    host_auth_reply)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in OTPmeServer1._end_host_auth(): %s" % e)
                self.logger.critical(msg)

            return self.build_response(auth_status, host_auth_reply)

        if command == "do_auth" \
        or command == "auth_login" \
        or command == "auth_unlock" \
        or command == "auth_logout":
            # Notify protocol handler about the auth start.
            try:
                self._start_user_auth(command, command_args)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in OTPmeServer1._start_user_auth(): %s" % e)
                self.logger.critical(msg)
            # Try to authenticate the user.
            try:
                user_auth_reply = self.authenticate_user(command, command_args)
                auth_status = True
            except OTPmeException as e:
                message = ("Error authenticating user: %s" % e)
                self.logger.critical(message)
                status = False
                config.raise_exception()
                return self.build_response(status, message, encrypt=False)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in authenticate_user(): %s" % e)
                self.logger.critical(msg)
                auth_status = False
                user_auth_reply = "Internal server error."
            # Notify protocol handler about the auth status.
            try:
                self._end_user_auth(command,
                                    command_args,
                                    auth_status,
                                    user_auth_reply)
            except Exception as e:
                config.raise_exception()
                msg = ("Error in OTPmeServer1._end_user_auth(): %s" % e)
                self.logger.critical(msg)

            return self.build_response(auth_status, user_auth_reply)

        # If we found no command to handle pass it on to our child class.
        try:
            response = self._process(command=command,
                                    command_args=command_args,
                                    binary_data=binary_data)
        except Exception as e:
            config.raise_exception()
            msg = ("Error in OTPmeServer1._process(): %s" % e)
            self.logger.critical(msg)
            message = "Internal server error."
            status = False
            response = self.build_response(status, message)
        return response

    def handle_preauth(self, preauth_request, enc_key=None):
        """ Handle preauth request. """
        enc_mod = None
        if self.encrypt_session:
            if enc_key is None:
                status = False
                message = (_("Preauth request misses encryption key."))
                return self.build_response(status, message, encrypt=False)
            # Set encryption mod for reply.
            enc_mod = self.session_enc_mod
            msg = "Decrypting preauth request key..."
            if config.debug_level() > 3:
                self.logger.debug(msg)
            try:
                enc_key = decode(enc_key, "hex")
                enc_key = self.site_key.decrypt(ciphertext=enc_key,
                                                algorithm="SHA256",
                                                cipher='PKCS1_OAEP')
            except Exception as e:
                msg = "Failed to decrypt preauth key: %s: %s" % (self.peer, e)
                self.logger.critical(msg)
                status = False
                message = (_("Failed to decrypt preauth key: %s" % self.peer))
                config.raise_exception()
                return self.build_response(status, message, encrypt=False)

        # Decode/decrypt preauth request.
        if self.encrypt_session:
            msg = "Decrypting preauth request..."
        else:
            msg = "Decoding preauth request..."
        if config.debug_level() > 3:
            self.logger.debug(msg)
        try:
            request = json.decode(preauth_request,
                                encryption=enc_mod,
                                enc_key=enc_key)
        except Exception as e:
            config.raise_exception()
            message = "Unable to decode preauth request: %s" % e
            status = False
            self.logger.warning(message)
            return self.build_response(status, message, encrypt=False)
        try:
            preauth_args = request['command_args']
        except:
            msg = "Received invalid request: Preauth args missing"
            raise OTPmeException(msg)

        # Do preauth check of protocol handler.
        try:
            self._preauth_check(preauth_args)
        except Exception as e:
            message = "Preauth check failed: %s" % e
            status = False
            self.logger.warning(message)
            return self.build_response(status, message, encrypt=False)

        # Get session DH parameter.
        ecdh_client_pub = None
        if self.encrypt_session:
            try:
                ecdh_client_pub = preauth_args['ecdh_client_pub']
            except:
                status = False
                message = (_("Invalid preauth request: Missing DH parameters."))
                return self.build_response(status, message, encrypt=False)

        # Try to get username.
        try:
            username = preauth_args['username']
        except:
            username = None

        if username and self.require_auth == "host":
            status = False
            message = "User authentication not allowed."
            return self.build_response(status, message, encrypt=False)

        # Try to get client name.
        try:
            client = preauth_args['client']
        except:
            client = None
        # Try to get client IP.
        try:
            client_ip = preauth_args['client_ip']
        except:
            client_ip = None

        # Get user.
        if username:
            self.user = backend.get_object(object_type="user",
                                            realm=config.realm,
                                            name=username,
                                            run_policies=True,
                                            _no_func_cache=True)
        # Get accessgroup to auth with.
        if client:
            try:
                self.access_group = self.get_access_group(client=client)
            except Exception as e:
                msg = ("Failed to get accessgroup of client: %s: %s"
                        % (client, e))
                self.logger.warning(msg)
                message = (_("Unable to get client accessgroup: %s" % client))
                status = False
                return self.build_response(status, message, encrypt=False)
        elif client_ip:
            try:
                self.access_group = self.get_access_group(client_ip=client_ip)
            except Exception as e:
                msg = ("Failed to get accessgroup of client: %s: %s"
                        % (client, e))
                self.logger.warning(msg)
                message = (_("Unable to get client accessgroup: %s" % client))
                status = False
                return self.build_response(status, message, encrypt=False)
        elif self.peer:
            try:
                self.access_group = self.get_access_group(host=self.peer.name)
            except Exception as e:
                msg = ("Failed to get accessgroup of host: %s: %s"
                        % (client, e))
                self.logger.warning(msg)
                message = (_("Unable to get host accessgroup: %s" % client))
                status = False
                return self.build_response(status, message, encrypt=False)
        else:
            self.access_group = config.realm_access_group

        # Debug stuff.
        if username and config.debug_enabled:
            # Set debug user e.g. to debug timings.
            config.debug_user = username
            if config.loglevel == "DEBUG":
                # In debug mode its handy to have username included in loglines.
                log_banner = "%s:%s(unauth):" % (config.log_name, username)
                self.logger = config.setup_logger(banner=log_banner,
                                                existing_logger=config.logger,
                                                pid=True)

        # Check if peer wants JWT auth.
        try:
            jwt_auth = preauth_args['jwt_auth']
        except:
            jwt_auth = False
        # Try to get preauth challenge.
        try:
            challenge = preauth_args['preauth_challenge']
        except Exception as e:
            challenge = None
        # Check if this is a login request.
        try:
            login = preauth_args['login']
        except:
            login = False
        # Check if this is a logout request.
        try:
            logout = preauth_args['logout']
        except:
            logout = False
        # Check if this request needs a token.
        try:
            need_token = preauth_args['need_token']
        except:
            need_token = False
        # Build preauth reply.
        try:
            preauth_reply = self.build_preauth_reply(challenge=challenge,
                                ecdh_client_pub=ecdh_client_pub,
                                username=username,
                                need_token=need_token,
                                jwt_auth=jwt_auth,
                                login=login,
                                logout=logout)
            status = True
        except Exception as e:
            config.raise_exception()
            status = False
            message = (_("Failed to build preauth reply."))
            return self.build_response(status, message, encrypt=False)

        # Encode/encrypt preauth reply.
        try:
            preauth_reply = json.encode(preauth_reply,
                                        encryption=enc_mod,
                                        enc_key=enc_key,
                                        encoding="base64")
        except Exception as e:
            config.raise_exception()
            msg = (_("Failed to encrypt preauth reply."))
            raise OTPmeException(msg)

        # Build reply.
        reply = {
                'type'          : 'preauth',
                'preauth_reply' : preauth_reply,
                }

        if config.debug_level() > 3:
            self.logger.debug("Sending preauth reply.")

        # The outer request is sent unencrypted!
        return self.build_response(status, reply, encrypt=False)

    def build_preauth_reply(self, challenge=None, ecdh_client_pub=None,
        username=None, login=False, logout=False,
        jwt_auth=False, need_token=False):
        """ Build preauth reply. """
        # Sign preauth challenge.
        preauth_response = None
        if challenge:
            # Load site certificate.
            site_cert = self._get_site_cert()
            if config.debug_level() > 3:
                self.logger.debug("Signing preauth challenge.")
            try:
                preauth_response = site_cert.sign(data=challenge, encoding="base64")
            except Exception as e:
                config.raise_exception()
                msg = (_("Failed to sign preauth challenge: %s") % e)
                raise OTPmeException(msg)

        ecdh_server_pub_pem =   None
        if self.encrypt_session:
            # Generate session key via DH.
            if config.debug_level() > 3:
                self.logger.debug("Generating session key via DH.")
            try:
                ecdh_key = ECKey()
                ecdh_key.gen_key(curve=self.ecdh_curve)
                ecdh_server_pub_pem = ecdh_key.export_public_key()
                ecdh_client_pub = ecdh_key.load_public_key(ecdh_client_pub)
                ecdh_shared_secret = ecdh_key.dhexchange(ecdh_client_pub)
                # FIXME: Does we get any implications using the server DH public
                #       key as salt?
                session_key = self.session_enc_mod.derive_key(ecdh_shared_secret,
                                                    salt=ecdh_server_pub_pem,
                                                    hash_type=self.session_key_hash_type,
                                                    hash_algo=self.session_key_hash_algo)
                self.session_key = session_key['key']
                self.can_encrypt = True
            except Exception as e:
                config.raise_exception()
                msg = (_("Failed to generate session key via DH: %s") % e)
                raise OTPmeException(msg)

        if not jwt_auth:
            preauth_done = False
            # For host/node preauth we are done here.
            if self.require_auth == "host":
                preauth_done = True
            # If we do not require any authentication we are also done.
            if not self.require_auth:
                preauth_done = True

            if preauth_done:
                self.preauth_status = True
                if not username:
                    preauth_reply = {
                            'realm'                 : config.realm,
                            'site'                  : config.site,
                            'time'                  : time.time(),
                            'status'                : self.preauth_status,
                            'status_message'        : "Host preauth",
                            'preauth_response'      : preauth_response,
                            'ecdh_server_pub'       : ecdh_server_pub_pem,
                            }
                    return preauth_reply

                if self.user:
                    # If user is from an other site we have to do redirected authentication.
                    if self.user.site_uuid != config.site_uuid and not self.session_reneg:
                        user_site = backend.get_object(object_type="site",
                                                    uuid=self.user.site_uuid)
                        if config.site_uuid not in user_site.trusted_sites:
                            msg = ("Redirecting authentication for user from other site: "
                                    "%s/%s/%s" % (self.user.realm, self.user.site, self.user.name))
                            self.logger.debug(msg)
                            preauth_reply = self.gen_jwt_auth_reply(self.user,
                                                            login,
                                                            preauth_response,
                                                            ecdh_server_pub_pem,
                                                            redirect=True)
                            return preauth_reply

        # Check if user exists.
        if username and not self.user:
            self.preauth_status = False
            preauth_reply = {
                    'realm'                 : config.realm,
                    'site'                  : config.site,
                    'time'                  : time.time(),
                    'status'                : self.preauth_status,
                    'status_message'        : "Login failed",
                    'preauth_response'      : preauth_response,
                    'ecdh_server_pub'       : ecdh_server_pub_pem,
                    }
            self.logger.warning("Unknown user: %s" % username)
            return preauth_reply

        if logout:
            self.preauth_status = True
            message = (_("Preauth done for logout request."))
            preauth_reply = {
                    'realm'                 : config.realm,
                    'site'                  : config.site,
                    'time'                  : time.time(),
                    'status'                : self.preauth_status,
                    'status_message'        : message,
                    'preauth_response'      : preauth_response,
                    'ecdh_server_pub'       : ecdh_server_pub_pem,
                    }
            return preauth_reply

        # Check if authentication is disabled.
        if not logout and not self.user.is_admin():
            auth_disabled = False
            # Make sure authentication of our site is not disabled.
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            if not my_site.auth_enabled:
                auth_disabled = True
                status_message = ("Authentication disabled for this site: "
                                    "%s/%s" % (my_site.realm, my_site.name))

            # Make sure authentication with users realm is not disabled.
            if not auth_disabled:
                user_realm = backend.get_object(object_type="realm",
                                                uuid=self.user.realm_uuid)
                if not user_realm.auth_enabled:
                    auth_disabled = True
                    status_message = ("Authentication with realm is disabled: %s"
                                        % (user_realm.name))

            # Make sure authentication with users site is not disabled.
            if not auth_disabled:
                user_site = backend.get_object(object_type="site",
                                            uuid=self.user.site_uuid)
                if not user_site.auth_enabled:
                    auth_disabled = True
                    status_message = ("Authentication with site is disabled: %s/%s"
                                        % (user_site.realm, user_site.name))

            if auth_disabled:
                self.preauth_status = False
                preauth_reply = {
                        'realm'                 : config.realm,
                        'site'                  : config.site,
                        'time'                  : time.time(),
                        'status'                : self.preauth_status,
                        'status_message'        : status_message,
                        'preauth_response'      : preauth_response,
                        'ecdh_server_pub'       : ecdh_server_pub_pem,
                        }
                self.logger.warning(status_message)
                return preauth_reply

        # If peer requested JWT authentication we need to generate a challenge
        # to send in reply.
        if jwt_auth:
            self.logger.debug("Peer wants JWT authentication.")
            preauth_reply = self.gen_jwt_auth_reply(self.user,
                                                    login,
                                                    preauth_response,
                                                    ecdh_server_pub_pem)
            return preauth_reply

        # If we do not need to check for valid user tokens we are done.
        if not need_token:
            self.preauth_status = True
            preauth_reply = {
                    'realm'                 : config.realm,
                    'site'                  : config.site,
                    'time'                  : time.time(),
                    'status'                : self.preauth_status,
                    'status_message'        : "Ready for user authentication",
                    'preauth_response'      : preauth_response,
                    'ecdh_server_pub'       : ecdh_server_pub_pem,
                    'valid_auth_types'      : [],
                    }
            return preauth_reply

        if self.require_auth == "host":
            self.preauth_status = True
            return

        # Get user tokens valid for our access group.
        msg = ("Selecting valid tokens for accessgroup/user: %s/%s"
                % (self.access_group, self.user.name))
        self.logger.debug(msg)

        # Get all valid tokens for the given access group.
        valid_user_tokens = self.get_valid_tokens(user=self.user, login=login)

        # Build dict with possible tokens to authenticate.
        verify_tokens = {}
        for token in valid_user_tokens:
            # Make sure we resolve token links.
            if token.destination_token:
                verify_token = token.get_destination_token()
            else:
                verify_token = token

            # Add token
            verify_tokens[verify_token.uuid] = {
                                            'token' : verify_token,
                                            '2f'    : False,
                                            }

            # Check if a second factor token is enabled.
            if verify_token.second_factor_token_enabled:
                try:
                    sftoken = verify_token.get_sftoken()
                    verify_tokens[sftoken.uuid] = {
                                                'token'     : sftoken,
                                                '2f'        : True,
                                                'fftoken'   : verify_token,
                                                }
                except Exception as e:
                    msg = ("Unable to load second factor token of '%s': %s"
                            % (verify_token.rel_path, e))
                    self.logger.critical(msg)

        # Get smartcard options.
        token_options = {}
        verify_token = None
        for uuid in verify_tokens:
            verify_token = verify_tokens[uuid]['token']
            is_2f_token = verify_tokens[uuid]['2f']
            try:
                smartcard_server_handler = config.get_smartcard_handler(verify_token.token_type)[1]
            except NotRegistered:
                continue
            smartcard_server_handler = smartcard_server_handler()
            try:
                token_opts = smartcard_server_handler.handle_preauth(token=verify_token)
            except Exception as e:
                msg = "Smarcard handler failed: %s: %s" % (verify_token, e)
                self.logger.warning(msg)
                continue
            try:
                pass_required = token_opts['pass_required']
            except KeyError:
                pass_required = False
            if is_2f_token:
                fftoken = verify_tokens[uuid]['fftoken']
                if fftoken.pass_type == "otp" \
                or fftoken.pass_type == "static":
                    pass_required = True
            try:
                self.token_challenges[verify_token.rel_path] = token_opts['challenge']
            except KeyError:
                pass
            token_opts['pass_required'] = pass_required
            token_opts['is_2f_token'] = is_2f_token
            token_options[verify_token.rel_path] = token_opts
            self.smartcard_handlers[verify_token.rel_path] = smartcard_server_handler
            self.logger.debug("Got valid smartcard type '%s' from token: %s"
                            % (verify_token.token_type, verify_token.rel_path))

        # Get ssh public keys from valid tokens.
        ssh_public_keys = []
        for uuid in verify_tokens:
            verify_token = verify_tokens[uuid]['token']
            if verify_token.pass_type != "ssh_key":
                continue
            ssh_public_keys.append(verify_token.ssh_public_key)

        if verify_token:
            self.preauth_status = True
            # Get users agent script.
            if self.user.agent_script:
                x = backend.get_object(object_type="script",
                                    uuid=self.user.agent_script)
                agent_script = decode(x.script, "base64")
                agent_script_uuid = x.uuid
                agent_script_path = x.rel_path
                agent_script_options = self.user.agent_script_options.copy()
                agent_script_signs = x.signatures.copy()
            else:
                agent_script = None
                agent_script_uuid = None
                agent_script_path = None
                agent_script_options = None
                agent_script_signs = None

            preauth_reply = {
                    'realm'                 : config.realm,
                    'site'                  : config.site,
                    'time'                  : time.time(),
                    'status'                : self.preauth_status,
                    'status_message'        : "Valid user tokens found",
                    'preauth_response'      : preauth_response,
                    'ecdh_server_pub'       : ecdh_server_pub_pem,
                    'token_options'         : token_options,
                    'ssh_public_keys'       : ssh_public_keys,
                    'agent_script'          : agent_script,
                    'agent_script_uuid'     : agent_script_uuid,
                    'agent_script_path'     : agent_script_path,
                    'agent_script_options'  : agent_script_options,
                    'agent_script_signs'    : agent_script_signs,
                    }

        else:
            self.preauth_status = False
            message = (_("No token found to authenticate user."))
            preauth_reply = {
                    'realm'                 : config.realm,
                    'site'                  : config.site,
                    'time'                  : time.time(),
                    'status'                : self.preauth_status,
                    'status_message'        : message,
                    'preauth_response'      : preauth_response,
                    'ecdh_server_pub'       : ecdh_server_pub_pem,
                    }
            self.logger.warning(message)

        return preauth_reply

    def gen_jwt_auth_reply(self, user, login, preauth_response, ecdh_server_pub_pem, redirect=False):
        # Generate JWT challenge. We use a signed JWT with the username
        # of the authenticating user and our realm/site as payload. This way
        # we can make sure that OTPmeClient() send a JWT only to the site
        # it belongs to. We also add the accessgroup this JWT should be
        # valid for. This will be checked by our AuthHandler().
        if login:
            jwt_reason = "REALM_LOGIN"
        else:
            jwt_reason = "REALM_AUTH"

        status = "jwt_auth"
        if redirect:
            status = "redirect_auth"

        challenge = stuff.gen_secret(len=32)
        jwt_data = {
                    'user'          : user.name,
                    'realm'         : config.realm,
                    'site'          : config.site,
                    'accessgroup'   : self.access_group,
                    'reason'        : jwt_reason,
                    'challenge'     : challenge,
                }
        self.logger.debug("Generating redirect challenge...")
        self.redirect_challenge = jwt.encode(payload=jwt_data,
                                            key=self.site_key,
                                            algorithm='RS256')
        self.preauth_status = True
        preauth_reply = {
                'status'                : status,
                'realm'                 : config.realm,
                'site'                  : config.site,
                'time'                  : time.time(),
                'auth_realm'            : user.realm,
                'auth_site'             : user.site,
                'auth_challenge'        : self.redirect_challenge,
                'status_message'        : "Authentication redirect",
                'preauth_response'      : preauth_response,
                'ecdh_server_pub'       : ecdh_server_pub_pem,
                }
        return preauth_reply

    def get_client_by_ip(self, realm, site, client_ip):
        """ Gets client by IP. """
        client_result = backend.search(object_type="client",
                                    attribute="address",
                                    value=client_ip,
                                    return_type="instance")
        if not client_result:
            return
        return client_result

    def get_access_group(self, client=None, client_ip=None, host=None):
        """ Try to get accessgroup from client. """
        if host:
            return config.realm_access_group

        if client:
            # Create client instance for the client of this request.
            auth_client = backend.get_object(object_type="client",
                                            realm=config.realm,
                                            site=config.site,
                                            name=client,
                                            run_policies=True,
                                            _no_func_cache=True)

        # If client is not set in this request but client_ip is set try to find
        # client by IP.
        if client_ip:
            self.logger.debug("Request contains no client name but a client IP. "
                        "Trying to find client name by IP.")
            # Try to get client name by IP.
            found_clients = self.get_client_by_ip(self.user.realm,
                                                self.user.site,
                                                client_ip)
            if len(found_clients) > 1:
                msg = ("More than one client has configured IP '%s': %s"
                        % (self.client_ip, ", ".join(found_clients)))
                self.logger.warning(msg)
                self.logger.warning("If you have clients that send requests without "
                                "a client name (e.g. NAS-ID for radius) you can "
                                "map a client name to this clients by adding "
                                "the correspondig IP to the client config. But "
                                "only to one client!")
                raise OTPmeException(msg)

            if len(found_clients) == 0:
                msg = ("Cannot find client of this request. Authentication "
                        "will fail.")
                self.logger.warning(msg)
                raise OTPmeException(msg)

            if len(found_clients) != 1:
                msg = ("Found multiple clients of this request. Authentication "
                        "will fail.")
                self.logger.warning(msg)
                raise OTPmeException(msg)

            # If we found exactly one client for this IP we can set it.
            auth_client = found_clients[0]
            # Create client instance for the client of this request.
            auth_client = backend.get_object(object_type="client",
                                            realm=config.realm,
                                            site=config.site,
                                            name=auth_client,
                                            run_policies=True,
                                            _no_func_cache=True)
            msg = ("Found client '%s' via IP '%s'."
                    % (auth_client.name, client_ip))
            self.logger.debug(msg)

        # If client is not enabled authentication must fail.
        if not auth_client.enabled:
            msg = ("Client '%s' is disabled." % self.client)
            self.logger.warning(msg)
            raise OTPmeException(msg)

        # Try to get access_group of the client.
        access_group = auth_client.access_group
        if not access_group:
            msg = ("Got no accessgroup from client config. "
                    "Authentication will fail.")
            self.logger.warning(msg)
            raise OTPmeException(msg)

        msg = ("Got accessgroup '%s' from client config." % access_group)
        self.logger.debug(msg)

        return access_group

    def get_peer_from_cert(self):
        """ Try to find OTPme object from peer infos. """
        if not self.client_cn:
            msg = ("Uuuuuh, we got no peer name (SSL certificate). "
                    "This should never happen. :(")
            self.logger.critical(msg)
            raise CertVerifyFailed("AUTH_CLIENT_CERT_MISSING")

        # Try to get peer name etc.
        try:
            peer_fqdn = self.client_cn
            peer_name = peer_fqdn.split(".")[0]
            peer_site = peer_fqdn.split(".")[1]
            peer_realm = ".".join(peer_fqdn.split(".")[2:])
        except:
            msg = ("Got invalid client cert CN from client: %s"
                    % self.client_cn)
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
                if peer.fqdn == self.client_cn:
                    return peer

        return None

    def get_valid_tokens(self, user, token_type=None, login=False,
        pass_type=None, check_sf_tokens=False):
        """
        Get tokens that could be used to authenticate the user for the given
        access group.
        """
        # Get auth accessgroup.
        auth_group = backend.get_object(object_type="accessgroup",
                                        realm=config.realm,
                                        site=config.site,
                                        name=self.access_group,
                                        run_policies=True,
                                        _no_func_cache=True)
        # Get possible user auth tokens
        valid_tokens = user.get_tokens(token_type=token_type,
                                        pass_type=pass_type,
                                        access_group=auth_group,
                                        check_sf_tokens=check_sf_tokens,
                                        host=self.peer,
                                        return_type="instance",
                                        quiet=True)
        if not login:
            return valid_tokens

        if not self.peer.logins_limited:
            return valid_tokens

        if self.user.is_admin():
            return valid_tokens

        # Get tokens valid for login host/node.
        valid_peer_tokens = self.peer.get_tokens(user_uuid=user.uuid,
                                                include_roles=True,
                                                return_type="instance")
        # Remove invalid tokens from list.
        for token in list(valid_tokens):
            if token in valid_peer_tokens:
                continue
            valid_tokens.remove(token)

        return valid_tokens

    def get_valid_ssh_token(self, user, ssh_auth_key):
        """ Check if we can find a valid SSH login token of the given user. """
        token = None
        verify_token = None
        valid_user_tokens_ssh = self.get_valid_tokens(user=user,
                                                pass_type="ssh_key")
        for _token in valid_user_tokens_ssh:
            # Make sure we use linked token if needed.
            if _token.destination_token:
                _verify_token = _token.get_destination_token()
            else:
                _verify_token = _token
            if _verify_token.ssh_public_key != ssh_auth_key:
                    continue
            # Set found token and stop searching.
            verify_token = _verify_token
            token = _token
            break

        return token, verify_token

    def authenticate_host(self, command, command_args):
        """ Authenticate host/node. """
        if self.peer_challenge:
            try:
                peer_response = command_args['client_response']
            except:
                msg = ("Invalid auth command: Missing peer challenge")
                self.logger.warning(msg)
                raise OTPmeException("AUTH_INVALID_REQUEST")

            try:
                status = self.peer.verify_challenge(self.peer_challenge,
                                                    peer_response)
            except Exception as e:
                msg = ("Error verifying peer challenge: %s" % e)
                self.logger.warning(msg)
                raise OTPmeException("AUTH_INVALID_REQUEST")

            if not status:
                msg = ("Failed to verify peer challenge.")
                self.logger.warning(msg)
                raise OTPmeException("AUTH_FAILED")

            msg = ("Peer response verification successful: %s"
                    % self.peer.name)
            if config.debug_level() > 3:
                self.logger.debug(msg)

            self.authenticated = True
            reply = "Host authentication successful."
            return reply

        # Verify peer certificate (only on the first request, before we
        # have generated the peer challenge).
        if self.peer.fqdn != self.client_cn:
            msg = (_("Peer certificate CN '%s' does not match FQDN of %s: %s")
                    % (self.client_cn, self.peer.type, self.peer.fqdn))
            self.logger.warning(msg)
            raise OTPmeException(msg)

        if config.debug_level() > 3:
            self.logger.debug("Verified peer certificate CN: %s" % self.peer.fqdn)

        # Set proctitle to contain peer name.
        peer_type = self.peer.type[0].upper() + self.peer.type[1:].lower()
        new_proctitle = "%s %s: %s" % (self.proctitle,
                                        peer_type,
                                        self.peer.name)
        setproctitle.setproctitle(new_proctitle)

        # In debug mode its handy to have node name included in loglines.
        if config.debug_enabled or config.loglevel == "DEBUG":
            log_banner = ("%s:%s:" % (config.log_name, self.peer.name))
            self.logger = config.setup_logger(banner=log_banner, pid=True,
                                            existing_logger=config.logger)

        # Get server challenge to be signed by us.
        try:
            server_challenge = command_args['server_challenge']
        except:
            msg = ("Invalid auth command: Missing server challenge")
            self.logger.warning(msg)
            raise OTPmeException("AUTH_INVALID_REQUEST")

        # Generate client challenge to be send to peer.
        self.peer_challenge = self.peer.gen_challenge()

        # Sign server challenge.
        my_host = self._get_host()
        server_response = my_host.sign_challenge(server_challenge)

        reply = {
                'client_challenge'  : self.peer_challenge,
                'server_response'   : server_response,
                }

        return reply

    def authenticate_user(self, command, command_args):
        """ Authenticate user. """
        # Indicates if authentication was successful.
        auth_status = False
        # Indicates realm login/logout.
        realm_login = False
        realm_logout = False
        # Indicates a screen unlock request.
        auth_unlock = False

        username = None
        password = None

        login_host = "unknown"
        login_host_ip = "unknown"
        login_host_type = None

        # Try to get client infos from where the users connects/logs in
        # (e.g. host, node etc.)
        if self.client:
            login_host_ip = self.client.split(":")[0]

        if self.client_cn:
            login_host = self.client_cn.split(".")[0]
        else:
            login_host = self.client

        # Set login_host_type from peer.
        if self.peer:
            login_host_type = self.peer.type

        # Check if we should do a realm login.
        if command == "auth_login":
            if self.name != "authd":
                msg = (_("Please connect to otpme-authd for realm logins."))
                raise OTPmeException(msg)
            realm_login = True
            self.access_group = config.realm_access_group

       # Check if we should handle a screen unlock request (e.g. no policy
       # check).
        if command == "auth_unlock":
            if self.name != "authd":
                msg = (_("Please connect to otpme-authd for unlock requests."))
                raise OTPmeException(msg)
            auth_unlock = True
            self.access_group = config.realm_access_group

        # Check if we should do a realm logout.
        if command == "auth_logout":
            if self.name != "authd":
                msg = (_("Please connect to otpme-authd for realm logout."))
                raise OTPmeException(msg)
            realm_logout = True
            self.access_group = config.realm_access_group

        # Try to get auth client.
        try:
            client = command_args.pop('client')
        except:
            client = None

        # Try to get username.
        try:
            username = command_args.pop('username')
        except:
            msg = ("Got incomplete command from client: %s: Missing username"
                    % self.client)
            self.logger.warning(msg)
            raise OTPmeException("AUTH_INCOMPLETE_COMMAND")

        # Check if user exists.
        if not self.user:
            msg = "Login failed."
            self.logger.warning(msg)
            raise OTPmeException("AUTH_FAILED")

        # If we are called from a daemon set proctitle to contain username.
        if not config.use_api:
            # Set process title.
            new_proctitle = "%s User: %s" % (self.proctitle, username)
            setproctitle.setproctitle(new_proctitle)
            # In debug mode its handy to have username included in loglines.
            if config.debug_enabled or config.loglevel == "DEBUG":
                log_banner = "%s:%s:" % (config.log_name, username)
                self.logger = config.setup_logger(banner=log_banner, pid=True,
                                                existing_logger=config.logger)
        try:
            auth_type = command_args.pop('auth_type')
        except KeyError:
            msg = "Missing auth type in request."
            raise OTPmeException(msg)

        # Try to get password from command args (e.g. password auth fallback if
        # no SSH public key has matched).
        try:
            password = command_args.pop('password')
        except:
            pass

        # Try to get challenge from command args.
        try:
            challenge = command_args.pop('challenge')
        except:
            challenge = None

        # Try to get response from command args.
        try:
            response = command_args.pop('response')
        except:
            response = None

        try:
            login_interface = command_args.pop('login_interface')
        except KeyError:
            login_interface = None

        try:
            replace_sessions = command_args.pop('replace_sessions')
        except KeyError:
            replace_sessions = False

        try:
            client_offline_enc_type = command_args.pop('client_offline_enc_type')
        except KeyError:
            client_offline_enc_type = None

        try:
            reneg = command_args.pop('reneg')
        except KeyError:
            reneg = False

        try:
            reneg_salt = command_args.pop('reneg_salt')
        except KeyError:
            reneg_salt = None

        try:
            rsp_hash_type = command_args.pop('rsp_hash_type')
        except KeyError:
            rsp_hash_type = None

        try:
            rsp_ecdh_client_pub = command_args.pop('rsp_ecdh_client_pub')
        except KeyError:
            rsp_ecdh_client_pub = None

        try:
            redirect_response = command_args.pop('redirect_response')
        except KeyError:
            redirect_response = None

        try:
            jwt_challenge = command_args.pop('jwt_challenge')
        except KeyError:
            jwt_challenge = None

        # Try to get SSH auth key.
        try:
            ssh_auth_key = command_args.pop('ssh_auth_key')
        except KeyError:
            ssh_auth_key = None

        # Set auth_mode.
        auth_mode = "auto"
        try:
            smartcard_data = command_args.pop('smartcard_data')
        except KeyError:
            smartcard_data = None
        if smartcard_data:
            try:
                is_2f_token = smartcard_data['is_2f_token']
            except KeyError:
                is_2f_token = False
            try:
                smartcard_token_rel_path = smartcard_data['token_rel_path']
            except KeyError:
                msg = "Missing token_rel_path in smartcard data."
                raise OTPmeException(msg)
            try:
                smartcard_server_handler = self.smartcard_handlers[smartcard_token_rel_path]
            except:
                msg = "Client sent smartcard data for unknown token."
                self.logger.warning(msg)
                raise OTPmeException(msg)
            try:
                smartcard_data = smartcard_server_handler.prepare_authentication(smartcard_data)
            except Exception as e:
                msg = "Smartcard handler exception: %s" % e
                self.logger.warning(msg)
                config.raise_exception()
                raise OTPmeException("SMARTCARD_HANLDER_EXCEPTION")
            try:
                smartcard_challenge = smartcard_data['challenge']
            except KeyError:
                smartcard_challenge = None
            if smartcard_challenge:
                if not self.token_challenges:
                    msg = "Got invalid challenge"
                    raise OTPmeException(msg)
                for token_rel_path in self.token_challenges:
                    x_challenge = self.token_challenges[token_rel_path]
                    if x_challenge == smartcard_challenge:
                        break
                    msg = "Got invalid challenge"
                    raise OTPmeException(msg)
            if is_2f_token:
                if not password:
                    return passauth(query_id="password", prompt="Password/OTP:")
            else:
                verify_token_result = backend.search(object_type="token",
                                                    attribute="rel_path",
                                                    value=smartcard_token_rel_path,
                                                    return_type="instance")
                if not verify_token_result:
                    msg = "Unknown smartcard token: %s" % smartcard_token_rel_path
                    raise OTPmeException(msg)
                self.token = verify_token_result[0]
            auth_mode = "smartcard"
            auth_type = auth_mode
        elif auth_type == "clear-text":
            if not password:
                return passauth(query_id="password", prompt="Password/OTP:")

        elif auth_type == "ssh":
            self.logger.debug("Selecting SSH token for user: %s"
                            % self.user.name)
            # Try to get valid SSH token of the user.
            token, \
            verify_token = self.get_valid_ssh_token(user=self.user,
                                                    ssh_auth_key=ssh_auth_key)
            if not token:
                msg = "Unable to find SSH token for given public key."
                raise OTPmeException(msg)
            try:
                token_challenge = self.token_challenges[verify_token.rel_path]
            except KeyError:
                token_challenge = None
            if not token_challenge:
                self.logger.debug("Doing %s authentication." % auth_type)
                # Set challenge and token for this request.
                token_challenge = verify_token.gen_challenge()
                self.token_challenges[verify_token.rel_path] = token_challenge
            if not self.token:
                self.token = token
            # If we have no response yet request it.
            if not response:
                return sshauth(query_id="response", challenge=token_challenge)

        if command_args:
            msg = "Got unknown command args: %s" % list(command_args.keys())
            self.logger.warning(msg)

        if challenge:
            if not self.token_challenges:
                msg = "Got invalid challenge"
                raise OTPmeException(msg)
            for token_rel_path in self.token_challenges:
                x_challenge = self.token_challenges[token_rel_path]
                if x_challenge == challenge:
                    break
                msg = "Got invalid challenge"
                raise OTPmeException(msg)

        # If we got a password try to auth user.
        if auth_type == "clear-text" or auth_type == "jwt":
            # Verify clear-text request.
            try:
                auth_reply = self.user.authenticate(auth_mode=auth_mode,
                                            auth_type=auth_type,
                                            client=client,
                                            realm_login=realm_login,
                                            realm_logout=realm_logout,
                                            unlock=auth_unlock,
                                            access_group=self.access_group,
                                            host_type=login_host_type,
                                            host=login_host,
                                            host_ip=login_host_ip,
                                            redirect_challenge=self.redirect_challenge,
                                            jwt_challenge=jwt_challenge,
                                            redirect_response=redirect_response,
                                            rsp_ecdh_client_pub=rsp_ecdh_client_pub,
                                            rsp_hash_type=rsp_hash_type,
                                            allow_sotp_reuse=self.allow_sotp_reuse,
                                            reneg=reneg,
                                            client_offline_enc_type=client_offline_enc_type,
                                            replace_sessions=replace_sessions,
                                            login_interface=login_interface,
                                            reneg_salt=reneg_salt,
                                            ecdh_curve=self.ecdh_curve,
                                            password=password,
                                            verify_host=self.verify_host)
            except OTPmeException:
                raise
            except Exception as e:
                config.raise_exception()
                msg = ("Error running User().authenticate(): %s" % e)
                self.logger.critical(msg, exc_info=True)
                raise OTPmeException(_("Internal error while authenticating user."))
            # Get auth status from reply.
            auth_status = auth_reply['status']
        else:
            user_token = None
            if self.token:
                user_token = self.token.name
            # Try to authenticate user.
            try:
                auth_reply = self.user.authenticate(auth_mode=auth_mode,
                                            auth_type=auth_type,
                                            client=client,
                                            realm_login=realm_login,
                                            realm_logout=realm_logout,
                                            unlock=auth_unlock,
                                            access_group=self.access_group,
                                            user_token=user_token,
                                            challenge=challenge,
                                            response=response,
                                            smartcard_data=smartcard_data,
                                            host_type=login_host_type,
                                            host=login_host,
                                            host_ip=login_host_ip,
                                            ecdh_curve=self.ecdh_curve,
                                            verify_host=self.verify_host,
                                            jwt_challenge=jwt_challenge,
                                            rsp_ecdh_client_pub=rsp_ecdh_client_pub,
                                            rsp_hash_type=rsp_hash_type,
                                            reneg=reneg,
                                            allow_sotp_reuse=self.allow_sotp_reuse,
                                            reneg_salt=reneg_salt,
                                            client_offline_enc_type=client_offline_enc_type,
                                            replace_sessions=replace_sessions,
                                            login_interface=login_interface,
                                            password=password)
            except OTPmeException:
                raise
            except Exception as e:
                config.raise_exception()
                msg = ("Error running User().authenticate(): %s" % e)
                self.logger.critical(msg, exc_info=True)
                raise OTPmeException("Internal error while authenticating user.")
            # Get auth status from reply.
            auth_status = auth_reply['status']

        if auth_status:
            # Get auth token from reply.
            auth_token = auth_reply.pop('token')
            # Make sure we use destination token for linked tokens.
            if auth_token.destination_token:
                verify_token = auth_token.get_destination_token()
            else:
                verify_token = auth_token

            # Set connection status to authenticated.
            self.authenticated = True
            # Set auth token in config module (e.g. used to check ACLs).
            config.auth_token = auth_token
            # Set auth user in config module (e.g. used to get user auto-sign
            # setting).
            config.auth_user = self.user
            # Set username of authenticated user.
            self.username = username

        # Set auth reply type.
        auth_reply['type'] = "auth"

        try:
            temp_pass_auth = auth_reply['temp_pass_auth']
        except:
            temp_pass_auth = False

        # Set login token also for auth requests (e.g. ldap server authentication).
        if auth_status:
            auth_reply['login_token_uuid'] = auth_token.uuid

        # For realm logins we return RSP, offline tokens etc.
        if auth_status and realm_login:
            offline_tokens = []
            # Add offline tokens to reply if enabled.
            if auth_token.allow_offline \
            and verify_token.allow_offline \
            and not temp_pass_auth:
                # Add auth token to offline_tokens.
                object_config = auth_token.get_offline_config()
                object_config['OID'] = auth_token.oid.full_oid
                offline_tokens.append(object_config)
                if auth_token.destination_token:
                    # Add linked token to offline_tokens.
                    object_config = verify_token.get_offline_config()
                    object_config['OID'] = verify_token.oid.full_oid
                    offline_tokens.append(object_config)
                # Check if a second factor token is enabled.
                second_factor_token = None
                if verify_token.second_factor_token_enabled:
                    try:
                        second_factor_token = verify_token.get_sftoken()
                    except Exception as e:
                        self.logger.critical("Unable to load second factor "
                                            "token of '%s': %s"
                                            % (verify_token.rel_path, e))
                if second_factor_token:
                    # Add second factor token to reply.
                    object_config = second_factor_token.get_offline_config(second_factor_usage=True)
                    object_config['OID'] = second_factor_token.oid.full_oid
                    offline_tokens.append(object_config)

            keep_session = False
            if auth_token.keep_session and verify_token.keep_session:
                keep_session = True

            # Add offline tokens etc. to auth reply.
            auth_reply['login_token'] = auth_token.rel_path
            auth_reply['login_pass_type'] = verify_token.pass_type
            auth_reply['offline_tokens'] = offline_tokens
            auth_reply['keep_session'] = keep_session

        # Print authentication timings.
        if config.print_timing_results:
            from otpme.lib import debug
            debug.print_timing_result(print_status=True)

        return auth_reply

    def decode_request(self, *args, **kwargs):
        return decode_request(*args, **kwargs)

    def build_response(self, status, message, binary_data=None, encrypt=None,
        compress=None, encoding="base64"):
        """ Build response. """
        enc_key = None
        enc_mod = None

        if encrypt is None:
            need_encryption = self.encrypt_session
        else:
            need_encryption = encrypt

        if config.use_api:
            need_encryption = False

        if need_encryption and self.can_encrypt:
            if not self.session_key:
                msg = (_("Session key missing."))
                raise OTPmeException(msg)
            enc_key = self.session_key
            enc_mod = self.session_enc_mod

        if compress is None:
            compress = self.compresss_response

        response = build_response(status, message,
                            binary_data=binary_data,
                            encoding=encoding,
                            compress=compress,
                            encryption=enc_mod,
                            enc_key=enc_key)
        if config.use_api:
            self.last_response = response

        return response

    def cleanup(self):
        """ Is called on client disconnect. """
        self.authenticated = False
        self.username = None
        self.token = None
        self.peer_challenge = None
        self.peer = None
        self.peer_cert = None
        self.redirect_challenge = None

        self.client = None
        self.client_name = None
        self.client_proc = None
        self.client_pid = None
        self.client_user = None
        self.client_cn = None

        self.host_type = None
        self.host_name = None
        self.host_realm = None
        self.host_site = None
        self.host_fqdn = None
