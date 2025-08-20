# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import jwt
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib import multiprocessing

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-auth-1.0"

def register():
    config.register_otpme_protocol("authd", PROTOCOL_VERSION, server=True)

class OTPmeAuthP1(OTPmeServer1):
    """ Class that implements OTPme-auth-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "authd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Authd does not require any authentication on client connect.
        self.require_auth = None
        self.require_preauth = True
        # Instructs parent class to require a client certificate.
        self.require_client_cert = True
        # Auth request are allowed to any node.
        self.require_master_node = False
        # We need a clean cluster status.
        self.require_cluster_status = True
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def set_proctitle(self, username):
        """ Set proctitle to contain username. """
        if config.use_api:
            return
        new_proctitle = "%s User: %s" % (self.proctitle, username)
        setproctitle.setproctitle(new_proctitle)
        # FIXME: does this work when running as freeradius module?
        # In debug mode its handy to have username included in loglines
        if config.debug_enabled or config.loglevel == "DEBUG":
            log_banner = "%s:%s:" % (config.log_name, username)
            self.logger = config.setup_logger(banner=log_banner,
                                        existing_logger=config.logger,
                                        pid=True)

    def _process(self, command, command_args, **kwargs):
        """ Handle authentication data received from auth_handler. """
        # All valid commands.
        valid_commands = [
                            "verify",
                            "get_jwt",
                            "verify_static",
                            "verify_mschap",
                        ]

        # Check if we got a valid command.
        if not command in valid_commands:
            message = "Unknown command: %s" % command
            status = False
            return self.build_response(status, message)

        if not config.use_api:
            try:
                self.check_cluster_status()
            except Exception as e:
                message = str(e)
                status = status_codes.CLUSTER_NOT_READY
                return self.build_response(status, message)

        if command == "get_jwt":
            msg = "Processing JWT request."
            self.logger.info(msg)

            if not self.authenticated:
                message = "Not logged in."
                status = status_codes.NEED_USER_AUTH
                self.require_auth = "user"
                return self.build_response(status, message)

            # Set proctitle to contain username.
            self.set_proctitle(self.username)

            try:
                jwt_reason = command_args['jwt_reason']
            except:
                status = False
                message = "AUTHD_INCOMPLETE_COMMAND"
                return self.build_response(status, message)

            try:
                jwt_challenge = command_args['jwt_challenge']
            except:
                status = False
                message = "AUTHD_INCOMPLETE_COMMAND"
                return self.build_response(status, message)

            try:
                jwt_accessgroup = command_args['jwt_accessgroup']
            except:
                status = False
                message = "AUTHD_INCOMPLETE_COMMAND"
                return self.build_response(status, message)

            token_accessgroups = config.auth_token.get_access_groups()
            if jwt_accessgroup not in token_accessgroups:
                status = False
                message = "AUTHD_PERMISSION_DENIED"
                return self.build_response(status, message)

            # Load JWT signing key.
            user_site = backend.get_object(uuid=config.auth_token.site_uuid)
            sign_key = user_site._key

            # Redirect user if we do not have the required site key.
            if not sign_key:
               message = "%s/%s" % (user_site.realm, user_site.name)
               status = status_codes.CONNECTION_REDIRECT
               return self.build_response(status, message)

            # Build JWT.
            jwt_data = {
                    'realm'             : config.realm,
                    'site'              : config.site,
                    'reason'            : jwt_reason,
                    'message'           : "JWT signed by authd.",
                    'challenge'         : jwt_challenge,
                    'login_time'        : time.time(),
                    'login_token'       : config.auth_token.uuid,
                    'auth_type'         : config.auth_type,
                    'accessgroup'       : jwt_accessgroup,
                    }

            _jwt = jwt.encode(payload=jwt_data, key=sign_key, algorithm='RS256')

            msg = ("Sigend JWT: user=%s token=%s access_group=%s, reason=%s"
                    % (self.username, config.auth_token.name,
                    jwt_accessgroup, jwt_reason))
            self.logger.info(msg)

            return self.build_response(True, _jwt)

        # Try to get username.
        try:
            username = command_args['username']
        except:
            username = None

        # Variables to build log entry if something goes wrong before we could
        # call User().authenticate()
        log_username = ""
        log_access_group = ""
        log_client = ""
        log_client_ip = ""
        log_session_id = ""
        log_auth_type = ""
        log_auth_mode = ""

        try:
            client = command_args['client']
        except:
            client = None

        try:
            client_ip = command_args['client_ip']
        except:
            client_ip = None

        try:
            host = command_args['host']
        except:
            host = None

        try:
            host_type = command_args['host_type']
        except:
            host_type = None

        try:
            host_ip = command_args['host_ip']
        except:
            host_ip = None

        try:
            password = command_args['password']
        except:
            password = None

        try:
            mschap_challenge = command_args['mschap_challenge']
        except:
            mschap_challenge = None

        try:
            mschap_response = command_args['mschap_response']
        except:
            mschap_response = None

        # Set host IP from source IP if requested.
        if host_ip == "auto":
            if not config.use_api:
                host_ip = self.client.split(":")[0]
            else:
                host_ip = None
        try:
            access_group = command_args['access_group']
        except:
            access_group = None

        # Set auth mode.
        if command == "verify" or command == "verify_mschap":
            auth_mode = "auto"

        # Set auth type.
        if command == "verify":
            auth_type = "clear-text"
        if command == "verify_mschap":
            auth_type = "mschap"

        # Set log variables.
        log_auth_mode = auth_mode
        log_auth_type = auth_type
        if username is not None:
            log_username = username
        if access_group is not None:
            log_access_group = access_group
        if client is not None:
            log_client = client
        if client_ip is not None:
            log_client_ip = client_ip
        if host is not None:
            log_client = host
        if host_ip is not None:
            log_client_ip = host_ip

        # Check for incomplete command.
        incomplete_command = False
        if not username:
            incomplete_command = True
        if not client and not client_ip and not host:
            incomplete_command = True
        if password is None:
            if mschap_challenge is None or mschap_response is None:
                incomplete_command = True

        if incomplete_command:
            status = False
            message = "Incomplete command."
            command_error = "AUTH_INCOMPLETE_COMMAND"

        # Check for invalid command.
        invalid_command = False
        if host and client:
            invalid_command = "Received conflicting host/client parameters."
        if password and mschap_response:
            invalid_command = ("Received conflicting auth parameters "
                                "password/MSCHAP.")
        if invalid_command:
            status = False
            message = invalid_command
            command_error = "AUTH_INVALID_COMMAND"

        # Build incomplete/invalid command response.
        if incomplete_command or invalid_command:
            msg = ("%s: user=%s access_group=%s client=%s client_ip=%s "
                    "auth_mode=%s auth_type=%s session=%s"
                            % (command_error,
                            log_username,
                            log_access_group,
                            log_client,
                            log_client_ip,
                            log_auth_mode,
                            log_auth_type,
                            log_session_id))
            self.logger.error(msg)
            return self.build_response(status, message)

        # Check if user exists.
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if not user:
            status = False
            command_error = "AUTH_UNKOWN_USER"
            auth_reply = {'message':'AUTH_FAILED', 'status':False}
            msg = ("%s: user=%s access_group=%s client=%s client_ip=%s "
                    "auth_mode=%s auth_type=%s session=%s"
                            % (command_error,
                            log_username,
                            log_access_group,
                            log_client,
                            log_client_ip,
                            log_auth_mode,
                            log_auth_type,
                            log_session_id))
            self.logger.warning(msg)
            return self.build_response(status, auth_reply)

        redirect_connection = False
        if user.realm != config.realm:
            redirect_connection = True
        if user.site != config.site:
            redirect_connection = True

        if redirect_connection:
            # Get authd connection.
            try:
                authd_conn = connections.get("authd",
                                            realm=user.realm,
                                            site=user.site,
                                            auto_preauth=True,
                                            auto_auth=False)
            except Exception as e:
                message = "Failed to get redirect connection"
                msg = "%s: %s" % (message, e)
                self.logger.critical(msg)
                status = False
                return self.build_response(status, message)

            # Send verify request.
            try:
                status, \
                status_code, \
                auth_reply, \
                binary_data = authd_conn.send(command="verify",
                                        command_args=command_args)
            except Exception as e:
                message = "Failed to authenticate user"
                msg = "%s: %s" % (message, e)
                self.logger.critical(msg)
                status = False
                return self.build_response(status, message)
            finally:
                authd_conn.close()

            return self.build_response(status, auth_reply)

        # Indicates if authentication was successful.
        auth_status = False

        # Set proctitle to contain username.
        self.set_proctitle(username)

        # Build auth request.
        kwargs = {
                    'auth_mode'     : auth_mode,
                    'auth_type'     : auth_type,
                    'access_group'  : access_group,
                    'challenge'     : mschap_challenge,
                    'response'      : mschap_response,
                    'password'      : password,
                    'host'          : host,
                    'host_type'     : host_type,
                    'host_ip'       : host_ip,
                    'client'        : client,
                    'client_ip'     : client_ip,
                    'ecdh_curve'    : self.ecdh_curve,
                }
        # Do authentication.
        auth_reply = user.authenticate(**kwargs)
        # Get auth status and message from reply.
        auth_status = auth_reply['status']
        # We will not send auth token instance to peer.
        try:
            auth_reply.pop('token')
        except KeyError:
            pass

        # Set connection status to authenticated.
        if auth_status:
            self.authenticated = True
            self.username = username

        # Build reply message.
        message = auth_reply
        if auth_status:
            status = True
        else:
            status = status_codes.ERR

        return self.build_response(status, message)

    def _close(self):
        pass
