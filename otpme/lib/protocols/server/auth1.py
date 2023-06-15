# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
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

    def _process(self, command, command_args):
        """ Handle authentication data received from auth_handler. """
        # All valid commands.
        valid_commands = [
                            "verify",
                            "get_jwt",
                            "verify_otp",
                            "verify_static",
                            "verify_mschap",
                            "verify_mschap_otp",
                            "verify_mschap_static",
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
            if not self.authenticated:
                msg = "Processing JWT request."
                self.logger.info(msg)
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
                message = "1AUTHD_INCOMPLETE_COMMAND"
                return self.build_response(status, message)

            try:
                jwt_challenge = command_args['jwt_challenge']
            except:
                status = False
                message = "2AUTHD_INCOMPLETE_COMMAND"
                return self.build_response(status, message)

            try:
                jwt_accessgroup = command_args['jwt_accessgroup']
            except:
                status = False
                message = "3AUTHD_INCOMPLETE_COMMAND"
                return self.build_response(status, message)

            # Load JWT signing key.
            user_site = backend.get_object(uuid=config.auth_token.site_uuid)
            sign_key = user_site._key

            # Redirect user if we do not have the required site key.
            if not sign_key:
               message = "%s/%s" % (user_site.realm, user_site.name)
               status = "303"
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
                    'accessgroup'       : jwt_accessgroup,
                    }

            _jwt = jwt.encode(payload=jwt_data, key=sign_key, algorithm='RS256')

            msg = ("Sigend JWT: user=%s token=%s access_group=%s, reason=%s"
                    % (self.username, config.auth_token.name,
                    jwt_accessgroup, jwt_reason))
            self.logger.info(msg)

            return self.build_response(True, _jwt)

        # Auth result string.
        auth_message = ""
        # Indicates if authentication was successful.
        auth_status = False
        # Variables to build log entry if something goes wrong before we could
        # call User().authenticate()
        log_username = ""
        log_token_name = ""
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

        # Try to get username.
        try:
            username = command_args['username']
        except:
            username = None

        # Set auth mode.
        if command == "verify" or command == "verify_mschap":
            auth_mode = "auto"
        if command == "verify_otp" or command == "verify_mschap_otp":
            auth_mode = "otp"
        if command == "verify_static" or command == "verify_mschap_static":
            auth_mode = "static"

        # Set auth type.
        if command == "verify" \
        or command == "verify_otp" \
        or command == "verify_static":
            auth_type = "clear-text"
        if command == "verify_mschap" \
        or command == "verify_mschap_otp" \
        or command == "verify_mschap_static":
            # Set auth type.
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
            msg = ("%s: user=%s token=%s access_group=%s client=%s client_ip=%s "
                    "auth_mode=%s auth_type=%s session=%s"
                            % (command_error,
                            log_username,
                            log_token_name,
                            log_access_group,
                            log_client,
                            log_client_ip,
                            log_auth_mode,
                            log_auth_type,
                            log_session_id))
            self.logger.error(msg)
            return self.build_response(status, message)

        # Set log user.
        log_username = username

        # Check if user exists.
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if not user:
            message = "AUTH_FAILED"
            status = False
            command_error = message
            msg = ("%s: user=%s token=%s access_group=%s client=%s client_ip=%s "
                    "auth_mode=%s auth_type=%s session=%s"
                            % (command_error,
                            log_username,
                            log_token_name,
                            log_access_group,
                            log_client,
                            log_client_ip,
                            log_auth_mode,
                            log_auth_type,
                            log_session_id))
            self.logger.error(msg)
            return self.build_response(status, message)

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
        auth_message = auth_reply['message']

        # Set connection status to authenticated.
        if auth_status:
            self.authenticated = True
            self.username = username

        # Build reply message.
        if auth_status:
            if auth_type == "mschap":
                nt_key = auth_reply['nt_key']
                message = "NT_KEY: %s" % nt_key
            else:
                message = auth_message
            status = True
        else:
            message = auth_message
            status = status_codes.ERR

        return self.build_response(status, message)

    def _close(self):
        pass
