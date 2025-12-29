# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import log
from otpme.lib import jwt
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.audit import get_audit_logger

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

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
        new_proctitle = f"{self.proctitle} User: {username}"
        setproctitle.setproctitle(new_proctitle)
        # FIXME: does this work when running as freeradius module?
        # In debug mode its handy to have username included in loglines
        if config.debug_enabled or config.loglevel == "DEBUG":
            log_banner = f"{config.log_name}:{username}:"
            self.logger = log.setup_logger(banner=log_banner,
                                        existing_logger=config.logger,
                                        pid=True)

    def gen_jwt(self, username, token, reason, challenge, access_group=None):
        if access_group:
            token_accessgroups = token.get_access_groups()
            if access_group not in token_accessgroups:
                msg = _("Access denied")
                raise AccessDenied(msg)

        # Load JWT signing key.
        user_site = backend.get_object(uuid=token.site_uuid)
        sign_key = user_site._key
        if not sign_key:
            msg = _("Access denied")
            raise AccessDenied(msg)

        # Build JWT.
        jwt_data = {
                'realm'             : config.realm,
                'site'              : config.site,
                'reason'            : reason,
                'message'           : "JWT signed by authd.",
                'challenge'         : challenge,
                'login_time'        : time.time(),
                'login_token'       : token.uuid,
                'auth_type'         : config.auth_type,
                'accessgroup'       : access_group,
                'socket_auth'       : config.socket_auth,
                }

        _jwt = jwt.encode(payload=jwt_data, key=sign_key, algorithm='RS256')

        log_msg = _("Sigend JWT: user={username} token={token_name} access_group={access_group}, reason={reason}", log=True)[1]
        log_msg = log_msg.format(username=username, token_name=token.name, access_group=access_group, reason=reason)
        self.logger.info(log_msg)
        return _jwt

    def _process(self, command, command_args, **kwargs):
        """ Handle authentication data received from auth_handler. """
        # All valid commands.
        valid_commands = [
                            "verify",
                            "get_jwt",
                            "token_verify",
                            "token_verify_mschap",
                            "verify_static",
                            "verify_mschap",
                        ]

        # Check if we got a valid command.
        if not command in valid_commands:
            message = _("Unknown command: {command}")
            message = message.format(command=command)
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
            log_msg = _("Processing JWT request.", log=True)[1]
            self.logger.info(log_msg)

            # Try to auth socket user.
            if not self.authenticated and self.client_user:
                try:
                    self.handle_socket_auth()
                except Exception as e:
                    status = False
                    message = str(e)
                    return self.build_response(status, message)

            if not self.authenticated:
                message = _("Not logged in.")
                status = status_codes.NEED_USER_AUTH
                self.require_auth = "user"
                return self.build_response(status, message)

            # Set proctitle to contain username.
            self.set_proctitle(self.username)

            try:
                jwt_reason = command_args['jwt_reason']
            except:
                status = False
                message = _("AUTHD_INCOMPLETE_COMMAND")
                return self.build_response(status, message)

            try:
                jwt_challenge = command_args['jwt_challenge']
            except:
                status = False
                message = _("AUTHD_INCOMPLETE_COMMAND")
                return self.build_response(status, message)

            try:
                jwt_accessgroup = command_args['jwt_accessgroup']
            except:
                jwt_accessgroup = None

            try:
                _jwt = self.gen_jwt(username=config.auth_token.owner,
                                    token=config.auth_token,
                                    reason=jwt_reason,
                                    challenge=jwt_challenge,
                                    access_group=jwt_accessgroup)
            except AccessDenied:
                status = False
                message = _("Unable to gen JWT.")
                return self.build_response(status, message)

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
        if command == "verify" \
        or command == "verify_mschap" \
        or command == "token_verify" \
        or command == "token_verify_mschap":
            auth_mode = "auto"

        # Set auth type.
        if command == "verify":
            auth_type = "clear-text"
        if command == "token_verify":
            auth_type = "clear-text"
        if command == "token_verify_mschap":
            auth_type = "mschap"
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
            message = _("Incomplete command.")
            command_error = "AUTH_INCOMPLETE_COMMAND"

        # Check for invalid command.
        invalid_command = False
        if host and client:
            invalid_command = _("Received conflicting host/client parameters.")
        if password and mschap_response:
            invalid_command = _("Received conflicting auth parameters password/MSCHAP.")
        if invalid_command:
            status = False
            message = invalid_command
            command_error = "AUTH_INVALID_COMMAND"

        # Build incomplete/invalid command response.
        if incomplete_command or invalid_command:
            log_msg = _("{command_error}: user={log_username} access_group={log_access_group} client={log_client} client_ip={log_client_ip} auth_mode={log_auth_mode} auth_type={log_auth_type} session={log_session_id}", log=True)[1]
            log_msg = log_msg.format(command_error=command_error, log_username=log_username, log_access_group=log_access_group, log_client=log_client, log_client_ip=log_client_ip, log_auth_mode=log_auth_mode, log_auth_type=log_auth_type, log_session_id=log_session_id)
            self.logger.error(log_msg)
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
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            log_msg = _("{command_error}: user={log_username} access_group={log_access_group} client={log_client} client_ip={log_client_ip} auth_mode={log_auth_mode} auth_type={log_auth_type} session={log_session_id}", log=True)[1]
            log_msg = log_msg.format(command_error=command_error, log_username=log_username, log_access_group=log_access_group, log_client=log_client, log_client_ip=log_client_ip, log_auth_mode=log_auth_mode, log_auth_type=log_auth_type, log_session_id=log_session_id)
            self.logger.warning(log_msg)
            return self.build_response(status, auth_response)

        redirect_connection = False
        if user.realm != config.realm:
            redirect_connection = True

        if not redirect_connection:
            if user.site != config.site:
                try:
                    stuff.get_site_trust_status(user.realm, user.site)
                except SiteNotTrusted:
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
                message, log_msg = _("Failed to get redirect connection", log=True)
                log_msg = f"{log_msg}: {e}"
                self.logger.critical(log_msg)
                status = False
                return self.build_response(status, message)
            # Gen JWT to be signed by other site.
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            site_key = my_site._key
            jwt_reason = "AUTH"
            challenge = stuff.gen_secret(len=32)
            jwt_data = {
                        'user'          : user.name,
                        'realm'         : config.realm,
                        'site'          : config.site,
                        'reason'        : jwt_reason,
                        'challenge'     : challenge,
                    }
            redirect_challenge = jwt.encode(payload=jwt_data,
                                            key=site_key,
                                            algorithm='RS256')
            # Get JWT from other site.
            verify_args = {
                            'username'          : username,
                            'password'          : password,
                            'mschap_challenge'  : mschap_challenge,
                            'mschap_response'   : mschap_response,
                            'host'              : config.host_data['name'],
                            'jwt_reason'        : jwt_reason,
                            'jwt_challenge'     : redirect_challenge,
                            #'jwt_accessgroup'   : config.sso_access_group,
                        }
            # Send verify request.
            if auth_type == "mschap":
                verify_command = "token_verify_mschap"
            else:
                verify_command = "token_verify"
            try:
                status, \
                status_code, \
                auth_response, \
                binary_data = authd_conn.send(command=verify_command,
                                            command_args=verify_args)
            except Exception as e:
                message, log_msg = _("Failed to authenticate user", log=True)
                log_msg = f"{log_msg}: {e}"
                self.logger.critical(log_msg)
                status = False
                return self.build_response(status, message)
            finally:
                authd_conn.close()

            if not status:
                message, log_msg = _("Remote authentication failed: {user}", log=True)
                log_msg = log_msg.format(user=user.name)
                message = message.format(user=user.name)
                self.logger.warning(log_msg)
                return self.build_response(status, message)

            try:
                redirect_response = auth_response['jwt']
            except KeyError:
                status = False
                message = _("Auth response misses JWT.")
                return self.build_response(status, message)

            nt_key = None
            if auth_type == "mschap":
                try:
                    nt_key = auth_response['nt_key']
                except KeyError:
                    status = False
                    message = _("Auth response misses NT_KEY.")
                    return self.build_response(status, message)

            # Try local JWT auth.
            auth_response = user.authenticate(auth_type="jwt",
                                        client=client,
                                        client_ip=client_ip,
                                        realm_login=False,
                                        realm_logout=False,
                                        jwt_reason=jwt_reason,
                                        verify_jwt_ag=False,
                                        redirect_challenge=redirect_challenge,
                                        redirect_response=redirect_response)
            auth_status = auth_response['status']
            if not auth_status:
                status = False
                message = _("JWT authentication failed.")
                return self.build_response(status, message)

            # Add NT_KEY to response.
            if auth_type == "mschap":
                auth_response['nt_key'] = nt_key

            # We will not send auth token instance to peer.
            try:
                auth_response.pop('token')
            except KeyError:
                pass

            return self.build_response(status, auth_response)

        # Indicates if authentication was successful.
        auth_status = False

        # Set proctitle to contain username.
        self.set_proctitle(username)

        if command == "token_verify" or command == "token_verify_mschap":
            if self.peer.type != "node":
                status = status_codes.PERMISSION_DENIED
                message = _("Access denied.")
                return self.build_response(status, message)
            try:
                jwt_reason = command_args['jwt_reason']
            except:
                jwt_reason = None
            try:
                jwt_challenge = command_args['jwt_challenge']
            except:
                jwt_challenge = None
            # Get audit logger.
            try:
                audit_logger = get_audit_logger()
            except Exception as e:
                log_msg = _("Failed to get audit logger: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                audit_logger = None
            if command == "token_verify":
                token_verify_parms = {
                        'auth_type'         : "clear-text",
                        'password'          : password,
                        'otp'               : password,
                        }
            if command == "token_verify_mschap":
                token_verify_parms = {
                        'auth_type' : "mschap",
                        'challenge' : mschap_challenge,
                        'response'  : mschap_response,
                        }
            auth_token = None
            for x_token in user.get_tokens(return_type="instance"):
                if command == "token_verify_mschap":
                    if not x_token.mschap_enabled:
                        continue
                try:
                    verify_status = x_token.verify(**token_verify_parms)
                except Exception as e:
                    log_msg = _("Verification of token '{token_name}' returned error: {error}", log=True)[1]
                    log_msg = log_msg.format(token_name=x_token.name, error=e)
                    self.logger.critical(log_msg)
                    continue
                if verify_status is None:
                    continue
                auth_token = x_token
                break

            _jwt = None
            auth_status = False
            if auth_token:
                auth_status = True
                try:
                    _jwt = self.gen_jwt(username=auth_token.owner,
                                        token=auth_token,
                                        reason=jwt_reason,
                                        challenge=jwt_challenge)
                except AccessDenied:
                    status = False
                    message = _("Unable to gen JWT.")
                    return self.build_response(status, message)
                nt_key = None
                if command == "token_verify_mschap":
                    nt_key = verify_status[1]
                auth_response = {
                            'status'        : auth_status,
                            'login_token'   : auth_token.rel_path,
                            'message'       : "Token successfully verified.",
                            'nt_key'        : nt_key,
                            'jwt'           : _jwt,
                            }
                log_msg = _("Token verified successful: {token}", log=True)[1]
                log_msg = log_msg.format(token=auth_token.rel_path)
                self.logger.info(log_msg)
                # Audit logging.
                if audit_logger:
                    audit_msg = f"{config.daemon_name}: {log_msg}"
                    self.audit_logger.info(audit_msg)
                    for x in self.audit_logger.handlers:
                        x.close()
            else:
                auth_response = {
                            'status'    : auth_status,
                            'message'   : "Auth failed.",
                            }
                log_msg = _("Token verification failed: {user}", log=True)[1]
                log_msg = log_msg.format(user=user.name)
                self.logger.warning(log_msg)
                # Audit logging.
                if audit_logger:
                    audit_msg = f"{config.daemon_name}: {log_msg}"
                    self.audit_logger.warning(audit_msg)
                    for x in self.audit_logger.handlers:
                        x.close()
        else:
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
            auth_response = user.authenticate(**kwargs)
            # Get auth status and message from response.
            auth_status = auth_response['status']
            # We will not send auth token instance to peer.
            try:
                auth_response.pop('token')
            except KeyError:
                pass

        # Build response message.
        message = auth_response
        if auth_status:
            status = True
        else:
            status = status_codes.ERR

        return self.build_response(status, message)

    def _close(self):
        pass
