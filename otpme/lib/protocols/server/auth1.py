# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
import time
import base64
import setproctitle
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData

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
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.encoding.base import decode
from otpme.lib.audit import get_audit_logger

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

DEPLOY_NAME = "sso-deploy"

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-auth-1.0"

def register():
    config.register_otpme_protocol("authd", PROTOCOL_VERSION, server=True)

def _serialize_fido2_state(state):
    """ Serialize fido2 state dict for Flask session storage. """
    serialized = {}
    for k, v in state.items():
        if isinstance(v, bytes):
            serialized[k] = base64.b64encode(v).decode('ascii')
            serialized['_b_' + k] = True
        else:
            serialized[k] = v
    return serialized

def _deserialize_fido2_state(data):
    """ Deserialize fido2 state dict from Flask session. """
    state = {}
    for k, v in data.items():
        if k.startswith('_b_'):
            continue
        if data.get('_b_' + k):
            state[k] = base64.b64decode(v)
        else:
            state[k] = v
    return state

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

    def get_audit_logger(self):
        # Get audit logger.
        try:
            audit_logger = get_audit_logger()
        except Exception as e:
            log_msg = _("Failed to get audit logger: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            audit_logger = None
        return audit_logger

    def get_user(self, username):
        # Check if user exists.
        if stuff.is_mac_address(username):
            result = backend.search(object_types=['host', 'device'],
                                    attribute="mac_address",
                                    value=username,
                                    realm=config.realm,
                                    run_policies=True,
                                    return_type="instance",
                                    _no_func_cache=True)
            if not result:
                return
            user = result[0]
        else:
            user = backend.get_object(object_type="user",
                                    name=username,
                                    realm=config.realm,
                                    run_policies=True,
                                    _no_func_cache=True)
        if not user:
            return
        return user

    def gen_jwt(self, username, token, reason, challenge, access_group=None, sso=False):
        if access_group:
            token_accessgroups = token.get_access_groups(return_type="uuid")
            try:
                ag_site = access_group.split("/")[0]
                ag_name = access_group.split("/")[1]
            except IndexError:
                msg = _("Invalid accessgroup name: {access_group}")
                msg = msg.format(access_group=access_group)
                raise AccessDenied(msg)
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=ag_name,
                                    realm=config.realm,
                                    site=ag_site)
            if not result:
                msg = _("Unknown accessgroup: {access_group}")
                msg = msg.format(access_group=access_group)
                raise AccessDenied(msg)
            ag_uuid = result[0]
            if ag_uuid not in token_accessgroups:
                msg = _("Token not in accessgroup: {token_path}: {access_group}")
                msg = msg.format(token_path=token.rel_path, access_group=access_group)
                raise AccessDenied(msg)

        # Load JWT signing key.
        user_site = backend.get_object(uuid=token.site_uuid)
        sign_key = user_site._key
        if not sign_key:
            msg = _("Access denied")
            raise AccessDenied(msg)

        # Get JWT validity from site config.
        if sso:
            jwt_valid_para = "sso_jwt_valid"
        else:
            jwt_valid_para = "auth_jwt_valid"
        jwt_valid = user_site.get_config_parameter(jwt_valid_para)
        try:
            jwt_valid = units.time2int(jwt_valid, time_unit="s")
        except Exception:
            msg = _("Invalid auth JWT validity.")
            raise ValueError(msg)

        # Build JWT.
        now = time.time()
        jwt_data = {
                'realm'             : config.realm,
                'site'              : config.site,
                'reason'            : reason,
                'message'           : "JWT signed by authd.",
                'challenge'         : challenge,
                'login_time'        : now,
                'exp'               : now + jwt_valid,
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

    def get_jwt(self, command_args):
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
            jwt_access_group = command_args['jwt_access_group']
        except:
            jwt_access_group = None

        try:
            _jwt = self.gen_jwt(username=config.auth_token.owner,
                                token=config.auth_token,
                                reason=jwt_reason,
                                challenge=jwt_challenge,
                                access_group=jwt_access_group)
        except AccessDenied as e:
            status = False
            message = _("Unable to gen JWT: {e}")
            message = message.format(e=e)
            return self.build_response(status, message)

        return self.build_response(True, _jwt)

    def get_apps(self, user):
        from otpme.lib.protocols.server.sso1 import get_apps
        return get_apps(user)

    def build_log_msg(self, command_error):
            log_msg = _("{command_error}: user={log_username} access_group={log_access_group} client={log_client} client_ip={log_client_ip} auth_mode={log_auth_mode} auth_type={log_auth_type}", log=True)[1]
            log_msg = log_msg.format(command_error=command_error, log_username=self.log_username, log_access_group=self.log_access_group, log_client=self.log_client, log_client_ip=self.log_client_ip, log_auth_mode=self.log_auth_mode, log_auth_type=self.log_auth_type)
            return log_msg

    def authd_redirect_command(self, command, user, command_args):
        try:
            authd_conn = connections.get("authd",
                                        realm=config.realm,
                                        site=user.site,
                                        auto_preauth=True,
                                        auto_auth=False)
        except Exception as e:
            log_msg = _("Redirect connection failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'REDIRECT_CONN_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        try:
            status, \
            status_code, \
            response, \
            binary_data = authd_conn.send(command=command,
                                        command_args=command_args)
        except Exception as e:
            log_msg = _("Failed to redirect command: {command}", log=True)[1]
            log_msg = log_msg.format(command=command)
            log_msg = f"{log_msg}: {e}"
            self.logger.warning(log_msg)
            auth_response = {'message':'REDIRECT_CONN_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        finally:
            authd_conn.close()
        return status, response

    def redirect_fido2_complete(self, user, smartcard_data, sso_challenge, client, client_ip):
        # Gen JWT to be signed by other site.
        my_site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)
        site_key = my_site._key
        jwt_reason = "AUTH"
        challenge = stuff.gen_secret(len=32)
        sso_jwt_ag = f"{config.site}/{config.sso_access_group}"
        jwt_data = {
                    'user'          : user.name,
                    'realm'         : config.realm,
                    'site'          : config.site,
                    'reason'        : jwt_reason,
                    'access_group'  : sso_jwt_ag,
                    'challenge'     : challenge,
                    'exp'           : time.time() + 60,
                }
        redirect_challenge = jwt.encode(payload=jwt_data,
                                        key=site_key,
                                        algorithm='RS256')
        verify_args = {
                        'username'          : user.name,
                        'client'            : client,
                        'client_ip'         : client_ip,
                        'sso_login'         : True,
                        'sso_challenge'     : sso_challenge,
                        'smartcard_data'    : smartcard_data,
                        'jwt_reason'        : jwt_reason,
                        'jwt_access_group'  : sso_jwt_ag,
                        'jwt_challenge'     : redirect_challenge,
                    }
        status, \
        response = self.authd_redirect_command(command="token_verify_fido2",
                                        user=user,
                                        command_args=verify_args)
        try:
            redirect_response = response['jwt']
        except KeyError:
            status = False
            message = _("Auth response misses JWT.")
            return self.build_response(status, message)
        # Try local JWT auth.
        auth_response = user.authenticate(auth_type="jwt",
                                    peer=self.peer,
                                    client=client,
                                    client_ip=client_ip,
                                    realm_login=False,
                                    realm_logout=False,
                                    jwt_auth=True,
                                    jwt_reason=jwt_reason,
                                    verify_jwt_ag=False,
                                    redirect_challenge=redirect_challenge,
                                    redirect_response=redirect_response)
        auth_status = auth_response['status']
        if not auth_status:
            status = False
            message = _("JWT authentication failed.")
            return self.build_response(status, message)
        # We will not send auth token instance to peer.
        try:
            auth_response.pop('token')
        except KeyError:
            pass
        # Get user apps.
        app_data = self.get_apps(user)
        auth_response['app_data'] = app_data
        # Get SSO jwt from remote auth response.
        auth_response['sso_jwt'] = response['sso_jwt']
        return self.build_response(status, auth_response)

    def fido2_auth_begin(self, username, command_args):
        try:
            rp_id = command_args['rp_id']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if not user:
            status = False
            command_error = "AUTH_UNKOWN_USER"
            auth_response = {'message':'Login failed.', 'status':False}
            log_msg = self.build_log_msg(command_error)
            self.logger.warning(log_msg)
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            status, \
            message = self.authd_redirect_command(command="fido2_auth_begin",
                                            user=user,
                                            command_args=command_args)
            return self.build_response(status, message)
        # Find user's deployed FIDO2 tokens.
        user_tokens = backend.search(object_type="token",
                                    attribute="owner_uuid",
                                    value=user.uuid,
                                    return_type="instance")
        credentials = []
        credential_token_map = {}
        for token in user_tokens:
            if token.token_type == "fido2" and token.credential_data:
                cred_data = decode(token.credential_data, "hex")
                acd = AttestedCredentialData(cred_data)
                credentials.append(acd)
                # Map base64url credential ID to token name for lookup in complete.
                cred_id_b64 = base64.urlsafe_b64encode(acd.credential_id).rstrip(b'=').decode()
                credential_token_map[cred_id_b64] = token.name
        if not credentials:
            status = False
            auth_response = {'message':'Login failed.', 'status':False}
            return self.build_response(status, auth_response)
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        request_options, auth_state = fido2_server.authenticate_begin(
            credentials,
            user_verification="preferred",
        )
        fido2_auth_state = _serialize_fido2_state(auth_state)
        fido2_credential_token_map = credential_token_map
        fido2_auth_data = {
                    'request_options'           : dict(request_options),
                    'fido2_auth_state'          : fido2_auth_state,
                    'fido2_credential_token_map': fido2_credential_token_map,
                }
        return self.build_response(True, fido2_auth_data)

    def fido2_auth_complete(self, username, client, client_ip, sso_challenge, command_args):
        try:
            rp_id = command_args['rp_id']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            auth_state = command_args['auth_state']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            auth_response = command_args['auth_response']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            matched_token_name = command_args['matched_token_name']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if not user:
            status = False
            command_error = "AUTH_UNKOWN_USER"
            auth_response = {'message':'Login failed.', 'status':False}
            log_msg = self.build_log_msg(command_error)
            self.logger.warning(log_msg)
            return self.build_response(status, auth_response)
        # Build smartcard_data for auth_handler.
        smartcard_data = {
            'rp_id': rp_id,
            'auth_state': auth_state,
            'auth_response': json.dumps(auth_response),
        }
        # Check for command redirection.
        if user.site != config.site:
            return self.redirect_fido2_complete(user=user,
                                        smartcard_data=smartcard_data,
                                        sso_challenge=sso_challenge,
                                        client=client,
                                        client_ip=client_ip)
        try:
            auth_result = user.authenticate(
                auth_type="smartcard",
                auth_mode="smartcard",
                client=config.sso_client_name,
                client_ip=client_ip,
                realm_login=False,
                realm_logout=False,
                smartcard_data=smartcard_data,
                user_token=matched_token_name,
            )
            auth_status = auth_result['status']
        except Exception as e:
            log_msg = _("FIDO2 authentication failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.critical(log_msg)
            status = False
            auth_response = {'message':'Login failed.', 'status':False}
            return self.build_response(status, auth_response)
        if not auth_status:
            status = False
            auth_response = {'message':'Login failed.', 'status':False}
            return self.build_response(status, auth_response)
        try:
            auth_token = auth_result.pop('token')
        except KeyError:
            auth_token = None
        # Gen JWT for SSO auth.
        if auth_token and client == config.sso_client_name:
            jwt_ag = f"{config.site}/{config.sso_access_group}"
            try:
                sso_jwt = self.gen_jwt(username=username,
                                    token=auth_token,
                                    reason="SSO_AUTH",
                                    challenge=sso_challenge,
                                    access_group=jwt_ag,
                                    sso=True)
            except AccessDenied as e:
                status = False
                message = _("Unable to gen SSO JWT: {e}")
                message = message.format(e=e)
                return self.build_response(status, message)
            auth_result['sso_jwt'] = sso_jwt
            # Get user apps.
            app_data = self.get_apps(user)
            auth_result['app_data'] = app_data
        return self.build_response(True, auth_result)

    def token_verify(self, user, auth_type, command, command_args,
        password=None, mschap_challenge=None, mschap_response=None,
        smartcard_data=None):
        try:
            jwt_reason = command_args['jwt_reason']
        except:
            jwt_reason = None
        try:
            jwt_challenge = command_args['jwt_challenge']
        except:
            jwt_challenge = None
        try:
            jwt_access_group = command_args['jwt_access_group']
        except:
            jwt_access_group = None
        try:
            sso_login = command_args['sso_login']
        except:
            sso_login = False
        try:
            sso_challenge = command_args['sso_challenge']
        except:
            sso_challenge = None
        # Get audit logger.
        audit_logger = self.get_audit_logger()
        if command == "token_verify":
            token_verify_parms = {
                    'auth_type'         : auth_type,
                    'password'          : password,
                    'otp'               : password,
                    }
        if command == "token_verify_mschap":
            token_verify_parms = {
                    'auth_type' : "mschap",
                    'challenge' : mschap_challenge,
                    'response'  : mschap_response,
                    }
        if command == "token_verify_fido2":
            token_verify_parms = {
                    'auth_type'     : "smartcard",
                    'smartcard_data': smartcard_data,
                    }
        auth_token = None
        for x_token in user.get_tokens(return_type="instance"):
            if command == "token_verify":
                if x_token.pass_type != "static":
                    if x_token.pass_type != "otp":
                        continue
            if command == "token_verify_mschap":
                if not x_token.mschap_enabled:
                    continue
            if command == "token_verify_fido2":
                if x_token.token_type != "fido2":
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
                                    access_group=jwt_access_group,
                                    challenge=jwt_challenge)
            except AccessDenied as e:
                status = False
                message = _("Unable to gen JWT: {e}")
                message = message.format(e=e)
                return self.build_response(status, message)
            nt_key = None
            if command == "token_verify_mschap":
                nt_key = verify_status[1]
            sso_jwt = None
            if sso_login:
                # Gen jwt for SSO auth.
                jwt_ag = f"{config.site}/{config.sso_access_group}"
                try:
                    sso_jwt = self.gen_jwt(username=user.name,
                                        token=auth_token,
                                        reason="SSO_AUTH",
                                        challenge=sso_challenge,
                                        access_group=jwt_ag,
                                        sso=True)
                except AccessDenied as e:
                    status = False
                    message = _("Unable to gen SSO JWT: {e}")
                    message = message.format(e=e)
                    return self.build_response(status, message)
            auth_response = {
                        'status'        : auth_status,
                        'login_token'   : auth_token.rel_path,
                        'message'       : "Token successfully verified.",
                        'nt_key'        : nt_key,
                        'sso_jwt'       : sso_jwt,
                        'jwt'           : _jwt,
                        }
            log_msg = _("Token verified successful: {token}", log=True)[1]
            log_msg = log_msg.format(token=auth_token.rel_path)
            self.logger.info(log_msg)
            # Audit logging.
            if audit_logger:
                audit_msg = f"{config.daemon_name}: {log_msg}"
                audit_logger.info(audit_msg)
                for x in audit_logger.handlers:
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
                audit_logger.warning(audit_msg)
                for x in audit_logger.handlers:
                    x.close()
        # Build response message.
        message = auth_response
        if auth_status:
            status = True
        else:
            status = status_codes.ERR
        return self.build_response(status, message)

    def do_redirect_auth(self, user, auth_type, sso_challenge=None,
        password=None, mschap_challenge=None, mschap_response=None,
        access_group=None, client=None, client_ip=None):
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
                    'exp'           : time.time() + 60,
                }
        redirect_challenge = jwt.encode(payload=jwt_data,
                                        key=site_key,
                                        algorithm='RS256')
        # Get JWT from other site.
        verify_args = {
                        'username'          : user.name,
                        'password'          : password,
                        'mschap_challenge'  : mschap_challenge,
                        'mschap_response'   : mschap_response,
                        'host'              : config.host_data['name'],
                        'jwt_reason'        : jwt_reason,
                        'jwt_challenge'     : redirect_challenge,
                        'jwt_access_group'  : access_group,
                    }
        if client == config.sso_client_name:
            verify_args['sso_login'] = True
            verify_args['sso_challenge'] = sso_challenge

        # Send verify request.
        if auth_type == "mschap":
            verify_command = "token_verify_mschap"
        else:
            verify_command = "token_verify"
        try:
            status, \
            status_code, \
            redirect_auth_response, \
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
            redirect_response = redirect_auth_response['jwt']
        except KeyError:
            status = False
            message = _("Auth response misses JWT.")
            return self.build_response(status, message)

        nt_key = None
        if auth_type == "mschap":
            try:
                nt_key = redirect_auth_response['nt_key']
            except KeyError:
                status = False
                message = _("Auth response misses NT_KEY.")
                return self.build_response(status, message)

        # Try local JWT auth.
        auth_response = user.authenticate(auth_type="jwt",
                                    peer=self.peer,
                                    client=client,
                                    client_ip=client_ip,
                                    realm_login=False,
                                    realm_logout=False,
                                    jwt_auth=True,
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
            auth_token = auth_response.pop('token')
        except KeyError:
            auth_token = None

        if auth_token and client == config.sso_client_name:
            # Get user apps.
            app_data = self.get_apps(user)
            auth_response['app_data'] = app_data
            # Get SSO jwt from remote auth response.
            auth_response['sso_jwt'] = redirect_auth_response['sso_jwt']
        return self.build_response(status, auth_response)

    def auth_user(self, user, auth_type, auth_mode,
        password=None, mschap_challenge=None, mschap_response=None,
        access_group=None, sso_challenge=None, host=None,
        host_type=None, host_ip=None, client=None, client_ip=None):
        # Build auth request.
        kwargs = {
                    'auth_mode'     : auth_mode,
                    'auth_type'     : auth_type,
                    'peer'          : self.peer,
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
        if not auth_status:
            status = False
            message = _("Authentication failed.")
            return self.build_response(status, message)
        # We will not send auth token instance to peer.
        try:
            auth_token = auth_response.pop('token')
        except KeyError:
            auth_token = None
        # Gen JWT for SSO auth.
        if auth_token and client == config.sso_client_name:
            sso_jwt_ag = f"{config.site}/{config.sso_access_group}"
            try:
                sso_jwt = self.gen_jwt(username=user.name,
                                    token=auth_token,
                                    reason="SSO_AUTH",
                                    challenge=sso_challenge,
                                    access_group=sso_jwt_ag,
                                    sso=True)
            except AccessDenied as e:
                status = False
                message = _("Unable to gen SSO JWT: {e}")
                message = message.format(e=e)
                return self.build_response(status, message)
            auth_response['sso_jwt'] = sso_jwt
            # Get user apps.
            app_data = self.get_apps(user)
            auth_response['app_data'] = app_data

        # Build response message.
        message = auth_response
        if auth_status:
            status = True
        else:
            status = status_codes.ERR

        return self.build_response(status, message)

    def _process(self, command, command_args, **kwargs):
        """ Handle authentication data received from auth_handler. """
        # All valid commands.
        valid_commands = [
                            "verify",
                            "get_jwt",
                            "token_verify",
                            "token_verify_mschap",
                            "token_verify_fido2",
                            "verify_static",
                            "verify_mschap",
                            "fido2_auth_begin",
                            "fido2_auth_complete",
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
            return self.get_jwt(command_args)

        # Try to get username.
        try:
            username = command_args['username']
        except:
            username = None

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

        try:
            smartcard_data = command_args['smartcard_data']
        except:
            smartcard_data = None

        try:
            access_group = command_args['access_group']
        except:
            access_group = None

        try:
            sso_logout = command_args['sso_logout']
        except:
            sso_logout = False

        try:
            sso_challenge = command_args['sso_challenge']
        except:
            sso_challenge = None

        # Set host IP from source IP if requested.
        if host_ip == "auto":
            if not config.use_api:
                host_ip = self.client.split(":")[0]
            else:
                host_ip = None

        # Set auth mode.
        auth_mode = "auto"

        # Set auth type.
        if command == "verify":
            auth_type = "clear-text"
        if command == "verify_static":
            auth_type = "clear-text"
        if command == "verify_mschap":
            auth_type = "mschap"
        if command == "token_verify":
            auth_type = "clear-text"
        if command == "token_verify_mschap":
            auth_type = "mschap"
        if command == "token_verify_fido2":
            auth_type = "smartcard"
        if command == "fido2_auth_begin":
            auth_type = "smartcard"
        if command == "fido2_auth_complete":
            auth_type = "smartcard"

        # Set log variables.
        self.log_auth_mode = auth_mode
        self.log_auth_type = auth_type
        self.log_username = username
        self.log_access_group = access_group
        self.log_client = None
        self.log_client_ip = None
        if client:
            self.log_client = client
        if client_ip:
            self.log_client_ip = client_ip
        if host:
            self.log_client = host
        if host_ip:
            self.log_client_ip = host_ip

        if command == "fido2_auth_begin":
            log_msg = _("Processing command fido2_auth_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.fido2_auth_begin(username, command_args)

        if command == "fido2_auth_complete":
            log_msg = _("Processing command fido2_auth_complete.", log=True)[1]
            self.logger.info(log_msg)
            return self.fido2_auth_complete(username, client, client_ip, sso_challenge, command_args)

        # Check for incomplete command.
        incomplete_command = False
        if not username:
            incomplete_command = True
        if not client and not client_ip and not host:
            incomplete_command = True
        if password is None:
            if smartcard_data is None:
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
            log_msg = self.build_log_msg(command_error)
            self.logger.error(log_msg)
            return self.build_response(status, message)

        # Get user/host/device.
        user = self.get_user(username)
        if not user:
            status = False
            command_error = "AUTH_UNKOWN_USER"
            auth_response = {'message':'Login failed.', 'status':False}
            log_msg = self.build_log_msg(command_error)
            self.logger.warning(log_msg)
            return self.build_response(status, auth_response)

        if user.realm != config.realm:
            status = False
            message = _("Cross realm auth not supported yet.")
            return self.build_response(status, message)

        redirect_connection = False
        if user.site != config.site:
            try:
                stuff.get_site_trust_status(user.realm, user.site)
            except SiteNotTrusted:
                redirect_connection = True
        if sso_logout:
            redirect_connection = False

        # Set proctitle to contain username.
        self.set_proctitle(username)

        # Do redirected authentication.
        if redirect_connection:
            return self.do_redirect_auth(user=user,
                                        auth_type=auth_type,
                                        sso_challenge=sso_challenge,
                                        password=password,
                                        mschap_challenge=mschap_challenge,
                                        mschap_response=mschap_response,
                                        access_group=access_group,
                                        client=client,
                                        client_ip=client_ip)

        if command == "token_verify" \
        or command == "token_verify_mschap" \
        or command == "token_verify_fido2":
            if self.peer.type != "node":
                status = status_codes.PERMISSION_DENIED
                message = _("Access denied.")
                return self.build_response(status, message)
            return self.token_verify(user=user,
                                    auth_type=auth_type,
                                    command=command,
                                    command_args=command_args,
                                    password=password,
                                    mschap_challenge=mschap_challenge,
                                    mschap_response=mschap_response,
                                    smartcard_data=smartcard_data)

        return self.auth_user(user=user,
                            auth_type=auth_type,
                            auth_mode=auth_mode,
                            password=password,
                            mschap_challenge=mschap_challenge,
                            mschap_response=mschap_response,
                            access_group=access_group,
                            sso_challenge=sso_challenge,
                            host=host,
                            host_ip=host_ip,
                            host_type=host_type,
                            client=client,
                            client_ip=client_ip)

    def _close(self):
        pass
