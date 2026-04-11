# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
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
from otpme.lib import oid
from otpme.lib import jwt
from otpme.lib import sotp
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

DEPLOY_NAME = "sso-deploy"

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-sso-1.0"

def register():
    config.register_otpme_protocol("ssod", PROTOCOL_VERSION, server=True)

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

def get_apps(user):
    """ Return SSO app metadata visible to the given user. """
    app_data = []
    result = backend.search(object_type="client",
                            attribute="sso_enabled",
                            value=True,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    if not result:
        return app_data
    user_ags = user.get_access_groups(return_type="uuid")
    for client in result:
        if not client.enabled:
            continue
        client_ag = backend.get_object(uuid=client.access_group_uuid)
        if client_ag.uuid not in user_ags:
            continue
        client_data = {
                    'app_ag'    : client_ag.name,
                    'app_name'  : client.sso_name,
                    'login_url' : client.login_url,
                    'helper_url': client.helper_url,
                    'sso_popup' : client.sso_popup,
                }
        if client.sso_logo:
            client_data['logo_type'] = client.sso_logo['image_type']
            client_data['logo_data'] = client.sso_logo['image_data']
        app_data.append(client_data)
    return app_data

class OTPmeSsoP1(OTPmeServer1):
    """ Class that implements OTPme-sso-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "ssod"
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

    def ssod_redirect_command(self, command, user, command_args):
        try:
            ssod_conn = connections.get("ssod",
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
            deploy_data, \
            binary_data = ssod_conn.send(command=command,
                                        command_args=command_args)
        except Exception as e:
            log_msg = _("Failed to redirect command: {command}", log=True)[1]
            log_msg = log_msg.format(command=command)
            log_msg = f"{log_msg}: {e}"
            self.logger.warning(log_msg)
            auth_response = {'message':'REDIRECT_CONN_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        finally:
            ssod_conn.close()
        return self.build_response(status, deploy_data)

    def verify_sso_jwt(self, username, sso_jwt):
        # Get user.
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if not user:
            msg = "AUTH_UNKOWN_USER"
            raise OTPmeException(msg)
        # Get users site public key to verify the JWT.
        user_site = backend.get_object(object_type="site",
                                    uuid=user.site_uuid)
        site_jwt_key = user_site._cert_public_key
        # Decode JWT.
        jwt.decode(jwt=sso_jwt, key=site_jwt_key, algorithm='RS256')
        return user

    def get_apps(self, username, sso_jwt, command_args):
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'JWT_INVALID', 'status':False}
            return self.build_response(False, auth_response)
        # App data is always served by the local node — no cross-site redirect.
        app_data = get_apps(user)
        return self.build_response(True, {'app_data': app_data, 'status': True})

    def get_sotp(self, username, sso_jwt, command_args):
        try:
            access_group = command_args['access_group']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            session_uuid = command_args['session_uuid']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'JWT_INVALID', 'status':False}
            return self.build_response(status, auth_response)
        # Get session.
        session = backend.get_object(uuid=session_uuid)
        if not session:
            status = False
            auth_response = {'message':'UNKNOWN_SESSION', 'status':False}
            return self.build_response(status, auth_response)
        # Verify session belongs to the authenticated user.
        if session.user_uuid != user.uuid:
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Gen SOTP.
        result = backend.search(object_type="accessgroup",
                             attribute="name",
                             value=access_group,
                             return_type="uuid")
        if not result:
            auth_response = {'message':'UNKNOWN_AG', 'status':False}
            return self.build_response(status, auth_response)
        ag_uuid = result[0]
        sotp_data = sotp.gen(password_hash=session.pass_hash,
                         access_group=ag_uuid)
        return self.build_response(True, sotp_data)

    def deploy_begin(self, username, sso_jwt, command_args):
        try:
            token_type = command_args['token_type']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            login_token_uuid = command_args['login_token_uuid']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="deploy_begin",
                                            user=user,
                                            command_args=command_args)
        # Prepare deploy.
        login_token = backend.get_object(uuid=login_token_uuid)
        login_token_name = login_token.name
        # Remove old sso-deploy token if it exists (e.g. from a previous attempt).
        old_deploy = user.token(DEPLOY_NAME)
        if old_deploy:
            user.del_token(token_name=DEPLOY_NAME,
                            force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=config.get_callback())
        # Create sso-deploy token under the user.
        try:
            user.add_token(token_name=DEPLOY_NAME,
                            token_type=token_type,
                            no_token_infos=True,
                            mode="mode1",
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=config.get_callback())
        except Exception as e:
            log_msg = _("SSO deploy failed for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name)
            self.logger.critical(log_msg)
            response = {'message':'DEPLOY_FAILED', 'status':False}
            return self.build_response(status, response)
        # Get deploy token.
        deploy_token = user.token(DEPLOY_NAME)
        if not deploy_token:
            response = {'message':'DEPLOY_FAILED', 'status':False}
            return self.build_response(status, response)
        # Build response.
        response = {
                    'token_type'                : token_type,
                    'deploy_token_name'         : DEPLOY_NAME,
                    'deploy_login_token_name'   : login_token_name,
                }
        # For FIDO2 tokens, use the WebAuthn registration flow.
        if token_type == "fido2":
            return self.build_response(True, response)
        deploy_token._write(callback=config.get_callback())
        # Get token secret.
        secret = deploy_token.get_secret(pin=deploy_token.pin, encoding="base32")
        # For OATH tokens (TOTP/HOTP): generate QR code.
        try:
            qrcode_data = deploy_token.gen_qrcode(pin=deploy_token.pin,
                                                  fmt="svg",
                                                  run_policies=False,
                                                  verify_acls=False)
            if isinstance(qrcode_data, bytes):
                qrcode_data = qrcode_data.decode('utf-8')
            qrcode_data_uri = "data:image/svg+xml;base64," + base64.b64encode(qrcode_data.encode()).decode()
        except Exception as e:
            log_msg = _("QR code generation failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            response = {'message':'DEPLOY_FAILED', 'status':False}
            return self.build_response(status, response)
        response['secret'] = secret
        response['pin'] = deploy_token.pin
        response['qrcode_img'] = qrcode_data_uri
        log_msg = _("SSO deploy started for user '{user_name}', token type '{token_type}'.", log=True)[1]
        log_msg = log_msg.format(user_name=user.name, token_type=token_type)
        self.logger.info(log_msg)
        return self.build_response(True, response)

    def deploy_verify(self, username, sso_jwt, command_args):
        try:
            token_data = command_args['token_data']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            login_token_name = command_args['login_token_name']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="deploy_verify",
                                            user=user,
                                            command_args=command_args)
        # Load the sso-deploy token.
        deploy_token = user.token(DEPLOY_NAME)
        if not deploy_token:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        # FIDO2 tokens are verified by the WebAuthn registration itself.
        # OATH tokens need OTP verification.
        if deploy_token.token_type == "fido2":
            if not deploy_token.credential_data:
                response = {'message':'Security key not registered yet.', 'status':False}
                return self.build_response(False, response)
        else:
            otp = str(token_data.get('otp', ''))
            if not otp:
                response = {'message':'OTP required.', 'status':False}
                return self.build_response(False, response)
            try:
                pin = deploy_token.pin or ""
                verify_result = deploy_token.verify_otp(otp=f"{pin}{otp}")
            except Exception as e:
                log_msg = _("SSO deploy OTP verification failed for user '{user_name}': {e}", log=True)[1]
                log_msg = log_msg.format(user_name=user.name, e=e)
                self.logger.warning(log_msg)
                response = {'message':'OTP verification failed.', 'status':False}
                return self.build_response(False, response)
            if not verify_result:
                response = {'message':'Invalid OTP. Please try again.', 'status':False}
                return self.build_response(False, response)
        # OTP verified - move sso-deploy token to replace the login token.
        target_path = f"{user.name}/{login_token_name}"
        try:
            deploy_token.move(target_path,
                            replace=True,
                            force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=config.get_callback())
        except Exception as e:
            log_msg = _("SSO deploy token move failed for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name, e=e)
            self.logger.critical(log_msg)
            response = {'message':'Token deployment failed.', 'status':False}
            return self.build_response(False, response)
        response = {'message':'Token deployment successful.', 'status':True}
        return self.build_response(True, response)

    def fido2_register_begin(self, username, sso_jwt, command_args):
        try:
            rp_id = command_args['rp_id']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            is_deploy = command_args['is_deploy']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="fido2_register_begin",
                                            user=user,
                                            command_args=command_args)
        # Find user's undeployed FIDO2 tokens (credential_data not set).
        user_tokens = backend.search(object_type="token",
                                    attribute="owner_uuid",
                                    value=user.uuid,
                                    return_type="instance")
        fido2_token = None
        existing_credentials = []
        # Skip excludeCredentials when replacing a token (sso-deploy flow),
        # so the user can re-use the same authenticator.
        for token in user_tokens:
            if token.token_type != "fido2":
                continue
            if token.credential_data:
                if not is_deploy:
                    cred_data = decode(token.credential_data, "hex")
                    existing_credentials.append(AttestedCredentialData(cred_data))
            elif fido2_token is None:
                fido2_token = token
        if not fido2_token:
            auth_response = {'message':'NO_TOKEN_FOUND', 'status':False}
            return self.build_response(status, auth_response)
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        user_data = {"id": user.name.encode(),
                    "name": user.name,
                    "displayName": user.name}
        create_options, reg_state = fido2_server.register_begin(
            user_data,
            credentials=existing_credentials,
            user_verification=fido2_token.uv or "preferred",
            authenticator_attachment="cross-platform",
        )
        fido2_reg_state = _serialize_fido2_state(reg_state)
        fido2_reg_data = {
                    'create_options'        : dict(create_options),
                    'fido2_reg_state'       : fido2_reg_state,
                    'fido2_reg_token_uuid'  : fido2_token.uuid,
                }
        return self.build_response(True, fido2_reg_data)

    def fido2_register_complete(self, username, sso_jwt, command_args):
        try:
            rp_id = command_args['rp_id']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            reg_state = command_args['reg_state']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            registration_data = command_args['registration_data']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            token_uuid = command_args['token_uuid']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="fido2_register_complete",
                                            user=user,
                                            command_args=command_args)
        # Deserialize reg state.
        reg_state = _deserialize_fido2_state(reg_state)
        # Get fido2 token
        fido2_token = backend.get_object(uuid=token_uuid)
        if not fido2_token:
            status = False
            auth_response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(status, auth_response)
        # Verify token belongs to user.
        if fido2_token.owner_uuid != user.uuid:
            status = False
            auth_response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(status, auth_response)
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        try:
            auth_data = fido2_server.register_complete(reg_state, registration_data)
        except Exception as e:
            log_msg = _("FIDO2 registration failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'REGISTRATION_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        # Store credential data on token.
        fido2_token.credential_data = encode(auth_data.credential_data, "hex")
        fido2_token._write(callback=config.get_callback())
        log_msg = _("FIDO2 token '{token}' registered for user '{user_name}'.")
        log_msg = log_msg.format(token=fido2_token.rel_path, user_name=user.name)
        self.logger.info(log_msg)
        response = {'message':log_msg, 'status':True}
        return self.build_response(True, response)

    def change_password(self, username, sso_jwt, command_args):
        try:
            token_path = command_args['token_path']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            current_password = command_args['current_password']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            new_password = command_args['new_password']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="change_password",
                                            user=user,
                                            command_args=command_args)
        # Get token.
        token_name = token_path.split("/")[1]
        token = backend.get_object(object_type="token",
                                    user=user.name,
                                    name=token_name,
                                    realm=config.realm)
        # Verify current password against the token.
        verify_result = token.verify_static(password=current_password,
                                            ignore_2f_token=True)
        if not verify_result:
            response = {'message':'Current password is incorrect.', 'status':False}
            return self.build_response(False, response)
        # Change password.
        callback = config.get_callback()
        callback.raise_exception = True
        try:
            token.change_password(password=new_password,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
        except Exception as e:
            message, log_msg = _("Password change failed for token: {token_path}: {e}", log=True)
            log_msg = log_msg.format(token_path=token_path, e=e)
            self.logger.warning(log_msg)
            message = message.format(token_path=token_path, e=e)
            response = {'message':message, 'status':False}
            return self.build_response(False, response)
        # Write token.
        token._write(callback=callback)
        message = _("Token password changed successfully.")
        return self.build_response(True, message)

    def change_pin(self, username, sso_jwt, command_args):
        try:
            token_path = command_args['token_path']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            current_pin = command_args['current_pin']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            new_pin = command_args['new_pin']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            status = False
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(status, auth_response)
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="change_pin",
                                            user=user,
                                            command_args=command_args)
        # Get token.
        token_name = token_path.split("/")[1]
        token = backend.get_object(object_type="token",
                                    user=user.name,
                                    name=token_name,
                                    realm=config.realm)
        if not token:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        # Verify token belongs to user.
        if token.owner_uuid != user.uuid:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        if token.pass_type != "otp":
            response = {'message':'Token does not support PIN change.', 'status':False}
            return self.build_response(False, response)
        # Verify current PIN against the token.
        if not token.pin or str(token.pin) != str(current_pin):
            response = {'message':'Current PIN is incorrect.', 'status':False}
            return self.build_response(False, response)
        # Change PIN.
        callback = config.get_callback()
        callback.raise_exception = True
        try:
            token.change_pin(pin=new_pin,
                            run_policies=False,
                            verify_acls=False,
                            callback=callback)
        except Exception as e:
            message, log_msg = _("PIN change failed for token: {token_path}: {e}", log=True)
            log_msg = log_msg.format(token_path=token_path, e=e)
            self.logger.warning(log_msg)
            message = message.format(token_path=token_path, e=e)
            response = {'message':message, 'status':False}
            return self.build_response(False, response)
        # Write token.
        token._write(callback=callback)
        message = _("Token PIN changed successfully.")
        return self.build_response(True, message)

    def _get_sso_token_role(self, user):
        """ Resolve the sso_token_role config parameter to a role instance.
        Must be called on the user's home site — the config parameter walks
        up the user's parent hierarchy to find the canonical value. """
        role_name = user.get_config_parameter("sso_token_role")
        if not role_name:
            return None
        if "/" in role_name:
            role_site = role_name.split("/")[0]
            role_name = role_name.split("/")[1]
        else:
            role_site = config.site
        result = backend.search(object_type="role",
                                attribute="name",
                                value=role_name,
                                realm=config.realm,
                                site=role_site,
                                return_type="instance")
        if not result:
            return None
        return result[0]

    def _resolve_sso_token_role(self, user, command_args):
        """ Resolve sso_token_role to a role instance. Cross-site users go
        through their home site's ssod to obtain the role UUID, then the
        role object is loaded locally via cluster-synced backend. """
        if user.site == config.site:
            return self._get_sso_token_role(user)
        status, resp = self._remote_ssod_call(user=user,
                                            command="sso_get_device_token_role_uuid",
                                            extra_args=command_args)
        if not status or not isinstance(resp, dict):
            return None
        role_uuid = resp.get('role_uuid')
        if not role_uuid:
            return None
        return backend.get_object(object_type="role", uuid=role_uuid)

    def sso_get_device_token_role_uuid(self, username, sso_jwt, command_args):
        """ Internal cross-site command: resolve sso_token_role on the
        user's home site and return its UUID. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'AUTH_FAILED', 'status':False})
        if user.site != config.site:
            return self.build_response(False, {'message':'WRONG_SITE', 'status':False})
        role = self._get_sso_token_role(user)
        if not role:
            return self.build_response(False, {'message':'sso_token_role is not configured.', 'status':False})
        return self.build_response(True, {'role_uuid': role.uuid, 'status': True})

    def _sanitize_device_token_name(self, device_name):
        """ Build a valid token name from a user-supplied device name. """
        name = device_name.strip().lower()
        out = []
        for ch in name:
            if ch.isalnum() or ch in "_.-:":
                out.append(ch)
            elif ch == " ":
                out.append("-")
        sanitized = "".join(out).strip("-._:")
        if not sanitized:
            return None
        return f"device-{sanitized}"

    def list_device_tokens(self, username, sso_jwt, command_args):
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        # The role UUID must come from the user's home site (config walks
        # up the user hierarchy), but the role object itself is
        # cluster-synced and loaded locally.
        role = self._resolve_sso_token_role(user, command_args)
        if not role:
            # Report this as a successful response with role_configured=False
            # so the frontend can disable the add form instead of showing a
            # load error to the user.
            response = {
                        'device_tokens'     : [],
                        'role_configured'   : False,
                        'role_info'         : "",
                        'status'            : True,
                    }
            return self.build_response(True, response)
        device_tokens = []
        for token_uuid in role.tokens:
            token = backend.get_object(object_type="token", uuid=token_uuid)
            if not token:
                continue
            if token.owner_uuid != user.uuid:
                continue
            if token.token_type != "password":
                continue
            device_tokens.append({
                        'name'          : token.name,
                        'device_name'   : token.description or token.name,
                    })
        response = {
                    'device_tokens'     : device_tokens,
                    'role_configured'   : True,
                    'role_info'         : role.info or "",
                    'status'            : True,
                }
        return self.build_response(True, response)

    def _local_create_device_token(self, user, token_name, device_name, callback):
        """ Create a password device token for the given user on this node.
        Returns (token_instance, new_password). The token is already written
        to the local backend. """
        new_password = user.add_token(token_name=token_name,
                                    token_type="password",
                                    no_token_infos=True,
                                    gen_qrcode=False,
                                    verify_acls=False,
                                    run_policies=False,
                                    callback=callback)
        token = user.token(token_name)
        if not token:
            raise OTPmeException("Failed to create device token.")
        token.description = device_name
        token.update_index('description', token.description)
        token._write(callback=callback)
        return token, new_password

    def sso_create_device_token(self, username, sso_jwt, command_args):
        """ Internal cross-site command: create a password device token on
        the user's home site and return the token's OID/OC together with
        the sso_token_role UUID (which must be resolved here, on the user's
        home site, since the config parameter walks up the user hierarchy).
        The calling site mirrors the token OC locally and then adds the
        token to the role. """
        try:
            token_name = command_args['token_name']
            device_name = command_args['device_name']
        except KeyError:
            return self.build_response(False, _("AUTHD_INCOMPLETE_COMMAND"))
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'AUTH_FAILED', 'status':False})
        if user.site != config.site:
            return self.build_response(False, {'message':'WRONG_SITE', 'status':False})
        # Resolve the sso_token_role on the user's home site — this is the
        # authoritative location since the config parameter walks up the
        # user's parent hierarchy.
        role = self._get_sso_token_role(user)
        if not role:
            return self.build_response(False, {'message':'sso_token_role is not configured.', 'status':False})
        if user.token(token_name):
            return self.build_response(False, {'message':'A device with this name already exists.', 'status':False})
        callback = config.get_callback()
        callback.raise_exception = True
        try:
            token, new_password = self._local_create_device_token(user=user,
                                                    token_name=token_name,
                                                    device_name=device_name,
                                                    callback=callback)
        except Exception as e:
            log_msg = _("Failed to create device token for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to create device token: {e}', 'status':False})
        # Read the object config so the calling site can mirror it locally.
        oc_obj = backend.read_config(token.oid)
        if not oc_obj:
            return self.build_response(False, {'message':'Failed to read token object config.', 'status':False})
        response = {
                    'status'        : True,
                    'password'      : new_password,
                    'token_full_oid': token.oid.full_oid,
                    'token_oc'      : oc_obj.copy(),
                    'role_uuid'     : role.uuid,
                }
        return self.build_response(True, response)

    def sso_delete_device_token(self, username, sso_jwt, command_args):
        """ Internal cross-site command: delete a password device token on
        the user's home site. """
        try:
            token_name = command_args['token_name']
        except KeyError:
            return self.build_response(False, _("AUTHD_INCOMPLETE_COMMAND"))
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'AUTH_FAILED', 'status':False})
        if user.site != config.site:
            return self.build_response(False, {'message':'WRONG_SITE', 'status':False})
        callback = config.get_callback()
        callback.raise_exception = True
        try:
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
        except Exception as e:
            log_msg = _("Failed to delete device token '{token}' for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to delete device token: {e}', 'status':False})
        return self.build_response(True, {'status': True})

    def _remote_ssod_call(self, user, command, extra_args):
        """ Run an ssod command on the user's home site. """
        try:
            ssod_conn = connections.get("ssod",
                                        realm=config.realm,
                                        site=user.site,
                                        auto_preauth=True,
                                        auto_auth=False)
        except Exception as e:
            log_msg = _("Remote ssod connection failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return False, {'message':'REDIRECT_CONN_FAILED', 'status':False}
        try:
            status, \
            status_code, \
            response, \
            binary_data = ssod_conn.send(command=command, command_args=extra_args)
        except Exception as e:
            log_msg = _("Remote ssod command '{command}' failed: {e}", log=True)[1]
            log_msg = log_msg.format(command=command, e=e)
            self.logger.warning(log_msg)
            return False, {'message':'REDIRECT_CONN_FAILED', 'status':False}
        finally:
            ssod_conn.close()
        return status, response

    def add_device_token(self, username, sso_jwt, command_args):
        try:
            device_name = command_args['device_name']
        except:
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(False, message)
        if not device_name or not str(device_name).strip():
            response = {'message':'Device name required.', 'status':False}
            return self.build_response(False, response)
        device_name = str(device_name).strip()
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        token_name = self._sanitize_device_token_name(device_name)
        if not token_name:
            response = {'message':'Invalid device name.', 'status':False}
            return self.build_response(False, response)
        callback = config.get_callback()
        callback.raise_exception = True
        new_password = None
        role = None
        if user.site != config.site:
            # Token creation must happen on the user's home site (authoritative
            # write). The remote ssod also resolves the sso_token_role UUID —
            # that parameter walks up the user hierarchy so the canonical
            # value lives on the user's home site.
            remote_args = dict(command_args)
            remote_args['token_name'] = token_name
            remote_args['device_name'] = device_name
            status, remote_resp = self._remote_ssod_call(user=user,
                                                    command="sso_create_device_token",
                                                    extra_args=remote_args)
            if not status or not isinstance(remote_resp, dict):
                return self.build_response(False, remote_resp)
            new_password = remote_resp.get('password')
            token_full_oid = remote_resp.get('token_full_oid')
            token_oc = remote_resp.get('token_oc')
            role_uuid = remote_resp.get('role_uuid')
            if not token_full_oid or not token_oc or not role_uuid:
                return self.build_response(False, {'message':'Invalid remote response.', 'status':False})
            # Mirror the remote token object locally so list_device_tokens
            # and the role.add_token call below find it without waiting for
            # the cluster sync to catch up.
            try:
                token_oid = oid.get(object_id=token_full_oid, resolve=True)
                backend.write_config(object_id=token_oid,
                                    object_config=token_oc,
                                    full_index_update=True,
                                    full_data_update=True,
                                    cluster=False)
            except Exception as e:
                log_msg = _("Failed to mirror remote device token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                return self.build_response(False, {'message':f'Failed to write remote object locally: {e}', 'status':False})
            # Load the role (by UUID returned from remote) for the local
            # add-to-role step.
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if not role:
                return self.build_response(False, {'message':'sso_token_role not found locally.', 'status':False})
        else:
            role = self._get_sso_token_role(user)
            if not role:
                response = {'message':'sso_token_role is not configured.', 'status':False}
                return self.build_response(False, response)
            if user.token(token_name):
                response = {'message':'A device with this name already exists.', 'status':False}
                return self.build_response(False, response)
            try:
                _token, new_password = self._local_create_device_token(user=user,
                                                    token_name=token_name,
                                                    device_name=device_name,
                                                    callback=callback)
            except Exception as e:
                log_msg = _("Failed to add device token for user '{user_name}': {e}", log=True)[1]
                log_msg = log_msg.format(user_name=user.name, e=e)
                self.logger.warning(log_msg)
                response = {'message':f'Failed to add device token: {e}', 'status':False}
                return self.build_response(False, response)
        # Add the token to the sso_token_role on this node. role._write()
        # propagates the change back to the role's home site via the cluster.
        token_path = f"{user.name}/{token_name}"
        try:
            role.add_token(token_path=token_path,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
            role._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to add device token to role '{role}': {e}", log=True)[1]
            log_msg = log_msg.format(role=role.name, e=e)
            self.logger.warning(log_msg)
            # Roll back: delete the token so we don't leave an orphan.
            try:
                if user.site != config.site:
                    self._remote_ssod_call(user=user,
                                            command="sso_delete_device_token",
                                            extra_args={**command_args, 'token_name': token_name})
                else:
                    user.del_token(token_name=token_name,
                                    force=True,
                                    verify_acls=False,
                                    run_policies=False,
                                    callback=callback)
            except Exception:
                pass
            response = {'message':'Failed to add device token to role.', 'status':False}
            return self.build_response(False, response)
        log_msg = _("Device token '{token}' added for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token_name, user_name=user.name)
        self.logger.info(log_msg)
        response = {
                    'status'        : True,
                    'name'          : token_name,
                    'device_name'   : device_name,
                    'password'      : new_password,
                }
        return self.build_response(True, response)

    def del_device_token(self, username, sso_jwt, command_args):
        try:
            token_name = command_args['token_name']
        except:
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(False, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'AUTH_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        role = self._resolve_sso_token_role(user, command_args)
        if not role:
            response = {'message':'sso_token_role is not configured.', 'status':False}
            return self.build_response(False, response)
        token = user.token(token_name)
        if not token:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        if token.owner_uuid != user.uuid:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        # Only allow deletion of tokens that are part of the sso_token_role.
        if token.uuid not in role.tokens:
            response = {'message':'Not a device token.', 'status':False}
            return self.build_response(False, response)
        callback = config.get_callback()
        callback.raise_exception = True
        token_path = f"{user.name}/{token_name}"
        try:
            role.remove_token(token_path=token_path,
                            force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
            role._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to remove device token from role: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
        # Delete the token object on its canonical site.
        if user.site != config.site:
            remote_args = dict(command_args)
            remote_args['token_name'] = token_name
            status, remote_resp = self._remote_ssod_call(user=user,
                                                    command="sso_delete_device_token",
                                                    extra_args=remote_args)
            if not status:
                return self.build_response(False, remote_resp)
        else:
            try:
                user.del_token(token_name=token_name,
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
            except Exception as e:
                log_msg = _("Failed to delete device token '{token}' for user '{user_name}': {e}", log=True)[1]
                log_msg = log_msg.format(token=token_name, user_name=user.name, e=e)
                self.logger.warning(log_msg)
                response = {'message':'Failed to delete device token.', 'status':False}
                return self.build_response(False, response)
        log_msg = _("Device token '{token}' deleted for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token_name, user_name=user.name)
        self.logger.info(log_msg)
        response = {'message':'Device token deleted.', 'status':True}
        return self.build_response(True, response)

    def _process(self, command, command_args, **kwargs):
        """ Handle SSO commands received from client. """
        # All valid commands.
        valid_commands = [
                            "get_apps",
                            "get_sotp",
                            "deploy_begin",
                            "deploy_verify",
                            "change_password",
                            "change_pin",
                            "fido2_register_begin",
                            "fido2_register_complete",
                            "list_device_tokens",
                            "add_device_token",
                            "del_device_token",
                            "sso_create_device_token",
                            "sso_delete_device_token",
                            "sso_get_device_token_role_uuid",
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

        # Try to get username.
        try:
            username = command_args['username']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)

        # Set proctitle to contain username.
        self.set_proctitle(username)

        try:
            sso_jwt = command_args['sso_jwt']
        except:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)

        if command == "get_apps":
            log_msg = _("Processing command get_apps.", log=True)[1]
            self.logger.info(log_msg)
            return self.get_apps(username, sso_jwt, command_args)

        if command == "get_sotp":
            log_msg = _("Processing command get_sotp.", log=True)[1]
            self.logger.info(log_msg)
            return self.get_sotp(username, sso_jwt, command_args)

        if command == "deploy_begin":
            log_msg = _("Processing command deploy_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.deploy_begin(username, sso_jwt, command_args)

        if command == "deploy_verify":
            log_msg = _("Processing command deploy_verify.", log=True)[1]
            self.logger.info(log_msg)
            return self.deploy_verify(username, sso_jwt, command_args)

        if command == "fido2_register_begin":
            log_msg = _("Processing command fido2_register_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.fido2_register_begin(username, sso_jwt, command_args)

        if command == "fido2_register_complete":
            log_msg = _("Processing command fido2_register_complete.", log=True)[1]
            self.logger.info(log_msg)
            return self.fido2_register_complete(username, sso_jwt, command_args)

        if command == "change_password":
            log_msg = _("Processing command change_password.", log=True)[1]
            self.logger.info(log_msg)
            return self.change_password(username, sso_jwt, command_args)

        if command == "change_pin":
            log_msg = _("Processing command change_pin.", log=True)[1]
            self.logger.info(log_msg)
            return self.change_pin(username, sso_jwt, command_args)

        if command == "list_device_tokens":
            log_msg = _("Processing command list_device_tokens.", log=True)[1]
            self.logger.info(log_msg)
            return self.list_device_tokens(username, sso_jwt, command_args)

        if command == "add_device_token":
            log_msg = _("Processing command add_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.add_device_token(username, sso_jwt, command_args)

        if command == "del_device_token":
            log_msg = _("Processing command del_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.del_device_token(username, sso_jwt, command_args)

        if command == "sso_create_device_token":
            log_msg = _("Processing command sso_create_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.sso_create_device_token(username, sso_jwt, command_args)

        if command == "sso_delete_device_token":
            log_msg = _("Processing command sso_delete_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.sso_delete_device_token(username, sso_jwt, command_args)

        if command == "sso_get_device_token_role_uuid":
            log_msg = _("Processing command sso_get_device_token_role_uuid.", log=True)[1]
            self.logger.info(log_msg)
            return self.sso_get_device_token_role_uuid(username, sso_jwt, command_args)

        return self.build_response(status, message)

    def _close(self):
        pass
