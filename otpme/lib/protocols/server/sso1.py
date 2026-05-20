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
except Exception:
    pass

from otpme.lib import log
from otpme.lib import oid
from otpme.lib import jwt
from otpme.lib import sotp
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.audit import emit_audit
from otpme.lib.protocols.oidc_helpers import verify_pkce as _verify_pkce_helper
from otpme.lib.protocols.oidc_helpers import compute_acr as _compute_acr_helper
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

def get_apps(token):
    """ Return SSO app metadata visible to the given token. """
    app_data = []
    search_attributes = {
                        "oidc_auth"     : {'or_values'  : [True]},
                        "sso_enabled"   : {'or_values'  : [True]},
                    }
    result = backend.search(object_type="client",
                            attributes=search_attributes,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    if not result:
        return app_data
    token_ags = token.get_access_groups(return_type="uuid")
    for client in result:
        if not client.enabled:
            continue
        if not client.access_group_uuid:
            continue
        client_ag = backend.get_object(uuid=client.access_group_uuid)
        if client_ag.uuid not in token_ags:
            continue
        client_data = {
                    'app_ag'    : client_ag.name,
                    'app_name'  : client.sso_name,
                    'login_url' : client.login_url,
                }
        if client.sso_enabled:
            client_data['helper_url'] = client.helper_url
            client_data['sso_popup'] = client.sso_popup
        if client.oidc_auth:
            client_data['oidc'] = True
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
        # In debug mode its handy to have username included in loglines
        if config.debug_enabled or config.loglevel == "DEBUG":
            log_banner = f"{config.log_name}:{username}:"
            self.logger = log.setup_logger(banner=log_banner,
                                        existing_logger=config.logger,
                                        pid=True)

    def get_callback(self):
        callback = config.get_callback()
        callback.job.client = self.client
        return callback

    def ssod_redirect_command(self, command, user, command_args, mgmt=False):
        try:
            ssod_conn = connections.get("ssod",
                                        mgmt=mgmt,
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
            return self.build_response(False, auth_response)
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
        jwt_data = jwt.decode(jwt=sso_jwt, key=site_jwt_key, algorithm='RS256')
        # Set auth token.
        auth_token_uuid = jwt_data['login_token']
        config.auth_token = backend.get_object(uuid=auth_token_uuid)
        return user

    def get_apps(self, username, sso_jwt, command_args):
        # Verify SSO jwt.
        try:
            self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'JWT_INVALID', 'status':False}
            return self.build_response(False, auth_response)
        # Get login token.
        login_token = config.auth_token
        # App data is always served by the local node — no cross-site redirect.
        app_data = get_apps(login_token)
        return self.build_response(True, {'app_data': app_data, 'status': True})

    def get_sotp(self, username, sso_jwt, command_args):
        client_ip = command_args.get('client_ip')
        access_group = command_args.get('access_group')
        if not access_group:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=username,
                       reason='access_group missing',
                       ip=client_ip)
            return self.build_response(False, _("AUTHD_INCOMPLETE_COMMAND"))
        session_uuid = command_args.get('session_uuid')
        if not session_uuid:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=username,
                       ag=access_group,
                       reason='session_uuid missing',
                       ip=client_ip)
            return self.build_response(False, _("AUTHD_INCOMPLETE_COMMAND"))
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=username,
                       ag=access_group,
                       reason='jwt_invalid',
                       ip=client_ip)
            return self.build_response(False, {
                'message': 'JWT_INVALID', 'status': False,
            })
        # Get session.
        session = backend.get_object(uuid=session_uuid)
        if not session:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=user.name,
                       ag=access_group,
                       session=session_uuid,
                       reason='unknown_session',
                       ip=client_ip)
            return self.build_response(False, {
                'message': 'UNKNOWN_SESSION', 'status': False,
            })
        # Verify session belongs to the authenticated user. A mismatch
        # here means someone presented a valid JWT but a session UUID
        # belonging to a different user -- worth investigating.
        if session.user_uuid != user.uuid:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=user.name,
                       ag=access_group,
                       session=session_uuid,
                       reason='session_user_mismatch',
                       ip=client_ip)
            return self.build_response(False, {
                'message': 'AUTH_FAILED', 'status': False,
            })
        # Gen SOTP.
        result = backend.search(object_type="accessgroup",
                             attribute="name",
                             value=access_group,
                             return_type="uuid")
        if not result:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=user.name,
                       ag=access_group,
                       reason='unknown_ag',
                       ip=client_ip)
            return self.build_response(False, {
                'message': 'UNKNOWN_AG', 'status': False,
            })
        ag_uuid = result[0]
        sotp_data = sotp.gen(password_hash=session.pass_hash,
                         access_group=ag_uuid)
        emit_audit("SSO", "sotp_issued",
                   user=user.name,
                   ag=access_group,
                   session=session.session_id,
                   ip=client_ip)
        return self.build_response(True, sotp_data)

    def deploy_begin(self, username, sso_jwt, command_args):
        try:
            token_type = command_args['token_type']
        except Exception:
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
                                            command_args=command_args,
                                            mgmt=True)
        # Prepare deploy.
        login_token = config.auth_token
        login_token_name = login_token.name
        # Remove old sso-deploy token if it exists (e.g. from a previous attempt).
        old_deploy = user.token(DEPLOY_NAME)
        callback = self.get_callback()
        if old_deploy:
            add_to_trash = user.get_config_parameter("add_device_token_to_trash")
            user.del_token(token_name=DEPLOY_NAME,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
        # Create sso-deploy token under the user.
        try:
            user.add_token(token_name=DEPLOY_NAME,
                            token_type=token_type,
                            no_token_infos=True,
                            mode="mode1",
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
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
        deploy_token._write(callback=callback)
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
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            login_token_name = command_args['login_token_name']
        except Exception:
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
                                            command_args=command_args,
                                            mgmt=True)
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
                            callback=self.get_callback())
        except Exception as e:
            config.raise_exception()
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
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            is_deploy = command_args['is_deploy']
        except Exception:
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
                                            command_args=command_args,
                                            mgmt=True)
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
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            reg_state = command_args['reg_state']
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            registration_data = command_args['registration_data']
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            token_uuid = command_args['token_uuid']
        except Exception:
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
                                            command_args=command_args,
                                            mgmt=True)
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
        # Verify attestation certificate if enabled.
        check_attestation_cert = user.get_config_parameter("check_fido2_attestation_cert")
        if check_attestation_cert:
            from otpme.lib.token.fido2.fido2 import verify_attestation_cert
            try:
                info_messages = verify_attestation_cert(registration_data)
            except OTPmeException as e:
                log_msg = _("FIDO2 attestation cert verification failed for token "
                            "'{token}' of user '{user_name}': {error}", log=True)[1]
                log_msg = log_msg.format(token=fido2_token.rel_path,
                                        user_name=user.name,
                                        error=e)
                self.logger.warning(log_msg)
                auth_response = {'message':str(e), 'status':False}
                return self.build_response(False, auth_response)
            for info_msg in info_messages:
                self.logger.info(info_msg)
        # Store credential data on token.
        fido2_token.credential_data = encode(auth_data.credential_data, "hex")
        fido2_token._write(callback=self.get_callback())
        log_msg = _("FIDO2 token '{token}' registered for user '{user_name}'.")
        log_msg = log_msg.format(token=fido2_token.rel_path, user_name=user.name)
        self.logger.info(log_msg)
        response = {'message':log_msg, 'status':True}
        return self.build_response(True, response)

    def change_language(self, username, sso_jwt, command_args):
        """ Persist the user's preferred UI language on the User object.

        Accepts ``language`` either as a supported locale code (e.g.
        "en", "de") or the literal string ``"default"`` to reset the
        pref (clears ``language_set`` so the locale selector falls
        back to Accept-Language).
        """
        try:
            language = command_args['language']
        except Exception:
            return self.build_response(False,
                    {'message': 'AUTHD_INCOMPLETE_COMMAND', 'status': False})
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message': 'AUTH_FAILED', 'status': False})
        # Cross-site: user lives on a different site; the object
        # write must happen there.
        if user.site != config.site:
            return self.ssod_redirect_command(command="change_language",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            user.change_language(language=language,
                                 verify_acls=False,
                                 callback=callback)
        except Exception as e:
            message, log_msg = _("Language change failed for user "
                                 "'{user_name}': {e}", log=True)
            log_msg = log_msg.format(user_name=user.name, e=e)
            self.logger.warning(log_msg)
            message = message.format(user_name=user.name, e=e)
            return self.build_response(False,
                    {'message': message, 'status': False})
        user._write(callback=callback)
        # Echo back the effective state so the web layer can refresh
        # its flask_session cache without re-querying.
        effective = user.language if user.language_set else None
        return self.build_response(True, {
            'message': 'OK',
            'language': effective,
        })

    def change_password(self, username, sso_jwt, command_args):
        try:
            current_password = command_args['current_password']
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            new_password = command_args['new_password']
        except Exception:
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
                                            command_args=command_args,
                                            mgmt=True)
        # Get token.
        token = config.auth_token
        token_path = token.rel_path
        # Verify current password against the token.
        verify_result = token.verify_static(password=current_password,
                                            ignore_2f_token=True)
        if not verify_result:
            response = {'message':'Current password is incorrect.', 'status':False}
            return self.build_response(False, response)
        # Change password.
        callback = self.get_callback()
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
            current_pin = command_args['current_pin']
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)
        try:
            new_pin = command_args['new_pin']
        except Exception:
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
                                            command_args=command_args,
                                            mgmt=True)
        # Get token.
        token = config.auth_token
        token_path = token.rel_path
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
        callback = self.get_callback()
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
        `user.get_config_parameter` walks user → unit(s) → site and applies
        the registered getter which returns a "<site>/<role>" path. Must
        be called on the user's home site. """
        try:
            role_path = user.get_config_parameter("sso_token_role")
        except Exception as e:
            log_msg = _("Failed to read sso_token_role: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        if not role_path:
            return None
        if "/" in role_path:
            role_site, role_name = role_path.split("/", 1)
        else:
            role_site = config.site
            role_name = role_path
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

    def _localized_info(self, obj, language, fallback="en"):
        """ Read an object's localized info field. OTPmeObject.info is a
        dict keyed by language code; pick the requested language, fall
        back to the configured fallback locale, then to any remaining
        entry, and finally to an empty string. """
        info = obj.info
        if not info:
            return ""
        try:
            return info[language]
        except KeyError:
            pass
        try:
            return info[fallback]
        except KeyError:
            pass
        for v in info.values():
            if not v:
                continue
            return v
        return ""

    def _resolve_language(self, user, command_args):
        """ Determine which language to render localized object fields in.
        Priority: an explicit `language` from the caller (CLI flag or
        API arg) wins, then the user's persisted language preference
        when the user actually set one (language_set=True), then a
        soft `accept_language` hint sent by the web layer, else "en".

        A user.language that is only the default ('en' with
        language_set=False) is intentionally ignored so the browser's
        Accept-Language still steers the render. """
        args = command_args or {}
        explicit = args.get('language')
        if explicit:
            return explicit
        try:
            if getattr(user, 'language_set', False) and user.language:
                return user.language
        except Exception:
            pass
        hint = args.get('accept_language')
        if hint:
            return hint
        return "en"

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

    def list_oidc_consents(self, username, sso_jwt, command_args):
        """ Return the user's stored OIDC consents enriched with the
        client's display name so the settings UI can show "Disconnect
        Nextcloud" instead of a bare UUID. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'AUTH_FAILED', 'status': False,
            })
        consents = []
        for cid, rec in user.list_oidc_consents().items():
            client = backend.get_object(object_type="client", uuid=cid)
            if client is None:
                # Stale consent for a deleted client -- surface so the
                # user can clean it up; name falls back to UUID.
                client_name = cid
                client_desc = '(client no longer registered)'
            else:
                client_name = getattr(client, 'name', cid)
                client_desc = getattr(client, 'description', '') or ''
            consents.append({
                'client_uuid':        cid,
                'client_name':        client_name,
                'client_description': client_desc,
                'scopes':             rec.get('scopes') or [],
                'granted_at':         rec.get('granted_at') or 0,
            })
        consents.sort(key=lambda c: c['client_name'])
        return self.build_response(True, {'consents': consents,
                                          'status':   True})

    def revoke_oidc_consent(self, username, sso_jwt, command_args):
        """ Drop the consent record for a specific client and -- as a
        side effect -- terminate every live OIDCSession this user
        still has open with that client. Without the session sweep
        the user could revoke the future-grant approval but a stolen
        AT/RT would keep working until natural expiry, which would
        surprise the user (the settings UI advertises the action as
        "disconnect").
        """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'AUTH_FAILED', 'status': False,
            })
        client_uuid = command_args.get('client_uuid')
        if not client_uuid:
            return self.build_response(False, {
                'message': 'client_uuid missing', 'status': False,
            })
        removed = user.revoke_oidc_consent(client_uuid)
        if removed:
            try:
                user._write(callback=self.get_callback())
            except Exception as e:
                log_msg = _("Failed to persist OIDC consent revocation "
                            "for user '{user}': {err}", log=True)[1]
                log_msg = log_msg.format(user=user.name, err=e)
                self.logger.warning(log_msg)
        # Kill live OIDC sessions for this (user, client) tuple. The
        # session.delete() override fires backchannel logout if the
        # client is configured for it.
        sessions = backend.search(object_type="session",
                                  attributes={
                                      'user_uuid':    {'value': user.uuid},
                                      'client':       {'value': client_uuid},
                                      'session_type': {'value': 'oidc'},
                                  },
                                  return_type="instance") or []
        killed = 0
        for sess in sessions:
            try:
                sess.delete(force=True, verify_acls=False)
                killed += 1
            except Exception as e:
                log_msg = _("Failed to terminate OIDC session '{sid}' "
                            "during consent revocation: {err}",
                            log=True)[1]
                log_msg = log_msg.format(sid=sess.session_id, err=e)
                self.logger.warning(log_msg)
        emit_audit("OIDC", 'consent_revoked',
                        user=user.name,
                        client=client_uuid,
                        was_present=removed,
                        sessions_killed=killed)
        return self.build_response(True, {'status':          True,
                                          'was_present':     removed,
                                          'sessions_killed': killed})

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
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="list_device_tokens",
                                            user=user,
                                            command_args=command_args)
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
        # Iterate the user's own tokens and check role membership on each.
        # This is cheaper than walking role.tokens when the role holds many
        # tokens (e.g. lots of users sharing the same sso_token_role).
        device_tokens = []
        for token_uuid in user.tokens:
            try:
                token = backend.get_object(object_type="token", uuid=token_uuid)
            except Exception as e:
                log_msg = _("Failed to read token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if not token:
                continue
            if token.token_type != "password":
                continue
            token_role_uuids = token.get_roles(return_type="uuid")
            if role.uuid not in token_role_uuids:
                continue
            device_tokens.append({
                        'name'          : token.name,
                        'device_name'   : token.name,
                    })
        language = self._resolve_language(user, command_args)
        response = {
                    'device_tokens'     : device_tokens,
                    'role_configured'   : True,
                    'role_info'         : self._localized_info(role, language),
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
                                    enable_mschap=True,
                                    run_policies=True,
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
        callback = self.get_callback()
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
        # Add token to local role to get it on list_device_tokens even if sync of remote
        # role was not done yet.
        try:
            role.add_token(token_path=token.rel_path,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
            role._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to add device token to role '{role}': {e}", log=True)[1]
            log_msg = log_msg.format(role=role.name, e=e)
            self.logger.warning(log_msg)
            try:
                add_to_trash = user.get_config_parameter("add_device_token_to_trash")
                user.del_token(token_name=token.name,
                                force=True,
                                verify_acls=False,
                                run_policies=True,
                                add_to_trash=add_to_trash,
                                callback=callback)
            except Exception:
                pass
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
        callback = self.get_callback()
        callback.raise_exception = True
        add_to_trash = user.get_config_parameter("add_device_token_to_trash")
        try:
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
        except Exception as e:
            log_msg = _("Failed to delete device token '{token}' for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to delete device token: {e}', 'status':False})
        return self.build_response(True, {'status': True})

    def _remote_ssod_call(self, user, command, extra_args, mgmt=False):
        """ Run an ssod command on the user's home site. """
        try:
            ssod_conn = connections.get("ssod",
                                        mgmt=mgmt,
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
        except Exception:
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
        callback = self.get_callback()
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
                                                    extra_args=remote_args,
                                                    mgmt=True)
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
                                    cluster=True)
            except Exception as e:
                log_msg = _("Failed to mirror remote device token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                return self.build_response(False, {'message':f'Failed to write remote object locally: {e}', 'status':False})
            # Get token from backend add add it to local user to make auth possible
            # even if sync was not done yet.
            token = backend.get_object(token_oid)
            user.add_token(new_token=token,
                        no_token_infos=True,
                        force=True,
                        verify_acls=False,
                        run_policies=True,
                        callback=callback)
            user._write(callback=callback)
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
                                            extra_args={**command_args, 'token_name': token_name},
                                            mgmt=True)
                else:
                    add_to_trash = user.get_config_parameter("add_device_token_to_trash")
                    user.del_token(token_name=token_name,
                                    force=True,
                                    verify_acls=False,
                                    run_policies=True,
                                    add_to_trash=add_to_trash,
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
        except Exception:
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
        callback = self.get_callback()
        callback.raise_exception = True
        # Delete the token object on its canonical site.
        if user.site != config.site:
            remote_args = dict(command_args)
            remote_args['token_name'] = token_name
            status, remote_resp = self._remote_ssod_call(user=user,
                                                    command="sso_delete_device_token",
                                                    extra_args=remote_args,
                                                    mgmt=True)
            if not status:
                return self.build_response(False, remote_resp)
        else:
            add_to_trash = user.get_config_parameter("add_device_token_to_trash")
            try:
                user.del_token(token_name=token_name,
                                force=True,
                                verify_acls=False,
                                run_policies=True,
                                add_to_trash=add_to_trash,
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

    # ------------------------------------------------------------------
    # OIDC OP commands. Server-to-server: the RP authenticates with
    # client_id + client_secret; the user is identified via the token
    # the RP presents. No sso_jwt involved.
    # ------------------------------------------------------------------

    def _compute_oidc_amr(self, auth_token):
        """ Read the amr values declared on the token's class.
        Returns a fresh list (defensive copy). Empty list if the
        token disappeared or doesn't declare amr values.

        All values emitted by OTPme token classes are IANA-registered
        (``hwk``, ``sc``, ``otp``, ``swk``, ``mca``, ``user``,
        ``pin``).

        Spec: RFC 8176 "Authentication Method Reference Values"
          (defines the ``amr`` claim + creates the IANA registry;
          ``pwd``, ``otp``, ``mfa``, ``hwk``, ``swk``, ``sc`` etc.
          are registered in §2)
          https://datatracker.ietf.org/doc/html/rfc8176
        IANA "Authentication Method Reference Values" registry
          (authoritative live list -- additions made after RFC 8176
          are tracked here)
          https://www.iana.org/assignments/authentication-method-reference-values/authentication-method-reference-values.xhtml
        Spec: OIDC Core 1.0 §2 "ID Token" (``amr`` claim)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        """
        if auth_token is None:
            return []
        values = getattr(auth_token, 'oidc_amr_values', None)
        if not values:
            return []
        return list(values)

    def _compute_oidc_acr(self, amr, scheme):
        """ Map an amr list to an acr string per scheme. Implementation
        lives in otpme.lib.protocols.oidc_helpers so it's
        unit-testable without the full handler import chain.

        Spec: OIDC Core 1.0 §2 "ID Token" (``acr`` claim)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        Spec: OIDC Core 1.0 §3.1.2.1 "Authentication Request"
          (acr_values request parameter; voluntary claim)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        return _compute_acr_helper(amr, scheme)

    def _resolve_acr_scheme(self, client):
        """ Resolve the ACR scheme via Site/Unit/Client config-param
        hierarchy. Falls back to "numeric" on any read failure.
        """
        try:
            scheme = client.get_config_parameter("oidc_acr_scheme")
        except Exception:
            scheme = None
        if scheme not in ("numeric", "none"):
            return "numeric"
        return scheme

    def _resolve_auth_time(self, oidc_session):
        """ Resolve the OIDC ``auth_time`` claim -- the unix timestamp
        of the original user authentication, NOT of the OIDC flow.

        Returns an int (unix timestamp) when known, ``None`` when not.
        Caller MUST omit the ``auth_time`` claim when this returns
        ``None``: an RP that asked for ``max_age`` will then treat the
        response as failing the freshness check and force re-auth --
        which is the conservative and correct outcome. Faking ``now``
        here would silently bypass max_age policies on banking /
        step-up RPs.

        Resolution order:
          1. Parent SSO session's ``creation_time`` -- the actual user
             login moment (best truth).
          2. OIDCSession's own ``creation_time`` -- the OIDC flow
             happened then, so user auth must be at-or-before this.
             Acceptable lower bound; still a real freshness indicator.
          3. ``None`` -- truly unknown, nothing to claim.

        Spec: OIDC Core 1.0 §2 "ID Token" (``auth_time`` claim:
          time of end-user authentication, REQUIRED when max_age is
          requested or essential)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        Spec: OIDC Core 1.0 §3.1.2.1 "Authentication Request"
          (``max_age`` parameter)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        try:
            parents = backend.search(object_type="session",
                                     attribute="child_session",
                                     value=oidc_session.uuid,
                                     return_type="instance")
            if parents:
                ct = getattr(parents[0], 'creation_time', None)
                if ct:
                    return int(ct)
        except Exception:
            pass
        ct = getattr(oidc_session, 'creation_time', None)
        if ct:
            return int(ct)
        return None

    def _resolve_access_token_ttl(self, client):
        """ Resolve the access-token lifetime (seconds) for the given
        client by walking the Site/Unit/Client config-parameter
        hierarchy. Falls back to 3600s on any read/parse failure to
        keep the issuance path robust. Same TTL is used for the ID
        Token's exp.

        Spec: RFC 6749 §5.1 "Successful Response" (``expires_in`` --
          recommended in token response, in seconds)
          https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
        Spec: OIDC Core 1.0 §2 "ID Token" (``exp`` claim -- absolute
          unix-timestamp expiry, MUST be present in ID Token)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        """
        from otpme.lib.humanize import units
        try:
            human = client.get_config_parameter("oidc_access_token_ttl")
        except Exception:
            human = None
        if human is None:
            return 3600
        try:
            return units.time2int(human, time_unit="s")
        except Exception:
            return 3600

    def _verify_oidc_client(self, client_id, client_secret):
        """ Look up the OIDC RP by name and constant-time-compare its
        secret. Returns ``(client_obj, None)`` on success or
        ``(None, internal_reason)`` on failure -- the internal_reason
        is for server-side logging only and MUST NOT be returned to
        the caller; the caller surfaces a generic
        "client authentication failed".

        Spec: RFC 6749 §2.3 "Client Authentication" (confidential
          clients authenticate; public clients may be unauthenticated)
          https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
        Spec: RFC 6749 §2.3.1 "Client Password" (Basic / form-body)
          https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
        Spec: OIDC Core 1.0 §9 "Client Authentication"
          (``token_endpoint_auth_method``: client_secret_basic,
          client_secret_post, none, ...)
          https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
        Spec: OAuth 2.1 §4.4 "Client Authentication" (public clients
          MUST use PKCE; ``none`` requires code_challenge)
          https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
        """
        import secrets as _secrets
        if not client_id:
            return None, "client_id missing"
        client = backend.get_object(object_type="client",
                                    name=client_id,
                                    realm=config.realm,
                                    site=config.site)
        if client is None:
            return None, f"unknown client '{client_id}'"
        if not getattr(client, 'enabled', True):
            return None, f"client '{client_id}' disabled"
        if not getattr(client, 'oidc_auth', False):
            return None, f"client '{client_id}' has OIDC disabled"
        method = getattr(client, 'oidc_token_endpoint_auth_method',
                         'client_secret_basic')
        if method == "none":
            # Public client + PKCE; no secret expected.
            return client, None
        if not client_secret:
            return None, "client_secret missing"
        stored = getattr(client, 'secret', None) or ""
        if not _secrets.compare_digest(str(stored), str(client_secret)):
            return None, f"wrong client_secret for '{client_id}'"
        return client, None

    def _verify_pkce(self, code_verifier, code_challenge,
                     code_challenge_method):
        """ Verify the PKCE code_verifier against the bound
        code_challenge. Returns True/False. Implementation lives in
        otpme.lib.protocols.oidc_helpers so it's unit-testable
        without the full handler import chain.

        Spec: RFC 7636 §4.6 "Server Verifies code_verifier before
          Returning the Tokens"
          https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
        """
        return _verify_pkce_helper(code_verifier, code_challenge,
                                    code_challenge_method)

    def _compute_oidc_sub(self, user, client, site):
        """ Compute the ``sub`` claim per the client's subject_type.

        public:   user.uuid (same value across RPs)
        pairwise: HMAC-SHA256(site.oidc_pairwise_secret,
                              sector_id || user.uuid)

        Sector_id defaults to client.name if no sector_identifier_uri
        is set. The site MUST have a pairwise secret -- a missing or
        empty secret would HMAC every (sector, user) pair to the same
        value across all sites that share a sector_id, defeating the
        privacy guarantee. enable_oidc() autogenerates one; if a Site
        was upgraded from a pre-fix build the operator has to run
        ``otpme-site change_oidc_pairwise_secret`` once.

        Spec: OIDC Core 1.0 §8 "Subject Identifier Types"
          (public vs pairwise)
          https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
        Spec: OIDC Core 1.0 §8.1 "Pairwise Identifier Algorithm"
          (informative: SHA-256/HMAC variants, sector_identifier
          derived from sector_identifier_uri host)
          https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
        Spec: RFC 2104 "HMAC: Keyed-Hashing for Message Authentication"
          https://datatracker.ietf.org/doc/html/rfc2104
        """
        subject_type = getattr(client, 'oidc_subject_type', 'public')
        if subject_type != "pairwise":
            return user.uuid
        import hmac
        import hashlib
        pw_secret = getattr(site, 'oidc_pairwise_secret', None)
        if not pw_secret:
            msg = _("Site '{site}' has no oidc_pairwise_secret. "
                    "Run 'otpme-site change_oidc_pairwise_secret' "
                    "or re-run enable_oidc.")
            msg = msg.format(site=getattr(site, 'name', '?'))
            raise OTPmeException(msg)
        if isinstance(pw_secret, str):
            pw_secret = pw_secret.encode("utf-8")
        sector = getattr(client, 'oidc_sector_identifier_uri', None) \
                 or client.name
        return hmac.new(pw_secret,
                        f"{sector}|{user.uuid}".encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _get_user_claims(self, user, scope_str, client=None):
        """ Build the OIDC user-claims dict for /userinfo and ID Token
        based on the granted scope string. ``sub`` is added by the
        caller because it depends on subject_type/pairwise secret.

        LDIF source attributes for individual claims are configurable
        via Site/Unit config params (e.g. ``oidc_email_attribute``)
        so admins can map non-standard schemas without code changes.

        Spec: OIDC Core 1.0 §5.1 "Standard Claims"
          (name, given_name, family_name, preferred_username, email,
          phone_number, address sub-claims, ...)
          https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        Spec: OIDC Core 1.0 §5.1.1 "Address Claim"
          (street_address, locality, region, postal_code, country)
          https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
        Spec: OIDC Core 1.0 §5.4 "Requesting Claims using Scope Values"
          (profile / email / address / phone scope mappings)
          https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
        Note: ``groups`` is not a Standard OIDC scope; widely supported
          de-facto via CAS Protocol §2.6 attribute return and the
          ``groups`` IANA-registered claim, used by NextCloud, Grafana,
          Authentik, ... For formal registration see "OAuth Parameters"
          IANA registry.
        """
        def _first(attr):
            try:
                vals = user.get_attribute(attr)
            except Exception:
                vals = []
            return vals[0] if vals else None

        scopes = set((scope_str or "").split())
        claims = {}
        if "profile" in scopes:
            given = _first('givenName')
            sn = _first('sn')
            cn = _first('cn')
            if given:
                claims['given_name'] = given
            if sn:
                claims['family_name'] = sn
            if cn:
                claims['name'] = cn
            elif given and sn:
                claims['name'] = f"{given} {sn}"
            claims['preferred_username'] = user.name
        if "email" in scopes:
            mail_attr = "mail"
            try:
                cfg = user.get_config_parameter("oidc_email_attribute")
                if cfg:
                    mail_attr = cfg
            except Exception:
                pass
            mail = _first(mail_attr)
            if mail:
                claims['email'] = mail
                # OTPme doesn't track email-verified state yet.
        if "phone" in scopes:
            phone = _first('telephoneNumber')
            if phone:
                claims['phone_number'] = phone
        if "address" in scopes:
            street = _first('postalAddress') or _first('street')
            locality = _first('l')
            region = _first('st')
            postal = _first('postalCode')
            country = _first('c')
            address = {}
            if street:
                address['street_address'] = street
            if locality:
                address['locality'] = locality
            if region:
                address['region'] = region
            if postal:
                address['postal_code'] = postal
            if country:
                address['country'] = country
            if address:
                claims['address'] = address
        if "groups" in scopes:
            # OTPme groups (POSIX-/LDAP-style memberships) -- the
            # natural fit for NextCloud's user_oidc and similar
            # group-aware RPs.
            #
            # Per-RP filtering: the ``groups`` claim is the
            # intersection of:
            #   * the user's group memberships (aggregated across
            #     the user's tokens), and
            #   * the group whitelist of the Scope object whose
            #     ``scope_id="groups"`` is granted to THIS client.
            #
            # Multiple Scope objects may share scope_id="groups"
            # but each holds its own whitelist; the right one for
            # this RP is the one that has this client as a member.
            try:
                user_groups = set(user.get_groups(return_type="name") or [])
            except Exception:
                user_groups = set()
            allowed_groups = set()
            if client is not None:
                try:
                    groups_scopes = backend.search(
                        object_type="scope",
                        attributes={
                            'scope_id': {'value': 'groups'},
                            'client':   {'value': client.uuid},
                            'enabled':  {'value': True},
                        },
                        return_type="instance")
                    for scope_obj in groups_scopes or []:
                        try:
                            scope_groups = scope_obj.get_groups(return_type="name") or []
                        except Exception:
                            scope_groups = []
                        allowed_groups.update(scope_groups)
                except Exception:
                    pass
            visible = sorted(user_groups & allowed_groups)
            if visible:
                claims['groups'] = visible
        return claims

    def _build_id_token_claims(self, oidc_session, user, client, site):
        """ Resolve the OIDC-domain claim values that the handler is
        responsible for (sub, user-attribute claims, auth_time, amr,
        acr). Infrastructure claims (iss/aud/iat/exp/jti/sid/nonce)
        and at_hash live on OIDCSession.build_id_token.

        Spec: OIDC Core 1.0 §2 "ID Token" (claim set: iss, sub, aud,
          exp, iat, auth_time, nonce, acr, amr, azp)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        Spec: OIDC Core 1.0 §5.4 "Requesting Claims using Scope Values"
          (user-attribute claims included in ID Token when the
          ``id_token`` audience requests them via scope)
          https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
        """
        claims = {
            "sub": self._compute_oidc_sub(user, client, site),
        }
        # User-attribute claims gated by granted scope.
        user_claims = self._get_user_claims(user, oidc_session.scope,
                                            client=client)
        # Avoid clobbering "sub": _get_user_claims caller-contract is
        # to NOT include sub, but be defensive.
        for k, v in (user_claims or {}).items():
            if k == "sub":
                continue
            claims[k] = v

        auth_time = self._resolve_auth_time(oidc_session)
        if auth_time is not None:
            claims["auth_time"] = auth_time

        auth_token = None
        if getattr(oidc_session, 'auth_token', None):
            auth_token = backend.get_object(object_type="token",
                                            uuid=oidc_session.auth_token)
        amr = self._compute_oidc_amr(auth_token)
        if amr:
            claims["amr"] = amr
        scheme = self._resolve_acr_scheme(client)
        acr = self._compute_oidc_acr(amr, scheme)
        if acr is not None:
            claims["acr"] = acr

        return claims

    def oidc_token(self, command_args):
        """ /token endpoint. Dispatches by grant_type.

        Spec: RFC 6749 §3.2 "Token Endpoint"
          https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
        Spec: RFC 6749 §4.5 "Extension Grants" (the dispatch model
          for unknown grant_type values -> ``unsupported_grant_type``)
          https://datatracker.ietf.org/doc/html/rfc6749#section-4.5
        Spec: OIDC Core 1.0 §3.1.3 "Token Endpoint"
          https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
        """
        grant_type = command_args.get("grant_type")
        if grant_type == "authorization_code":
            return self._oidc_token_code_exchange(command_args)
        if grant_type == "refresh_token":
            return self._oidc_token_refresh(command_args)
        return self.build_response(False, {
            'error': 'unsupported_grant_type',
            'error_description': f"grant_type '{grant_type}' not supported",
        })

    def _oidc_token_code_exchange(self, command_args):
        """ grant_type=authorization_code:
            - validate client credentials
            - locate OIDCSession via SHA-256(code) index
            - verify redirect_uri match, PKCE, expiry, single-use
            - consume code, issue AT+RT, build ID Token

        Spec: RFC 6749 §4.1.3 "Access Token Request"
          (grant_type=authorization_code parameters: code,
          redirect_uri, client_id)
          https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        Spec: RFC 6749 §4.1.4 "Access Token Response"
          https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
        Spec: RFC 6749 §5.2 "Error Response" (invalid_grant,
          invalid_client, invalid_request, unsupported_grant_type)
          https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        Spec: OIDC Core 1.0 §3.1.3.2 "Token Request Validation"
          (redirect_uri match, code single-use)
          https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
        Spec: OIDC Core 1.0 §3.1.3.3 "Successful Token Response"
          (id_token added to RFC 6749 response)
          https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        Spec: RFC 7636 §4.6 "Server Verifies code_verifier"
          https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
        """
        from otpme.lib.session.oidc_session import (
                hash_token, STATE_PENDING_CODE_EXCHANGE)

        client_id = command_args.get("client_id")
        client_secret = command_args.get("client_secret")
        code = command_args.get("code")
        redirect_uri = command_args.get("redirect_uri")
        code_verifier = command_args.get("code_verifier")
        # Source IP of the /token request -- the RP server, not the
        # user's browser. Logged for audit; not stored on the session
        # so the original browser IP captured at /authorize stays
        # intact.
        client_ip = command_args.get("client_ip")

        log_msg = _("OIDC code exchange from {ip} for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?", cid=client_id or "?")
        self.logger.info(log_msg)

        # All security-sensitive failures collapse to one generic
        # description; the actual reason goes to the log only.
        GENERIC_INVALID_GRANT = "invalid or expired code"
        GENERIC_INVALID_CLIENT = "client authentication failed"
        GENERIC_SERVER_ERROR = "internal server error"

        def _fail(error_code, generic_msg, log_reason):
            log_msg = _("OIDC code exchange rejected ({reason}).", log=True)[1]
            log_msg = log_msg.format(reason=log_reason)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'token_code_exchange_failed',
                            level='warning',
                            client=client_id,
                            error=error_code,
                            reason=log_reason,
                            ip=client_ip)
            return self.build_response(False, {
                'error': error_code,
                'error_description': generic_msg,
            })

        client, err = self._verify_oidc_client(client_id, client_secret)
        if err:
            return _fail('invalid_client', GENERIC_INVALID_CLIENT, err)
        if "authorization_code" not in (client.oidc_grant_types or []):
            return _fail('unauthorized_client', 'unauthorized_client',
                         "authorization_code not enabled for this client")
        if not code:
            # Configuration / request bug -- safe to be specific.
            emit_audit("OIDC", 'token_code_exchange_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason='code missing',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'code missing',
            })

        code_hash = hash_token(code)
        result = backend.search(object_type="session",
                                attribute="authcode_hash",
                                value=code_hash,
                                return_type="instance")
        if not result:
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         "unknown or already-consumed code")
        oidc_session = result[0]

        if oidc_session.state != STATE_PENDING_CODE_EXCHANGE \
        or not oidc_session.authcode_valid():
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         "code expired or session not pending")

        # Cross-client replay defense.
        if oidc_session.client != client.uuid:
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         f"code was issued to a different client (got '{client_id}')")

        # redirect_uri mismatch is a configuration bug on the RP
        # side -- specific is OK and helps debugging.
        if oidc_session.redirect_uri != (redirect_uri or ""):
            emit_audit("OIDC", 'token_code_exchange_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_grant',
                            reason='redirect_uri mismatch',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_grant',
                'error_description': 'redirect_uri mismatch',
            })

        if not self._verify_pkce(code_verifier,
                                  oidc_session.code_challenge,
                                  oidc_session.code_challenge_method):
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         "PKCE verification failed")

        user = backend.get_object(object_type="user",
                                  uuid=oidc_session.user_uuid)
        if user is None:
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         f"user uuid {oidc_session.user_uuid} not found")

        site = backend.get_object(object_type="site",
                                realm=oidc_session.realm,
                                name=oidc_session.site)
        if site is None or not getattr(site, 'oidc_keys', None):
            return _fail('server_error', GENERIC_SERVER_ERROR,
                         "site has no signing key")

        # Single-use consume + combined token issuance. TTL is
        # resolved per-client (Site/Unit/Client hierarchy). The
        # combined call binds at_hash to the freshly-rotated AT
        # before the plaintext leaves the session. id_token_jti is
        # surfaced for cross-system audit correlation.
        at_ttl = self._resolve_access_token_ttl(client)
        oidc_session.consume_authcode()
        try:
            id_claims = self._build_id_token_claims(oidc_session,
                                                     user, client, site)
            at, rt, id_token, id_token_jti = \
                    oidc_session.issue_tokens_with_id_token(
                            ttl_access=at_ttl,
                            client=client,
                            site=site,
                            claims=id_claims)
        except Exception as e:
            config.raise_exception()
            log_msg = _("Failed to issue tokens / build ID Token: {err}",
                        log=True)[1]
            log_msg = log_msg.format(err=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'error': 'server_error',
                'error_description': GENERIC_SERVER_ERROR,
            })

        # Persist + bump activity stamp.
        oidc_session.write_config()
        try:
            oidc_session.update_last_used_time()
        except Exception:
            pass

        emit_audit("OIDC", 'token_code_exchange_success',
                        client=client_id,
                        user=user.name,
                        session=oidc_session.session_id,
                        scope=oidc_session.scope or "",
                        ttl=at_ttl,
                        id_token_jti=id_token_jti,
                        ip=client_ip)
        response = {
            'access_token': at,
            'token_type': 'Bearer',
            'expires_in': at_ttl,
            'id_token': id_token,
            'scope': oidc_session.scope or "",
        }
        if "refresh_token" in (client.oidc_grant_types or []):
            response['refresh_token'] = rt
        return self.build_response(True, response)

    def _oidc_token_refresh(self, command_args):
        """ grant_type=refresh_token:
            - validate client credentials
            - locate OIDCSession via SHA-256(refresh_token) index
            - check state=active, client matches (cross-client replay)
            - rotate AT+RT, build fresh ID Token

        Spec: RFC 6749 §6 "Refreshing an Access Token"
          (grant_type=refresh_token; refresh_token, scope parameters)
          https://datatracker.ietf.org/doc/html/rfc6749#section-6
        Spec: OAuth 2.1 §6.1 "Refresh Token Protection"
          (rotate-and-invalidate-chain on replay; revoke the entire
          chain when a burned RT is presented)
          https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
        Spec: OAuth 2.0 Security Best Current Practice §4.13
          (RT rotation; detection of replay; chain invalidation)
          https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
        Spec: OIDC Core 1.0 §12 "Using Refresh Tokens"
          (ID Token may be re-issued during refresh; iat refreshed)
          https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
        """
        from otpme.lib.session.oidc_session import hash_token, STATE_ACTIVE

        client_id = command_args.get("client_id")
        client_secret = command_args.get("client_secret")
        refresh_token = command_args.get("refresh_token")
        client_ip = command_args.get("client_ip")

        log_msg = _("OIDC refresh from {ip} for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?", cid=client_id or "?")
        self.logger.info(log_msg)

        GENERIC_INVALID_GRANT = "invalid or expired refresh token"
        GENERIC_INVALID_CLIENT = "client authentication failed"
        GENERIC_SERVER_ERROR = "internal server error"

        def _fail(error_code, generic_msg, log_reason):
            log_msg = _("OIDC refresh rejected ({reason}).", log=True)[1]
            log_msg = log_msg.format(reason=log_reason)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'token_refresh_failed',
                            level='warning',
                            client=client_id,
                            error=error_code,
                            reason=log_reason,
                            ip=client_ip)
            return self.build_response(False, {
                'error': error_code,
                'error_description': generic_msg,
            })

        client, err = self._verify_oidc_client(client_id, client_secret)
        if err:
            return _fail('invalid_client', GENERIC_INVALID_CLIENT, err)
        if "refresh_token" not in (client.oidc_grant_types or []):
            return _fail('unauthorized_client', 'unauthorized_client',
                         "refresh_token not enabled for this client")
        if not refresh_token:
            emit_audit("OIDC", 'token_refresh_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason='refresh_token missing',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'refresh_token missing',
            })

        rt_hash = hash_token(refresh_token)
        result = backend.search(object_type="session",
                                attribute="refresh_token_hash",
                                value=rt_hash,
                                return_type="instance")
        if not result:
            # Active index missed -- check the burn index. A hit there
            # means this RT was already rotated out, so the legitimate
            # RP can't be presenting it: it's a replay (token theft).
            # OAuth 2.1 §6.1 says invalidate the whole token chain:
            #   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
            # (mirrored in OAuth Security BCP §4.13:
            #   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
            burned = backend.search(object_type="session",
                                    attribute="burned_refresh_token_hash",
                                    value=rt_hash,
                                    return_type="instance")
            if burned:
                replayed_session = burned[0]
                # Cross-client check: only act if the calling client
                # actually owns the session. Otherwise a malicious
                # client could weaponize this to nuke another client's
                # session by replaying the victim's burned RT.
                if replayed_session.client == client.uuid:
                    sid = replayed_session.session_id
                    try:
                        replayed_session.delete(force=True,
                                                 verify_acls=False)
                    except Exception as e:
                        log_msg = _("Failed to invalidate replayed OIDC "
                                    "session '{sid}': {err}", log=True)[1]
                        log_msg = log_msg.format(sid=sid, err=e)
                        self.logger.warning(log_msg)
                    emit_audit("OIDC", 'token_refresh_replay_detected',
                                    level='warning',
                                    client=client_id,
                                    session=sid,
                                    reason='burned refresh token replay',
                                    ip=client_ip)
                else:
                    # Suspicious but not actionable -- log without
                    # killing someone else's session.
                    emit_audit("OIDC", 'token_refresh_replay_cross_client',
                                    level='warning',
                                    client=client_id,
                                    session=replayed_session.session_id,
                                    reason='burned RT presented by foreign client',
                                    ip=client_ip)
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         "unknown refresh token (potential replay)")
        oidc_session = result[0]

        if oidc_session.state != STATE_ACTIVE:
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         "session not active")

        # Cross-client replay defense: the RT must be redeemed by the
        # same client it was issued to.
        if oidc_session.client != client.uuid:
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         f"refresh token belongs to a different client (got '{client_id}')")

        # If the parent SSO session has expired, the OIDCSession may
        # still linger until the next cleanup pass. Refuse refresh
        # explicitly via outdate(): returns True if session is alive,
        # False/None if it's expired/should be removed.
        try:
            still_alive = oidc_session.outdate()
            if still_alive is False:
                return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                             "session expired")
        except Exception:
            pass

        user = backend.get_object(object_type="user",
                                  uuid=oidc_session.user_uuid)
        if user is None:
            return _fail('invalid_grant', GENERIC_INVALID_GRANT,
                         f"user uuid {oidc_session.user_uuid} not found")

        site = backend.get_object(object_type="site",
                                realm=oidc_session.realm,
                                name=oidc_session.site)
        if site is None or not getattr(site, 'oidc_keys', None):
            return _fail('server_error', GENERIC_SERVER_ERROR,
                         "site has no signing key")

        # Rotate: combined AT/RT/ID-Token mint. The session burns the
        # rotated-out RT so a later replay is detectable. TTL is
        # resolved per-client at issuance time, so a config change
        # picks up on the next refresh without invalidating live
        # tokens. at_hash is bound to the freshly-rotated AT.
        at_ttl = self._resolve_access_token_ttl(client)
        try:
            id_claims = self._build_id_token_claims(oidc_session,
                                                     user, client, site)
            at, rt, id_token, id_token_jti = \
                    oidc_session.issue_tokens_with_id_token(
                            ttl_access=at_ttl,
                            client=client,
                            site=site,
                            claims=id_claims)
        except Exception as e:
            log_msg = _("Failed to issue tokens / build ID Token (refresh): "
                        "{err}", log=True)[1]
            log_msg = log_msg.format(err=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'error': 'server_error',
                'error_description': GENERIC_SERVER_ERROR,
            })

        oidc_session.write_config()
        try:
            oidc_session.update_last_used_time()
        except Exception:
            pass

        emit_audit("OIDC", 'token_refresh_success',
                        client=client_id,
                        user=user.name,
                        session=oidc_session.session_id,
                        scope=oidc_session.scope or "",
                        ttl=at_ttl,
                        id_token_jti=id_token_jti,
                        ip=client_ip)
        response = {
            'access_token': at,
            'token_type': 'Bearer',
            'expires_in': at_ttl,
            'refresh_token': rt,
            'id_token': id_token,
            'scope': oidc_session.scope or "",
        }
        return self.build_response(True, response)

    def oidc_userinfo(self, command_args):
        """ /userinfo endpoint.

        Auth: Bearer access_token (no client_id/secret). The token is
        self-identifying -- a single Storage-Lookup on its hash gives
        us the OIDCSession, from there user/client/scope.

        Spec: OIDC Core 1.0 §5.3 "UserInfo Endpoint"
          https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        Spec: OIDC Core 1.0 §5.3.2 "Successful UserInfo Response"
          (``sub`` REQUIRED in response; claims filtered by granted
          scope)
          https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        Spec: RFC 6750 §2 "Authenticated Requests" (Bearer access
          token in Authorization header)
          https://datatracker.ietf.org/doc/html/rfc6750#section-2
        """
        from otpme.lib.session.oidc_session import hash_token, STATE_ACTIVE

        access_token = command_args.get("access_token")
        client_ip = command_args.get("client_ip")

        log_msg = _("OIDC userinfo from {ip}.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?")
        self.logger.info(log_msg)

        # All token-related failures collapse to one generic message;
        # the real reason is logged.
        GENERIC_INVALID_TOKEN = "invalid or expired token"
        GENERIC_SERVER_ERROR = "internal server error"

        def _fail(error_code, generic_msg, log_reason):
            log_msg = _("OIDC userinfo rejected ({reason}).", log=True)[1]
            log_msg = log_msg.format(reason=log_reason)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'error': error_code,
                'error_description': generic_msg,
            })

        if not access_token:
            return _fail('invalid_token', GENERIC_INVALID_TOKEN,
                         "access_token missing")

        at_hash = hash_token(access_token)
        result = backend.search(object_type="session",
                                attribute="access_token_hash",
                                value=at_hash,
                                return_type="instance")
        if not result:
            return _fail('invalid_token', GENERIC_INVALID_TOKEN,
                         "unknown access token")
        oidc_session = result[0]

        if oidc_session.state != STATE_ACTIVE \
        or not oidc_session.access_token_valid():
            return _fail('invalid_token', GENERIC_INVALID_TOKEN,
                         "access token expired or revoked")

        user = backend.get_object(object_type="user",
                                  uuid=oidc_session.user_uuid)
        if user is None:
            return _fail('invalid_token', GENERIC_INVALID_TOKEN,
                         f"user uuid {oidc_session.user_uuid} not found")

        client = backend.get_object(object_type="client",
                                    uuid=oidc_session.client)
        if client is None:
            return _fail('invalid_token', GENERIC_INVALID_TOKEN,
                         f"client uuid {oidc_session.client} not found")

        site = backend.get_object(object_type="site",
                                realm=oidc_session.realm,
                                name=oidc_session.site)
        if site is None:
            return _fail('server_error', GENERIC_SERVER_ERROR,
                         f"site '{oidc_session.site}' not found")

        # Bump activity stamp -- /userinfo IS user-driven activity.
        try:
            oidc_session.update_last_used_time()
        except Exception:
            pass

        claims = self._get_user_claims(user, oidc_session.scope, client=client)
        # `sub` REQUIRED in /userinfo response:
        # OIDC Core 1.0 §5.3.2 "Successful UserInfo Response"
        #   https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        claims['sub'] = self._compute_oidc_sub(user, client, site)
        return self.build_response(True, claims)

    def oidc_introspect(self, command_args):
        """ /introspect endpoint.

        Auth: client_id + client_secret (server-to-server).
        Request: ``token`` (REQUIRED), ``token_type_hint`` (OPTIONAL,
        either ``access_token`` or ``refresh_token`` -- only a search
        order hint, the spec requires us to check both).

        ANY situation where the token is not currently valid (unknown
        / expired / revoked / belongs to another client) is reported
        uniformly as ``{"active": false}`` -- no info leak about
        which tokens exist or who they belong to.

        Spec: RFC 7662 §2 "Introspection Endpoint"
          (token + token_type_hint request parameters)
          https://datatracker.ietf.org/doc/html/rfc7662#section-2
        Spec: RFC 7662 §2.1 "Introspection Request"
          (``token_type_hint`` is a hint only, not authoritative)
          https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
        Spec: RFC 7662 §2.2 "Introspection Response"
          (active true/false + optional claims; uniform 200 response)
          https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
        """
        from otpme.lib.session.oidc_session import hash_token, STATE_ACTIVE

        client_id = command_args.get("client_id")
        client_secret = command_args.get("client_secret")
        token = command_args.get("token")
        hint = command_args.get("token_type_hint")
        client_ip = command_args.get("client_ip")

        log_msg = _("OIDC introspect from {ip} for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?", cid=client_id or "?")
        self.logger.info(log_msg)

        client, err = self._verify_oidc_client(client_id, client_secret)
        if err:
            log_msg = _("OIDC introspect rejected ({reason}).", log=True)[1]
            log_msg = log_msg.format(reason=err)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'introspect_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_client',
                            reason=err,
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_client',
                'error_description': "client authentication failed",
            })
        if not token:
            emit_audit("OIDC", 'introspect_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason='token missing',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'token missing',
            })

        h = hash_token(token)
        # Hint is only a search-order optimization; we MUST check both.
        search_order = ['access_token_hash', 'refresh_token_hash']
        if hint == 'refresh_token':
            search_order = ['refresh_token_hash', 'access_token_hash']

        oidc_session = None
        token_kind = None
        for attr in search_order:
            result = backend.search(object_type="session",
                                    attribute=attr,
                                    value=h,
                                    return_type="instance")
            if result:
                oidc_session = result[0]
                token_kind = ('access' if attr == 'access_token_hash'
                              else 'refresh')
                break

        if oidc_session is None:
            return self.build_response(True, {'active': False})

        # State + expiry. Any failure -> active=false (no leak).
        if oidc_session.state != STATE_ACTIVE:
            return self.build_response(True, {'active': False})
        if token_kind == 'access' and not oidc_session.access_token_valid():
            return self.build_response(True, {'active': False})

        # Cross-client introspection defense: a token must be
        # introspected by the client it was issued to.
        if oidc_session.client != client.uuid:
            emit_audit("OIDC", 'introspect_cross_client',
                            level='warning',
                            client=client_id,
                            session=oidc_session.session_id,
                            token_kind=token_kind,
                            ip=client_ip)
            return self.build_response(True, {'active': False})

        user = backend.get_object(object_type="user",
                                  uuid=oidc_session.user_uuid)
        site = backend.get_object(object_type="site",
                                realm=oidc_session.realm,
                                name=oidc_session.site)
        if user is None or site is None:
            # Inconsistent backend state; treat as inactive rather
            # than 500'ing.
            return self.build_response(True, {'active': False})

        issuer = f"https://{site.sso_fqdn}/oidc"
        sub = self._compute_oidc_sub(user, client, site)

        response = {
            'active': True,
            'scope': oidc_session.scope or "",
            'client_id': client.name,
            'username': user.name,
            'token_type': 'Bearer',
            'sub': sub,
            'aud': client.name,
            'iss': issuer,
        }
        if token_kind == 'access':
            response['exp'] = oidc_session.access_token_expires_at
        # No fixed `exp` for refresh tokens -- their lifetime is
        # bounded by the parent SSO session, not a per-token stamp.

        return self.build_response(True, response)

    def oidc_revoke(self, command_args):
        """ /revoke endpoint.

        Auth: client_id + client_secret (server-to-server).
        Request: ``token`` (REQUIRED), ``token_type_hint`` (OPTIONAL,
        ``access_token`` or ``refresh_token`` -- search-order hint
        only; we check both indexes anyway).

        The OP MUST return HTTP 200 for any valid client request,
        regardless of whether the token existed or belonged to the
        calling client. Only ``invalid_client`` / ``invalid_request``
        are real errors. This prevents token-existence probing.

        Revoking either an AT or an RT terminates the underlying
        OIDCSession (and triggers backchannel logout via the session's
        delete()) -- AT and RT share a single session here.

        Spec: RFC 7009 §2 "Token Revocation" (token + token_type_hint)
          https://datatracker.ietf.org/doc/html/rfc7009#section-2
        Spec: RFC 7009 §2.1 "Revocation Request"
          (token_type_hint is a search-order hint, not authoritative)
          https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
        Spec: RFC 7009 §2.2 "Revocation Response"
          (200 + empty body uniformly to prevent token probing)
          https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
        Spec: RFC 7009 §2.1, 2nd ¶ (revoking a refresh token SHOULD
          also invalidate access tokens issued under it)
        """
        from otpme.lib.session.oidc_session import hash_token

        client_id = command_args.get("client_id")
        client_secret = command_args.get("client_secret")
        token = command_args.get("token")
        hint = command_args.get("token_type_hint")
        client_ip = command_args.get("client_ip")

        log_msg = _("OIDC revoke from {ip} for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?", cid=client_id or "?")
        self.logger.info(log_msg)

        client, err = self._verify_oidc_client(client_id, client_secret)
        if err:
            log_msg = _("OIDC revoke rejected ({reason}).", log=True)[1]
            log_msg = log_msg.format(reason=err)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'revoke_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_client',
                            reason=err,
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_client',
                'error_description': "client authentication failed",
            })
        if not token:
            emit_audit("OIDC", 'revoke_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason='token missing',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'token missing',
            })

        h = hash_token(token)
        search_order = ['access_token_hash', 'refresh_token_hash']
        if hint == 'refresh_token':
            search_order = ['refresh_token_hash', 'access_token_hash']

        oidc_session = None
        for attr in search_order:
            result = backend.search(object_type="session",
                                    attribute=attr,
                                    value=h,
                                    return_type="instance")
            if result:
                oidc_session = result[0]
                break

        # RFC 7009 §2.2: success regardless of whether the token was
        # found or whether the calling client owns it.
        #   https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
        if oidc_session is None:
            return self.build_response(True, {})

        # Cross-client revoke defense: silently no-op if the token
        # belongs to a different client. Still return 200.
        if oidc_session.client != client.uuid:
            log_msg = _("OIDC revoke ignored: token belongs to a different client (got '{cid}').", log=True)[1]
            log_msg = log_msg.format(cid=client_id)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'revoke_cross_client',
                            level='warning',
                            client=client_id,
                            session=oidc_session.session_id,
                            ip=client_ip)
            return self.build_response(True, {})

        # Delete the OIDCSession. The override fires backchannel
        # logout if the client has a backchannel_logout_uri set.
        delete_failed = None
        try:
            oidc_session.delete(force=True, verify_acls=False)
        except Exception as e:
            log_msg = _("OIDC revoke: delete failed for session '{sid}': {err}", log=True)[1]
            log_msg = log_msg.format(sid=oidc_session.session_id, err=e)
            self.logger.warning(log_msg)
            delete_failed = str(e)
            # Per spec, still 200 to caller; internal failure logged.

        if delete_failed:
            emit_audit("OIDC", 'revoke_delete_failed',
                            level='warning',
                            client=client_id,
                            session=oidc_session.session_id,
                            reason=delete_failed,
                            ip=client_ip)
        else:
            emit_audit("OIDC", 'revoke_success',
                            client=client_id,
                            session=oidc_session.session_id,
                            ip=client_ip)
        log_msg = _("OIDC session '{sid}' revoked for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(sid=oidc_session.session_id, cid=client_id)
        self.logger.info(log_msg)
        return self.build_response(True, {})

    def oidc_end_session(self, command_args):
        """ /end_session endpoint.

        Browser-driven, no client_secret envelope -- trust is rooted
        in the signed ``id_token_hint`` (sid/aud/iss verified against
        site keys, exp not enforced).

        Logout behavior is decided by the resolved client's
        ``oidc_logout_scope`` config parameter:

        - ``"sso"`` (default): respond with ``{"action": "redirect_logout"}``;
          web layer hands off to /logout, which uses the existing
          SLP cascade to terminate the SSO session and all child
          OIDCSessions (each firing backchannel logout if configured).
        - ``"rp"``: delete only this OIDCSession (firing its
          backchannel logout side effect) and respond with
          ``{"action": "redirect_post_logout"}``.

        Open-redirect defense: the requested
        ``post_logout_redirect_uri`` is validated against the
        client's ``oidc_logout_redirect_uris`` allowlist here. The
        validated URI (or absent if not allowlisted / not provided)
        is included in the response so the web layer can decide
        between honoring the redirect and showing a generic OP
        logout page.

        Spec: OIDC RP-Initiated Logout 1.0 §2 "RP-Initiated Logout"
          (id_token_hint, client_id, post_logout_redirect_uri, state)
          https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
        Spec: OIDC RP-Initiated Logout 1.0 §3 "Redirection to RP
          After Logout" (state echo, validation against
          post_logout_redirect_uris)
          https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling
        Spec: OIDC Back-Channel Logout 1.0 (cascade to other RPs in
          the SSO session when ``oidc_logout_scope=sso``)
          https://openid.net/specs/openid-connect-backchannel-1_0.html
        Spec: OWASP ASVS V5.1.5 (open-redirect defense:
          allowlist-based validation of post_logout_redirect_uri)
        """
        id_token_hint = command_args.get("id_token_hint")
        client_id = command_args.get("client_id")
        post_logout_redirect_uri = command_args.get("post_logout_redirect_uri")
        client_ip = command_args.get("client_ip")

        log_msg = _("OIDC end_session from {ip} for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?", cid=client_id or "?")
        self.logger.info(log_msg)

        if not id_token_hint:
            emit_audit("OIDC", 'end_session_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason='id_token_hint missing',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'id_token_hint missing',
            })

        try:
            sid, hint_aud = self._parse_id_token_hint(id_token_hint,
                                                     allow_expired=True)
        except Exception as e:
            log_msg = _("OIDC end_session: id_token_hint invalid: {err}", log=True)[1]
            log_msg = log_msg.format(err=e)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'end_session_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason=f'id_token_hint invalid: {e}',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'id_token_hint invalid',
            })

        if client_id and client_id != hint_aud:
            log_msg = _("OIDC end_session: client_id mismatch with id_token_hint aud (got '{cid}', hint='{aud}').", log=True)[1]
            log_msg = log_msg.format(cid=client_id, aud=hint_aud)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'end_session_failed',
                            level='warning',
                            client=client_id,
                            hint_aud=hint_aud,
                            error='invalid_request',
                            reason='client_id does not match id_token_hint aud',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'client_id does not match id_token_hint',
            })
        client_id = client_id or hint_aud

        client = backend.get_object(object_type="client",
                                    name=client_id,
                                    realm=config.realm,
                                    site=config.site)
        if client is None:
            emit_audit("OIDC", 'end_session_failed',
                            level='warning',
                            client=client_id,
                            error='invalid_request',
                            reason='unknown client',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'unknown client',
            })

        # Validate post_logout_redirect_uri against the client's
        # registered allowlist. Anything not allowlisted is dropped
        # (web layer falls back to a generic logout page).
        validated_post_uri = None
        if post_logout_redirect_uri:
            allowed = set(getattr(client, 'oidc_logout_redirect_uris', []))
            if post_logout_redirect_uri in allowed:
                validated_post_uri = post_logout_redirect_uri
            else:
                log_msg = _("OIDC end_session: post_logout_redirect_uri '{uri}' not in allowlist for client '{cid}'.", log=True)[1]
                log_msg = log_msg.format(uri=post_logout_redirect_uri,
                                        cid=client_id)
                self.logger.warning(log_msg)
                emit_audit("OIDC", 'end_session_post_uri_rejected',
                                level='warning',
                                client=client_id,
                                requested_uri=post_logout_redirect_uri,
                                ip=client_ip)

        try:
            scope_mode = client.get_config_parameter("oidc_logout_scope")
        except Exception:
            scope_mode = None
        if scope_mode not in ("sso", "rp"):
            scope_mode = "sso"

        response = {'scope': scope_mode}
        if validated_post_uri:
            response['post_logout_redirect_uri'] = validated_post_uri

        if scope_mode == "sso":
            # Web layer hands off to /logout (SLP cascade).
            log_msg = _("OIDC end_session: scope=sso, deferring to /logout (client='{cid}').", log=True)[1]
            log_msg = log_msg.format(cid=client_id)
            self.logger.info(log_msg)
            emit_audit("OIDC", 'end_session_sso_deferred',
                            client=client_id,
                            session=sid,
                            post_logout_redirect_uri=validated_post_uri,
                            ip=client_ip)
            response['action'] = 'redirect_logout'
            # Surface the initiating client so the SLP cascade can
            # suppress back-channel logout to *this* RP -- it already
            # triggered the logout itself.
            response['initiating_client_uuid'] = client.uuid
            return self.build_response(True, response)

        # scope_mode == "rp": kill just this OIDCSession.
        oidc_session = backend.get_object(object_type="session", uuid=sid)
        if oidc_session is None:
            log_msg = _("OIDC end_session: session '{sid}' already gone.", log=True)[1]
            log_msg = log_msg.format(sid=sid)
            self.logger.info(log_msg)
            emit_audit("OIDC", 'end_session_session_missing',
                            client=client_id,
                            session=sid,
                            ip=client_ip)
            response['action'] = 'redirect_post_logout'
            return self.build_response(True, response)

        if oidc_session.client != client.uuid:
            log_msg = _("OIDC end_session: client/session mismatch (client='{cid}').", log=True)[1]
            log_msg = log_msg.format(cid=client_id)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'end_session_failed',
                            level='warning',
                            client=client_id,
                            session=oidc_session.session_id,
                            error='invalid_request',
                            reason='session does not belong to client',
                            ip=client_ip)
            return self.build_response(False, {
                'error': 'invalid_request',
                'error_description': 'session does not belong to this client',
            })

        session_id_for_audit = oidc_session.session_id
        try:
            # skip_backchannel: the RP itself triggered /end_session,
            # so a back-channel logout POST to it would be redundant
            # (and the RP typically answers HTTP 4xx because it has
            # already cleaned up locally).
            oidc_session.delete(force=True, verify_acls=False,
                                skip_backchannel=True)
        except Exception as e:
            log_msg = _("OIDC end_session: delete failed for session '{sid}': {err}", log=True)[1]
            log_msg = log_msg.format(sid=oidc_session.session_id, err=e)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'end_session_delete_failed',
                            level='warning',
                            client=client_id,
                            session=session_id_for_audit,
                            reason=str(e),
                            ip=client_ip)
            response['action'] = 'redirect_post_logout'
            return self.build_response(True, response)

        log_msg = _("OIDC session '{sid}' ended for client '{cid}' (rp scope).", log=True)[1]
        log_msg = log_msg.format(sid=oidc_session.session_id, cid=client_id)
        self.logger.info(log_msg)
        emit_audit("OIDC", 'end_session_rp_ended',
                        client=client_id,
                        session=session_id_for_audit,
                        post_logout_redirect_uri=validated_post_uri,
                        ip=client_ip)
        response['action'] = 'redirect_post_logout'
        return self.build_response(True, response)

    def oidc_authorize_validate(self, username, sso_jwt, command_args):
        """ Pre-validate an /authorize request and (on success) issue
        a SOTP scoped to the OIDC client's access group, all in one
        roundtrip.

        Web layer flow:
            1. ssod oidc_authorize_validate -> (sotp, client_ag)  [this]
            2. authd verify(password=sotp, oidc_context=True, ...)
            3. 302 redirect to RP

        Two-tier error reporting:
          - ``client_id`` / ``redirect_uri`` invalid  -> ``can_redirect=False``,
            web layer renders an error page (no redirect: would be an
            open-redirect vector).
          - All other errors -> ``can_redirect=True``, web layer
            redirects back to the validated redirect_uri with
            ``?error=...&state=...``.

        Spec: OIDC Core 1.0 §3.1.2.1 "Authentication Request"
          (request parameters: response_type, scope, client_id,
          redirect_uri, state, nonce, code_challenge,
          code_challenge_method)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        Spec: OIDC Core 1.0 §3.1.2.2 "Authentication Request
          Validation" (server-side checks before issuing code)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
        Spec: OIDC Core 1.0 §3.1.2.6 "Authentication Error Response"
          (two-tier: redirect_uri-invalid stays on OP; everything else
          redirects with error+state)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthError
        Spec: RFC 6749 §3.1.2 "Redirection Endpoint"
          (redirect_uri must match a pre-registered value exactly)
          https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
        Spec: RFC 7636 §4.3 "Client Sends the Code Challenge..."
          https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
        Spec: OAuth 2.1 §7.5.2 (PKCE required; ``plain`` forbidden by
          default, opt-in only via oidc_allow_plain_pkce)
          https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
        """
        # Authenticate the calling user via the SSO JWT, the same way
        # get_sotp does it. We need a verified user identity to issue
        # a SOTP off their session.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'JWT_INVALID',
                'status':  False,
            })

        session_uuid = command_args.get('session_uuid')
        if not session_uuid:
            return self.build_response(False, 'AUTHD_INCOMPLETE_COMMAND')
        session = backend.get_object(uuid=session_uuid)
        if not session:
            return self.build_response(False, {
                'message': 'UNKNOWN_SESSION', 'status': False,
            })
        if session.user_uuid != user.uuid:
            return self.build_response(False, {
                'message': 'AUTH_FAILED', 'status': False,
            })

        client_id = command_args.get("client_id")
        redirect_uri = command_args.get("redirect_uri")
        response_type = command_args.get("response_type")
        scope = command_args.get("scope") or ""
        code_challenge = command_args.get("code_challenge")
        code_challenge_method = command_args.get("code_challenge_method") or "plain"
        client_ip = command_args.get("client_ip")
        # OIDC ``prompt`` parameter (Core 3.1.2.1). Space-separated;
        # we only care about ``consent`` (force re-show even if a
        # stored consent covers the request) and ``none`` (RP forbids
        # any user interaction, so any consent gap must be reported
        # as ``interaction_required``).
        prompt_values = set((command_args.get("prompt") or "").split())
        # Set by the web layer after the user clicked Allow on the
        # consent screen. Without this flag, consent gaps return
        # ``consent_required`` to the web layer instead of issuing
        # a SOTP -- a malicious /authorize caller cannot bypass the
        # consent screen by setting it themselves because they don't
        # have a valid SSO JWT for the affected user.
        consent_granted = bool(command_args.get("consent_granted"))

        log_msg = _("OIDC authorize-validate from {ip} for user '{user}', client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?",
                                 user=user.name,
                                 cid=client_id or "?")
        self.logger.info(log_msg)

        def _err(error, description, can_redirect):
            log_msg = _("OIDC authorize rejected ({reason}).", log=True)[1]
            log_msg = log_msg.format(reason=description)
            self.logger.warning(log_msg)
            emit_audit("OIDC", 'authorize_rejected',
                            level='warning',
                            user=user.name,
                            client=client_id,
                            redirect_uri=redirect_uri,
                            error=error,
                            reason=description,
                            ip=client_ip)
            return self.build_response(False, {
                'error':             error,
                'error_description': description,
                'can_redirect':      can_redirect,
            })

        # Tier 1: client_id + redirect_uri -- failure here = no redirect.
        if not client_id:
            return _err('invalid_request', 'client_id missing',
                        can_redirect=False)
        if not redirect_uri:
            return _err('invalid_request', 'redirect_uri missing',
                        can_redirect=False)

        client = backend.get_object(object_type="client",
                                     name=client_id,
                                     realm=config.realm,
                                     site=config.site)
        if client is None:
            return _err('invalid_request', f"unknown client '{client_id}'",
                        can_redirect=False)
        if not getattr(client, 'enabled', True):
            return _err('invalid_request', f"client '{client_id}' disabled",
                        can_redirect=False)
        if not getattr(client, 'oidc_auth', False):
            return _err('invalid_request',
                        f"client '{client_id}' has OIDC disabled",
                        can_redirect=False)

        allowed_uris = getattr(client, 'oidc_redirect_uris', []) or []
        if redirect_uri not in allowed_uris:
            return _err('invalid_request',
                        f"redirect_uri '{redirect_uri}' not registered",
                        can_redirect=False)

        client_ag = getattr(client, 'access_group', None)
        if not client_ag:
            return _err('server_error',
                        f"client '{client_id}' has no access_group",
                        can_redirect=False)

        # Tier 2: from here on, redirect_uri is trusted -- errors go
        # back to the RP via redirect with state echo.
        if response_type != "code":
            return _err('unsupported_response_type',
                        f"response_type '{response_type}' not supported",
                        can_redirect=True)
        allowed_response_types = getattr(client, 'oidc_response_types', []) or []
        if response_type not in allowed_response_types:
            return _err('unsupported_response_type',
                        f"response_type '{response_type}' not allowed for this client",
                        can_redirect=True)

        allowed_grant_types = getattr(client, 'oidc_grant_types', []) or []
        if "authorization_code" not in allowed_grant_types:
            return _err('unauthorized_client',
                        "authorization_code grant not enabled for this client",
                        can_redirect=True)

        scope_set = set(scope.split())
        if 'openid' not in scope_set:
            return _err('invalid_scope',
                        "scope must include 'openid'",
                        can_redirect=True)

        # PKCE is required by default (OAuth 2.1 §7.5):
        #   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
        # Per-client / unit / site override walks up via the standard
        # config-param parent hierarchy. Disable only for legacy RPs
        # that can't generate code_verifier/code_challenge.
        try:
            pkce_required = client.get_config_parameter("oidc_pkce_required")
        except Exception:
            pkce_required = True
        if pkce_required is None:
            pkce_required = True

        if pkce_required and not code_challenge:
            return _err('invalid_request',
                        "PKCE is required: code_challenge missing",
                        can_redirect=True)
        # Method only validated when a challenge was provided -- with
        # PKCE off and no challenge, method is moot.
        if code_challenge:
            if code_challenge_method not in ("plain", "S256"):
                return _err('invalid_request',
                            f"code_challenge_method '{code_challenge_method}' not supported",
                            can_redirect=True)
            # OAuth 2.1 §7.5.2 forbids 'plain':
            #   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
            # Allowed only when the client (or its site/unit)
            # explicitly opted in via oidc_allow_plain_pkce -- never
            # the default.
            if code_challenge_method == "plain":
                try:
                    allow_plain = client.get_config_parameter(
                            "oidc_allow_plain_pkce")
                except Exception:
                    allow_plain = False
                if not allow_plain:
                    return _err('invalid_request',
                                "code_challenge_method 'plain' is forbidden "
                                "(OAuth 2.1); use 'S256'",
                                can_redirect=True)

        # End-user consent. Decision matrix:
        #   require_consent=False, no prompt=consent  -> skip
        #   prompt=consent                            -> force show
        #   stored consent covers requested scopes    -> skip
        #   otherwise                                 -> consent_required
        # prompt=none on top: any consent gap becomes interaction_required.
        requested_scopes = set(scope.split())
        try:
            require_consent = client.get_config_parameter(
                    "oidc_require_consent")
        except Exception:
            require_consent = False
        force_consent = "consent" in prompt_values
        if force_consent or require_consent:
            stored = user.get_oidc_consent(client.uuid) or {}
            stored_scopes = set(stored.get('scopes') or [])
            covered = (not force_consent
                       and requested_scopes.issubset(stored_scopes))
            if not covered and not consent_granted:
                # prompt=none + consent gap is a hard error per spec.
                if "none" in prompt_values:
                    return _err('interaction_required',
                                "user consent required but prompt=none",
                                can_redirect=True)
                emit_audit("OIDC", 'authorize_consent_required',
                                user=user.name,
                                client=client_id,
                                scope=scope,
                                forced=force_consent,
                                ip=client_ip)
                # No SOTP yet -- the web layer renders the consent
                # screen and re-invokes with consent_granted=True.
                client_name = getattr(client, 'name', client_id)
                client_desc = getattr(client, 'description', '') or ''
                # Compute the concrete claim values the RP would
                # receive so the consent screen can show "email:
                # alice@example.com" instead of just "email". This is
                # the same computation that runs at /token (and
                # /userinfo) -- previewing it doesn't leak anything
                # the user doesn't already know about themselves.
                try:
                    claims_preview = self._get_user_claims(user, scope,
                                                            client=client) or {}
                except Exception as e:
                    log_msg = _("Failed to compute claims preview for "
                                "consent screen: {err}", log=True)[1]
                    log_msg = log_msg.format(err=e)
                    self.logger.warning(log_msg)
                    claims_preview = {}
                # Normalise: callers send dict-able values only.
                # Strip anything non-JSON-serialisable defensively so
                # the response stays clean for ssod/web transport.
                claims_preview = {k: v for k, v in claims_preview.items()
                                  if isinstance(v, (str, int, float, bool,
                                                    list, dict, type(None)))}
                return self.build_response(True, {
                    'consent_required':  True,
                    'client_name':       client_name,
                    'client_description': client_desc,
                    'scopes':            sorted(requested_scopes),
                    'claims_preview':    claims_preview,
                })
            if consent_granted:
                user.set_oidc_consent(client.uuid, requested_scopes)
                try:
                    user._write(callback=self.get_callback())
                except Exception as e:
                    log_msg = _("Failed to persist OIDC consent for "
                                "user '{user}' / client '{cid}': "
                                "{err}", log=True)[1]
                    log_msg = log_msg.format(user=user.name,
                                              cid=client_id, err=e)
                    self.logger.warning(log_msg)
                emit_audit("OIDC", 'authorize_consent_granted',
                                user=user.name,
                                client=client_id,
                                scope=scope,
                                ip=client_ip)

        # Resolve client AG -> UUID, generate SOTP from session.
        ag_search = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=client_ag,
                                    return_type="uuid")
        if not ag_search:
            return _err('server_error', f"unknown access_group '{client_ag}'",
                        can_redirect=False)
        ag_uuid = ag_search[0]
        sotp_data = sotp.gen(password_hash=session.pass_hash,
                             access_group=ag_uuid)

        emit_audit("SSO", "sotp_issued",
                   user=user.name,
                   ag=client_ag,
                   session=session.session_id,
                   client=client_id,
                   via='oidc_authorize',
                   ip=client_ip)
        emit_audit("OIDC", 'authorize_success',
                        user=user.name,
                        client=client_id,
                        redirect_uri=redirect_uri,
                        scope=scope,
                        access_group=client_ag,
                        ip=client_ip)
        return self.build_response(True, {
            'ok':        True,
            'client_ag': client_ag,
            'sotp':      sotp_data,
        })

    def oidc_discovery(self, command_args):
        """ /.well-known/openid-configuration metadata.

        Field set is per the OIDC Discovery spec; values come from
        the running site + configured capabilities so admins don't
        drift from reality.

        Issuer + endpoint URLs are derived from ``site.sso_fqdn``;
        web layer doesn't need to pass anything.

        ``scopes_supported`` lists every enabled Scope object in the
        realm. This field is meant as the full set of scopes the OP
        accepts -- some RP libraries (mod_auth_openidc, oidc-client-ts,
        ...) refuse to complete auto-setup if a configured scope is
        missing here. Custom scopes (e.g. ``payments.execute``) are
        still gated by their per-Scope client allowlist;
        advertisement is independent of grant.

        Spec: OIDC Discovery 1.0 §3 "OpenID Provider Metadata"
          (issuer, *_endpoint, scopes_supported,
          response_types_supported, subject_types_supported,
          id_token_signing_alg_values_supported,
          token_endpoint_auth_methods_supported,
          claims_supported, grant_types_supported,
          code_challenge_methods_supported, ...)
          https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        Spec: OIDC Discovery 1.0 §4 "Obtaining OpenID Provider
          Configuration Information" (.well-known URL convention)
          https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
        Spec: RFC 8414 "OAuth 2.0 Authorization Server Metadata"
          (sibling spec; same metadata, OAuth-only)
          https://datatracker.ietf.org/doc/html/rfc8414
        Spec: OIDC Back-Channel Logout 1.0 §4 "Logout Discovery"
          (backchannel_logout_supported,
          backchannel_logout_session_supported)
          https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport
        Spec: OIDC Front-Channel Logout 1.0 §3 "Discovery Document"
          (frontchannel_logout_supported)
          https://openid.net/specs/openid-connect-frontchannel-1_0.html#FCSupport
        Spec: RFC 7636 §4.3 (advertise S256 in
          code_challenge_methods_supported; OAuth 2.1 omits "plain")
          https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
        """
        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if site is None:
            return self.build_response(False, {
                'error': 'server_error',
                'error_description': 'site not found',
            })

        issuer = f"https://{site.sso_fqdn}/oidc"

        # Algorithms = whatever currently lives on the site (active
        # + retired). Falls back to RS256 if oidc_keys is empty.
        algs = set()
        oidc_keys = site.get_oidc_keys()
        for jwk in oidc_keys.values():
            alg = jwk.get("alg")
            if alg:
                algs.add(alg)
        if not algs:
            algs = {"RS256"}

        # All enabled scopes on this site. Per OIDC Discovery 1.0 §3,
        # ``scopes_supported`` should advertise the full set the OP
        # accepts -- some RP libraries (mod_auth_openidc, oidc-client-ts)
        # refuse to complete auto-setup if a configured scope is
        # missing here. Scoping to the issuing site keeps the
        # advertisement consistent with the site-local OP semantics
        # (issuer/jwks/clients all live on this site). Privacy-wise
        # not a leak: scope names aren't secrets, and per-Scope
        # client allowlists still gate actual grants in
        # _compute_oidc_granted_scope. scope_id may repeat across
        # Scope objects (per-RP namespacing); dedup via sorted().
        scope_ids = backend.search(
                            object_type="scope",
                            attributes={
                                'enabled':     {'value': True},
                            },
                            realm=config.realm,
                            site=config.site,
                            return_attributes=['scope_id'])
        doc = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_uri": f"{issuer}/jwks",
            "introspection_endpoint": f"{issuer}/introspect",
            "revocation_endpoint": f"{issuer}/revoke",
            "end_session_endpoint": f"{issuer}/end_session",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": sorted(algs),
            "scopes_supported": sorted(scope_ids),
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
            ],
            # OAuth 2.1 §7.5.2: only S256 in discovery.
            #   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
            # ``plain`` is still accepted on the wire when an
            # individual client has ``oidc_allow_plain_pkce=True``
            # (legacy interop), but we don't advertise it.
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": [
                "sub", "iss", "aud", "iat", "exp", "jti", "sid",
                "name", "given_name", "family_name", "preferred_username",
                "email", "phone_number",
                "address",
                "groups",
            ],
            "frontchannel_logout_supported": False,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
        }
        return self.build_response(True, doc)

    def oidc_jwks(self, command_args):
        """ /jwks endpoint -- public keys only.

        Returns active + retired keys (so RPs can verify tokens
        signed before the most recent rotation). Revoked keys are
        removed from oidc_keys entirely and never appear here.

        Spec: RFC 7517 §5 "JWK Set Format"
          ({"keys": [<JWK>, ...]})
          https://datatracker.ietf.org/doc/html/rfc7517#section-5
        Spec: OIDC Core 1.0 §10.1 "Signing" (key rotation guidance;
          OP keeps retired keys published until tokens signed under
          them expire)
          https://openid.net/specs/openid-connect-core-1_0.html#SigEnc
        Spec: OIDC Core 1.0 §10.1.1 "Rotation of Asymmetric Signing
          Keys"
          https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
        """
        from otpme.lib.encryption.jwk import render_jwks

        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if site is None:
            return self.build_response(False, {
                'error': 'server_error',
                'error_description': 'site not found',
            })

        if not site.oidc_keys:
            return self.build_response(False, {
                'error': 'server_error',
                'error_description': 'site has not OIDC keys',
            })

        keys = list(site.get_oidc_keys().values())

        return self.build_response(True, render_jwks(keys))

    def _parse_id_token_hint(self, id_token_hint: str,
            allow_expired: bool = False):
        """ Decode + verify a JWT ID Token issued by us.

        Returns ``(sid, aud)``. Raises ``OTPmeException`` on
        signature/issuer/audience problems.

        ``allow_expired``: when True, ``exp``/``iat``/``nbf`` time
        checks are skipped. Only the /end_session flow should set
        this -- logout after the AT/ID-Token expired is legitimate
        per OIDC RP-Initiated Logout 1.0 §2. Any other use of the
        id_token_hint (e.g. silent re-auth, prompt=none binding)
        MUST keep the default ``False`` so an expired token can't
        be replayed.

        Independent of ``allow_expired``, an ``iat``-age cap is
        enforced (config parameter ``oidc_id_token_hint_max_age``,
        default 90 days) so a years-old ID Token from a leaked
        backup can't still drive an /end_session.

        Spec: OIDC RP-Initiated Logout 1.0 §2 "RP-Initiated Logout"
          (id_token_hint -- a previously issued ID Token used to
          identify the user/session being logged out)
          https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
        Spec: OIDC Core 1.0 §3.1.3.7 "ID Token Validation"
          (signature, iss, aud checks; exp normally enforced --
          relaxed only on the end_session path)
          https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        Spec: RFC 7519 §4.1.3 "aud" (may be a single string or an
          array of strings)
          https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        Spec: RFC 8725 §3 "Don't Mix Up Algorithms"
          (keyset-based verification pins to the alg encoded in
          the JWK; ``none`` is never accepted)
          https://datatracker.ietf.org/doc/html/rfc8725#section-3
        """
        import time as _time
        from joserfc import jwt as joserfc_jwt
        from joserfc.jwt import JWTClaimsRegistry
        from joserfc.jwk import RSAKey, ECKey, OKPKey, KeySet
        from otpme.lib.encryption.jwk import public_jwk

        class _NoTimeJWTClaimsRegistry(JWTClaimsRegistry):
            def validate_exp(self, value):
                return
            def validate_iat(self, value):
                return
            def validate_nbf(self, value):
                return

        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if site is None or not getattr(site, 'oidc_keys', None):
            raise OTPmeException("site has no signing keys")

        # Build a KeySet of all keys (active + retired) so old
        # tokens still verify during/after rotation.
        keys = []
        for jwk in site.get_oidc_keys().values():
            try:
                pub = public_jwk(jwk)
                kty = pub.get("kty")
                if kty == "RSA":
                    keys.append(RSAKey.import_key(pub))
                elif kty == "EC":
                    keys.append(ECKey.import_key(pub))
                elif kty == "OKP":
                    keys.append(OKPKey.import_key(pub))
            except Exception:
                continue
        if not keys:
            raise OTPmeException("no usable signing keys on site")
        keyset = KeySet(keys=keys)

        decoded = joserfc_jwt.decode(id_token_hint, keyset)
        claims = decoded.claims

        issuer = f"https://{site.sso_fqdn}/oidc"
        registry_cls = _NoTimeJWTClaimsRegistry if allow_expired \
                else JWTClaimsRegistry
        registry = registry_cls(
            iss={"essential": True, "value": issuer},
            aud={"essential": True},
            sub={"essential": True},
            sid={"essential": True},
        )
        try:
            registry.validate(claims)
        except Exception as e:
            raise OTPmeException(f"id_token_hint claim validation failed: {e}")

        # iat-age cap. Hardened against replay of a years-old leaked
        # ID Token. exp is intentionally NOT enforced (post-AT-expiry
        # logout is legitimate), but a hint older than the cap is
        # treated as stale.
        from otpme.lib.humanize import units
        try:
            max_age_human = site.get_config_parameter(
                    "oidc_id_token_hint_max_age")
        except Exception:
            max_age_human = None
        try:
            max_age = units.time2int(max_age_human, time_unit="s") \
                    if max_age_human is not None else 90 * 86400
        except Exception:
            max_age = 90 * 86400
        iat_claim = claims.get("iat")
        if iat_claim is not None:
            try:
                iat = int(iat_claim)
            except (TypeError, ValueError):
                raise OTPmeException("id_token_hint iat is not an integer")
            now = int(_time.time())
            # Reject iat from the far future (clock-skew threshold:
            # 5 minutes). Catches malformed/forged hints whose iat
            # would otherwise sit forever within the max_age window.
            if iat > now + 300:
                raise OTPmeException("id_token_hint iat is in the future")
            if (now - iat) > max_age:
                raise OTPmeException(
                        f"id_token_hint is older than the configured "
                        f"max age ({max_age}s)")

        # RFC 7519 §4.1.3: ``aud`` may be a JSON string or array of
        # strings:
        #   https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        aud_claim = claims["aud"]
        if isinstance(aud_claim, list):
            if not aud_claim:
                raise OTPmeException("aud empty")
            aud = aud_claim[0]
        else:
            aud = aud_claim
        return claims["sid"], aud

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
                            "change_language",
                            "fido2_register_begin",
                            "fido2_register_complete",
                            "list_device_tokens",
                            "add_device_token",
                            "del_device_token",
                            "sso_create_device_token",
                            "sso_delete_device_token",
                            "sso_get_device_token_role_uuid",
                            "oidc_token",
                            "oidc_userinfo",
                            "oidc_introspect",
                            "oidc_revoke",
                            "oidc_end_session",
                            "oidc_discovery",
                            "oidc_jwks",
                            "oidc_authorize_validate",
                            "list_oidc_consents",
                            "revoke_oidc_consent",
                        ]

        # OIDC commands are server-to-server (or browser-to-server
        # for end_session); the user-facing username/sso_jwt
        # envelope is bypassed for them.
        oidc_commands = ("oidc_token", "oidc_userinfo",
                         "oidc_introspect", "oidc_revoke",
                         "oidc_end_session",
                         "oidc_discovery", "oidc_jwks")

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

        if command in oidc_commands:
            log_msg = _("Processing OIDC command {command}.", log=True)[1]
            log_msg = log_msg.format(command=command)
            self.logger.info(log_msg)
            if command == "oidc_token":
                return self.oidc_token(command_args)
            if command == "oidc_userinfo":
                return self.oidc_userinfo(command_args)
            if command == "oidc_introspect":
                return self.oidc_introspect(command_args)
            if command == "oidc_revoke":
                return self.oidc_revoke(command_args)
            if command == "oidc_end_session":
                return self.oidc_end_session(command_args)
            if command == "oidc_discovery":
                return self.oidc_discovery(command_args)
            if command == "oidc_jwks":
                return self.oidc_jwks(command_args)

        # Try to get username.
        try:
            username = command_args['username']
        except Exception:
            status = False
            message = _("AUTHD_INCOMPLETE_COMMAND")
            return self.build_response(status, message)

        # Set proctitle to contain username.
        self.set_proctitle(username)

        try:
            sso_jwt = command_args['sso_jwt']
        except Exception:
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

        if command == "change_language":
            log_msg = _("Processing command change_language.", log=True)[1]
            self.logger.info(log_msg)
            return self.change_language(username, sso_jwt, command_args)

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

        if command == "oidc_authorize_validate":
            log_msg = _("Processing command oidc_authorize_validate.", log=True)[1]
            self.logger.info(log_msg)
            return self.oidc_authorize_validate(username, sso_jwt, command_args)

        if command == "list_oidc_consents":
            log_msg = _("Processing command list_oidc_consents.", log=True)[1]
            self.logger.info(log_msg)
            return self.list_oidc_consents(username, sso_jwt, command_args)

        if command == "revoke_oidc_consent":
            log_msg = _("Processing command revoke_oidc_consent.", log=True)[1]
            self.logger.info(log_msg)
            return self.revoke_oidc_consent(username, sso_jwt, command_args)

        return self.build_response(status, message)

    def _close(self):
        pass
