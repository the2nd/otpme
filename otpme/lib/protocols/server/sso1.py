# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import base64
import hashlib
import hmac
import traceback
import setproctitle
from pyotp.totp import TOTP
from urllib.parse import quote
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
from otpme.lib import stuff
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib import qrcode
from otpme.lib.protocols import status_codes
from otpme.lib.protocols import sso_helpers
from otpme.lib.protocols import tiqr_helpers
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.daemon.clusterd import add_cluster_state
from otpme.lib.daemon.clusterd import cluster_sync_state_delete
from otpme.lib.token.tiqr import tiqr as tiqr_token
from otpme.lib.classes.data_objects.photo import read_photo

from otpme.lib.exceptions import *

# Base of the staging token name a deploy parks its new credential
# under until the verify step moves it onto the SSO token. Realm and
# site get appended by OTPmeSsoP1._deploy_token_name(): with one portal
# per site the same user can have a deploy running at each, and a
# single shared slot would let one silently delete the other's.
#
# The base on its own is what a name is *tested* against -- see
# tiqr_enroll_finish(), which is reached by the phone directly and can
# be handed a grant another site issued, so the site in it is not ours
# to derive.
DEPLOY_NAME = "sso-deploy"

# Max age (in seconds) of an SSO session's reauth_time for a sensitive
# self-service action to count as "step-up freshly verified" without
# requiring another trip through /reauth. Kept short so a forgotten-
# unlocked-portal window doesn't stay indefinitely open for account-
# recovery-relevant changes. Sudo-mode style: refresh happens by re-
# authenticating, not by extending the window.
#
# Configurable as sso_reauth_timeout (site, unit, user); this is the
# value for a site older than the parameter, where the cascade finds
# nothing -- the same number the registration uses as its default.
STEP_UP_MAX_AGE = 120

# How much of that window has to be left when the settings page opens
# an add form. The user still has to type a name and touch a key after
# that, and a window that runs out in between costs them a second trip
# through /reauth -- so get_step_up_state asks for the reauth early
# rather than let them start something they cannot finish.
STEP_UP_ADD_MARGIN = 30

# How long a TOTP enrollment waits for its first code (seconds), and how
# many wrong ones it takes. Long enough to install an app first; the
# attempts are there for typos, not for security -- whoever holds the
# session sees the secret anyway.
TOTP_ENROLL_EXPIRY = 600
TOTP_ENROLL_MAX_ATTEMPTS = 5

# Token types a device token may be. The role says which of them its
# device tokens are (device_token_types); password when it says nothing.
DEVICE_TOKEN_TYPES = ("password", "totp")

# Byte length of the raw SSO-token recovery secret. 32 bytes = 256 bits
# after hex-encoding gives a 64-char URL parameter -- fits well into a
# short mail link and provides plenty of entropy against guessing.
# Persistent storage is a SHA256 hash of this value; the raw form only
# lives in the recovery mail body and the user's browser URL.
SSO_RECOVERY_TOKEN_BYTES = 32

# Token types the SSO-token recovery deploy flow knows how to
# provision credentials for. The admin's per-user/unit/site
# ``allow_sso_token_recovery`` list is authoritative for *whether*
# recovery is allowed; this list tracks *which* provisioning paths
# the deploy handlers actually implement (TOTP secret+QR, WebAuthn
# attestation, tiqr enrollment grant, plain-password change). Adding
# a new token type = add a branch in ``recovery_deploy_begin`` +
# ``recovery_deploy_verify`` + this tuple.
SSO_RECOVERY_DEPLOY_TYPES = ("totp", "fido2", "tiqr", "password")

# Token types a user may hand the SSO role to from the portal. Every one
# of them has a card of its own on the settings page, which is what
# makes promoting it meaningful: you can see the thing you are choosing.
# Passkeys are deliberately out -- they are meant as peers of the login
# token, not as the token the recovery flow looks for.
PROMOTABLE_TOKEN_TYPES = ("tiqr", "fido2", "totp")

# Name prefixes are built by OTPmeSsoP1._token_name_prefix(), which is
# the one place both ends go through: the add flows name tokens with it
# and the listings show only what carries it. A list filtered on a
# prefix nobody generates would simply be empty, with nothing to say
# why -- so the two must not be able to drift apart.

# Deploy types that are a thing the user owns and can tell apart from
# another of the same kind, so the deploy asks what to call it. The
# label is what the rename dialog offers when the SSO role later moves
# to another token -- exactly the types that can hold that role.
DEVICE_NAME_TOKEN_TYPES = PROMOTABLE_TOKEN_TYPES

# The parameter that allows managing tokens of a type on the settings
# page. Promoting is done from those cards, so it needs the same.
MGMT_ALLOW_PARAMS = {
            "fido2":    "sso_allow_fido2_mgmt",
            "tiqr":     "sso_allow_tiqr_mgmt",
            "totp":     "sso_allow_totp_mgmt",
            }

# Token types the portal can provision, and the parameter that says
# whether a user may be handed one. Order is what the deploy page shows.
DEPLOY_TOKEN_TYPES = ("totp", "fido2", "tiqr", "password")
DEPLOY_ALLOW_PARAMS = {
            "totp":     "sso_allow_totp_deploy",
            "fido2":    "sso_allow_fido2_deploy",
            "tiqr":     "sso_allow_tiqr_deploy",
            "password": "sso_allow_password_deploy",
            }

# On top of the deploy parameter above, these types have a switch that
# governs whether they may be used in the portal at all -- signing in
# included. Handing somebody a token of a type they cannot sign in with
# would be a way to lock them out, so deploying requires both.
DEPLOY_TYPE_ENABLED_PARAMS = {
            "fido2":    "sso_allow_fido2",
            "tiqr":     "sso_allow_tiqr",
            "totp":     "sso_allow_totp",
            }

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-sso-1.0"

def register():
    config.register_otpme_protocol("ssod", PROTOCOL_VERSION, server=True)

def _is_current_token(token):
    """ Is this the token the current session is signed in with?

    config.auth_token is set by verify_sso_jwt from the UUID the JWT
    carries. Deleting or disabling that very token locks the user out
    rather than sending them to a clean re-auth -- the next request
    would look for a token that is gone. Four handlers refuse it for
    that reason, and the passkey and tiqr listings flag it so the
    buttons are not offered in the first place. """
    if config.auth_token is None:
        return False
    return config.auth_token.uuid == token.uuid

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
    owner = backend.get_object(uuid=token.owner_uuid)
    allow_disabled_login = owner.allow_disabled_login
    token_ags = token.get_access_groups(return_type="uuid")
    for client in result:
        if not client.enabled:
            continue
        if not client.login_url:
            continue
        if not client.access_group_uuid:
            continue
        client_ag = backend.get_object(uuid=client.access_group_uuid)
        if not client_ag:
            continue
        if client_ag.uuid not in token_ags:
            continue
        maintenance_mode = False
        if not client_ag.enabled:
            if not allow_disabled_login:
                maintenance_mode = True
        client_data = {
                    'app_ag'            : client_ag.name,
                    'app_name'          : client.sso_name,
                    'login_url'         : client.login_url,
                    'maintenance_mode'  : maintenance_mode,
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
        self.require_preauth = False
        self.encrypt_session = False
        # Instructs parent class to require a client certificate.
        self.require_client_cert = True
        # ssod request are allowed on any node.
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

    def _portal_site(self, command_args):
        """ The site of the portal the user is standing in front of.

        ``portal_site`` is set by ssod_redirect_command() and
        _remote_ssod_call() on every cross-site forward. Its absence
        means we are the portal ourselves. """
        return command_args.get('portal_site') or config.site

    def _token_name_prefix(self, token_type, command_args):
        """ The prefix every token this portal creates for a user wears.

        Realm and site are in it because one user can hold a token of
        the same type for several portals -- the whole point of a
        per-site default_sso_token_name. Without the site in the name
        the second portal would either collide with the first one's
        token or list it as its own, and a security key registered for
        one portal's RP ID cannot answer for the other.

        The one place both ends go through: the add flows build names
        with it, the listings and the per-token commands accept only
        what carries it. A name generated with one prefix and filtered
        with another simply disappears from its card. """
        portal_site = self._portal_site(command_args)
        return f"{token_type}-{config.realm}-{portal_site}-"

    def _deploy_token_name(self, command_args):
        """ The staging token name of the portal running this deploy.

        Per portal, so two deploys for the same user cannot land in one
        slot -- deploy_begin() clears a stale staging token, and with a
        shared name that would silently throw away the other portal's
        half-finished enrollment.

        Only for creating and looking one up. Whether a *given* name is
        a staging name is asked with _is_deploy_token_name(), because
        that question also comes up for grants issued elsewhere. """
        portal_site = self._portal_site(command_args)
        return f"{DEPLOY_NAME}-{config.realm}-{portal_site}"

    def _is_deploy_token_name(self, token_name):
        """ Is this the staging name of a deploy, whoever started it?

        The site in the name is the one that issued the grant, and the
        phone finishing a tiqr enrollment may well reach a different
        one -- so this asks about the shape, not about us. A user
        chosen device name cannot look like this: those all carry a
        type prefix from _token_name_prefix(). """
        if not token_name:
            return False
        return token_name.startswith(f"{DEPLOY_NAME}-")

    def _sso_token_name(self, command_args):
        """ The name of the SSO token of the portal being used.

        Site scoped, and read off the site rather than off the user:
        user.get_config_parameter() walks the user's parents and would
        always end at the user's home site, while what a portal deploys,
        recovers and promotes is its own token. A user of site A signing
        in at site B's portal has to get B's answer -- that is what lets
        the same hardware key hold one credential per site, each in its
        own OTPme token, each with its own RP ID.

        ``portal_site`` is set by ssod_redirect_command() and
        _remote_ssod_call() on every cross-site forward. Its absence
        means we are the portal ourselves.

        The name is only ever a name, never a permission -- every one of
        the callers below still checks that the token belongs to this
        user -- so a peer that named a site it has no business naming
        could at worst make us look for a token under a different name
        of the same user. An unknown site falls back to our own, which
        is the answer we would have given before this parameter existed.
        """
        portal_site = self._portal_site(command_args)
        site = backend.get_object(object_type="site",
                                realm=config.realm,
                                name=portal_site)
        if site is None:
            log_msg = _("Unknown portal site '{site}', using own.", log=True)[1]
            log_msg = log_msg.format(site=portal_site)
            self.logger.warning(log_msg)
            site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)
        if site is None:
            return None
        return site.get_config_parameter("default_sso_token_name")

    def gen_sotp(self, user, ag_uuid, session_hash):
        user_ags = user.get_access_groups(return_type="uuid")
        if ag_uuid not in user_ags:
            msg = _("Unknown accessgroup")
            raise UnknownAccessgroup(msg)
        sotp_data = sotp.gen(password_hash=session_hash,
                             access_group=ag_uuid)
        return sotp_data

    def ssod_redirect_command(self, command, user, command_args, mgmt=False):
        try:
            ssod_conn = connections.get("ssod",
                                        mgmt=mgmt,
                                        realm=config.realm,
                                        site=user.site,
                                        auto_preauth=True,
                                        auto_auth=False)
        except Exception as e:
            log_msg = _("Redirect connection failed for command '{command}' (user '{user}' site '{site}' mgmt={mgmt}): {e}", log=True)[1]
            log_msg = log_msg.format(command=command,
                                    user=user.name,
                                    site=user.site,
                                    mgmt=mgmt,
                                    e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'REDIRECT_CONN_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        # The session_uuid only exists on the redirecting site (where the
        # SSO portal lives). The foreign ssod must not try to look it up
        # in its local backend -- strip it before forwarding.
        forward_args = dict(command_args)
        forward_args.pop('session_uuid', None)
        # Which portal the user is standing in front of. The home site
        # is about to run the command with its own config.site, and
        # what several of these commands need is the portal's answer --
        # see _sso_token_name(). Set here rather than at each call
        # site, because every one of them comes through here.
        forward_args['portal_site'] = config.site
        try:
            status, \
            status_code, \
            deploy_data, \
            binary_data = ssod_conn.send(command=command,
                                        command_args=forward_args)
        except Exception as e:
            log_msg = _("Failed to redirect command '{command}' (user '{user}' site '{site}' mgmt={mgmt}): {e}", log=True)[1]
            log_msg = log_msg.format(command=command,
                                    user=user.name,
                                    site=user.site,
                                    mgmt=mgmt,
                                    e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'REDIRECT_CONN_FAILED', 'status':False}
            return self.build_response(False, auth_response)
        finally:
            ssod_conn.close()
        log_msg = _("Redirect '{command}' to site '{site}' returned status={status} status_code={status_code}.", log=True)[1]
        log_msg = log_msg.format(command=command,
                                site=user.site,
                                status=status,
                                status_code=status_code)
        self.logger.debug(log_msg)
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
        # A JWT that decodes with this site's key still only proves it
        # was issued to some token *on* this site — not to the token of
        # the user named in the request. Bind the JWT to both:
        #   * the reason (SSO_AUTH), so a REALM_AUTH/REALM_LOGIN JWT for
        #     the same user cannot be substituted here
        #   * the token owner, so Alice's SSO JWT cannot drive endpoints
        #     that expect to act on Bob (see deploy_verify etc.)
        if jwt_data.get('reason') != 'SSO_AUTH':
            msg = "AUTH_WRONG_JWT_REASON"
            raise OTPmeException(msg)
        # The reason alone does not prove the token was allowed to open an
        # SSO session -- that is what membership in the SSO accessgroup
        # says, and gen_jwt() only checks it when the JWT is bound to one.
        # So require that binding here. Only the name is compared: a
        # foreign user's JWT is signed by, and carries the accessgroup of,
        # their home site.
        jwt_ag = jwt_data.get('accessgroup') or ""
        if jwt_ag.split("/")[-1] != config.sso_access_group:
            msg = "AUTH_WRONG_JWT_ACCESSGROUP"
            raise OTPmeException(msg)
        auth_token_uuid = jwt_data['login_token']
        auth_token = backend.get_object(uuid=auth_token_uuid)
        if not auth_token:
            msg = "AUTH_UNKOWN_TOKEN"
            raise OTPmeException(msg)
        if auth_token.owner_uuid != user.uuid:
            msg = "AUTH_JWT_USER_MISMATCH"
            raise OTPmeException(msg)
        # Set auth token.
        config.auth_token = auth_token
        self._set_auth_session(user, jwt_data)
        return user

    def _set_auth_session(self, user, jwt_data):
        """ Take over the SSO session the request names, for the audit log.

        The JWT cannot carry it: for a user of an untrusted site it is
        signed by the home site before this site has opened the session.
        So the web layer sends the session from its cookie -- a value the
        browser supplies -- and it counts only when the session exists
        here, belongs to this user and was opened with the token of this
        JWT: the login token, the link it came through, or a link whose
        destination it is. Otherwise nothing is set; a wrong session in
        the audit log is worse than none. Nothing is refused here. """
        session_uuid = getattr(self, '_request_session_uuid', None)
        if not session_uuid:
            return
        try:
            session = backend.get_object(object_type="session",
                                        uuid=session_uuid)
        except Exception:
            session = None
        if session is None:
            return
        if session.user_uuid != user.uuid:
            return
        login_token_uuid = jwt_data.get('login_token')
        jwt_tokens = (login_token_uuid, jwt_data.get('src_token'))
        if session.auth_token not in jwt_tokens:
            session_token = backend.get_object(uuid=session.auth_token)
            if session_token is None:
                return
            if session_token.destination_token != login_token_uuid:
                return
        config.auth_session = session.uuid
        config.auth_session_id = session.session_id

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
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        session_uuid = command_args.get('session_uuid')
        if not session_uuid:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=username,
                       ag=access_group,
                       reason='session_uuid missing',
                       ip=client_ip)
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
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
        try:
            sotp_data = self.gen_sotp(user, ag_uuid, session.pass_hash)
        except UnknownAccessgroup:
            emit_audit("SSO", "sotp_failed",
                       level='warning',
                       user=user.name,
                       ag=access_group,
                       reason='no_ag_permissions',
                       ip=client_ip)
            return self.build_response(False, {
                'message': 'UNKNOWN_AG', 'status': False,
            })
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
            message = "SSOD_INCOMPLETE_COMMAND"
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
        # Re-deploy assumes a credential the user can hand off and
        # re-enroll (OTP secret, FIDO2 attestation, ...). A passkey has
        # neither -- it lives on the device's authenticator -- so the
        # re-deploy UX (replace current login token in-place) makes no
        # sense. The settings page hides the entry point; defense in
        # depth here in case someone hits the deploy URL directly.
        if config.auth_token is not None \
        and config.auth_token.token_type == "passkey":
            return self.build_response(False, {
                'message': 'Re-deploy is not supported when signed in '
                           'with a passkey. Add or remove passkeys from '
                           'the Settings page instead.',
                'status': False})
        # Before the step-up: a re-deploy that is not allowed must not
        # send the user through /reauth first.
        if self._redeploy_refused(user):
            return self._redeploy_refused_response()
        # What this hands out replaces the token the user signs in with,
        # so it is the one flow where an unlocked browser buys the whole
        # account. The recovery deploy is a different command and is not
        # gated here: it has no session to prove anything with, the mail
        # link is the proof.
        step_up = self._step_up_required(user, "deploy_login_token_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        # Check for command redirection.
        if user.site != config.site:
            forward_args = dict(command_args)
            forward_args['_step_up_verified'] = True
            return self.ssod_redirect_command(command="deploy_begin",
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        # Unknown token_type falls through here and is rejected later by
        # add_token(), which is where the list of real types lives.
        if not self._deploy_type_allowed(user, token_type):
            msg = _("Deploy of token type '{tt}' is not allowed.")
            msg = msg.format(tt=token_type)
            return self.build_response(False, {'message': msg, 'status': False})
        # Prepare deploy.
        login_token = config.auth_token
        login_token_name = login_token.name
        # The portal deploys the token it is meant to deploy, not
        # whichever one you happened to sign in with. Without this a
        # user who logged in with an extra tiqr phone would silently
        # overwrite that phone instead of their SSO token -- harmless
        # while the SSO token was the only way in, but no longer true
        # now that additional tokens can log in as well.
        sso_token_name = self._sso_token_name(command_args)
        if sso_token_name and login_token_name != sso_token_name:
            msg = _("Please sign in with your '{name}' token to deploy.")
            msg = msg.format(name=sso_token_name)
            return self.build_response(False, {'message': msg, 'status': False})
        # Password: no staging token at all. The user's chosen
        # credential is the ONLY password we ever set; deploy_verify
        # creates the token with add_token(replace=True) in one step.
        # No placeholder, no double policy check, no cleanup path.
        if token_type == "password":
            response = {
                        'token_type'                : token_type,
                        'deploy_login_token_name'   : login_token_name,
                    }
            log_msg = _("SSO deploy started for user '{user_name}', token type 'password' (no staging token).", log=True)[1]
            log_msg = log_msg.format(user_name=user.name)
            self.logger.info(log_msg)
            return self.build_response(True, response)
        # Remove old sso-deploy token if it exists (e.g. from a previous
        # attempt). Our own staging slot only -- another portal's
        # half-finished deploy is none of our business.
        deploy_name = self._deploy_token_name(command_args)
        old_deploy = user.token(deploy_name)
        callback = self.get_callback()
        if old_deploy:
            # Not into the trash. A staging token from an abandoned
            # attempt was never in service -- it holds a credential
            # nobody ever authenticated with, and keeping it would only
            # collect debris. add_device_token_to_trash, which this
            # used to ask, is about the WLAN/IMAP device tokens and has
            # nothing to say here.
            user.del_token(token_name=deploy_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=False,
                            callback=callback)
            user._write(callback=callback)
        # tiqr: no staging token either, for the same reason as the
        # passkey flow -- the slot appears only once the phone has
        # delivered its secret. The enrollment grant simply names
        # DEPLOY_NAME as the token to create, so the whole regular
        # enrollment path applies unchanged and deploy_verify finds an
        # ordinary tiqr token waiting to be moved into place.
        # Both types that end up as somebody's phone or key carry a
        # label the user gave them, and both need it before anything is
        # created: tiqr because it goes into the enrollment grant, and
        # FIDO2 so the token has one at all -- without it the rename
        # dialog on a later promotion has nothing to offer but a random
        # string.
        device_name = None
        if token_type in DEVICE_NAME_TOKEN_TYPES:
            device_name, error = self._deploy_device_name(user, token_type,
                                                        command_args)
            if error is not None:
                return error
        if token_type == "tiqr":
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            expiry = time.time() + my_site.get_config_parameter("tiqr_enrollment_expiry")
            enroll_key = tiqr_helpers.build_enroll_key(
                                    tiqr_token.get_site_secret(),
                                    tiqr_helpers.ENROLL_SCOPE_METADATA,
                                    expiry,
                                    user_uuid=user.uuid,
                                    token_name=deploy_name,
                                    device_name=device_name,
                                    login_token_uuid=login_token.uuid)
            url_template = tiqr_helpers.build_metadata_url_template(my_site.sso_fqdn)
            metadata_url = tiqr_helpers.build_metadata_url(url_template,
                                                        enroll_key)
            enroll_scheme = my_site.get_config_parameter("tiqr_enroll_scheme")
            enroll_url = tiqr_helpers.build_enroll_url(enroll_scheme,
                                                    metadata_url)
            try:
                qrcode_data = qrcode.gen_qrcode(enroll_url, fmt="svg")
                if isinstance(qrcode_data, bytes):
                    qrcode_data = qrcode_data.decode('utf-8')
                qrcode_img = ("data:image/svg+xml;base64,"
                            + base64.b64encode(qrcode_data.encode()).decode())
            except Exception as e:
                log_msg = _("tiqr: QR code generation failed: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                return self.build_response(False,
                                {'message':'DEPLOY_FAILED', 'status':False})
            response = {
                        'token_type'                : token_type,
                        'deploy_token_name'         : deploy_name,
                        'deploy_login_token_name'   : login_token_name,
                        'enroll_url'                : enroll_url,
                        'qrcode_img'                : qrcode_img,
                    }
            log_msg = _("SSO deploy started for user '{user_name}', token type 'tiqr'.", log=True)[1]
            log_msg = log_msg.format(user_name=user.name)
            self.logger.info(log_msg)
            return self.build_response(True, response)
        # Create sso-deploy token (OATH or FIDO2) under the user.
        try:
            user.add_token(token_name=deploy_name,
                            token_type=token_type,
                            no_token_infos=True,
                            mode="mode1",
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("SSO deploy failed for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name)
            self.logger.critical(log_msg)
            response = {'message':'DEPLOY_FAILED', 'status':False}
            return self.build_response(status, response)
        # Get deploy token.
        deploy_token = user.token(deploy_name)
        if not deploy_token:
            response = {'message':'DEPLOY_FAILED', 'status':False}
            return self.build_response(status, response)
        # Build response.
        response = {
                    'token_type'                : token_type,
                    'deploy_token_name'         : deploy_name,
                    'deploy_login_token_name'   : login_token_name,
                }
        # FIDO2: setup via WebAuthn dance, no secret/QR here.
        if token_type == "fido2":
            # Where the self-service flow puts the label as well, so
            # both kinds of security key are named the same way. It
            # survives deploy_verify: the move renames the token, it
            # does not build a new one.
            deploy_token.change_device_name(device_name,
                                        force=True,
                                        verify_acls=False,
                                        run_policies=False,
                                        callback=callback)
            deploy_token._write(callback=callback)
            return self.build_response(True, response)
        # TOTP carries its label the same way, see above.
        if device_name:
            deploy_token.change_device_name(device_name,
                                        force=True,
                                        verify_acls=False,
                                        run_policies=False,
                                        callback=callback)
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

    def _redeploy_refused(self, user):
        """ Is this a re-deploy of the login token the config refuses?

        A token flagged sso_deploy has to be deployed, that is the
        forced first-login deploy and never refused here. Anything else
        is the user replacing their login token by choice, which
        sso_allow_login_token_redeploy allows or not. """
        login_token = config.auth_token
        if login_token is not None and login_token.sso_deploy:
            return False
        return not self._mgmt_allowed(user, "sso_allow_login_token_redeploy")

    def _redeploy_refused_response(self):
        return self.build_response(False,
                {'message':'Re-deploying your login token is not allowed.',
                'status':False})

    def get_login_token_options(self, username, sso_jwt, command_args):
        """ What the settings page offers for the login token.

        Read only and answered here, also for a user of another site:
        the parameters are synced, and the login token is the one of
        this SSO session. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        return self.build_response(True, {
                # For login tokens an administrator manages: with
                # sso_allow_totp_mgmt on the TOTP card sets PINs itself.
                'pin_change'    : not self._mgmt_allowed(user,
                                                "sso_allow_totp_mgmt"),
                'redeploy'      : not self._redeploy_refused(user),
                'status'        : True,
            })

    def get_allowed_deploy_token_types(self, username, sso_jwt, command_args):
        """ Return the token types this user is allowed to deploy in the
        SSO portal. Drives the deploy page UI so disabled types are not
        even rendered as buttons; ``deploy_begin`` enforces the same
        check authoritatively. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        # Asked here, before anything is shown, so the deploy page can
        # send the user through /reauth first and offer the choice
        # afterwards. deploy_begin still enforces it -- this only
        # decides when the user gets asked, not whether.
        #
        # On the portal and before the redirect below: the SSO session
        # lives here, and the home site could not answer it.
        #
        # A re-deploy that is not allowed goes first, or the page would
        # send the user through /reauth for nothing.
        if self._redeploy_refused(user):
            return self.build_response(True, {
                            'token_types'       : [],
                            'redeploy_refused'  : True,
                            'status'            : True,
                        })
        if self._step_up_missing(user, "deploy_login_token_reauth",
                                command_args):
            return self.build_response(True, {
                            'token_types'       : [],
                            'step_up_required'  : True,
                            'status'            : True,
                        })
        if user.site != config.site:
            # Answered above already. Without the marker the home site
            # asks again, cannot find a session that only exists here,
            # and sends the user back to /reauth for ever.
            forward_args = dict(command_args)
            forward_args['_step_up_verified'] = True
            return self.ssod_redirect_command(
                                    command="get_allowed_deploy_token_types",
                                    user=user,
                                    command_args=forward_args,
                                    mgmt=True)
        allowed = [tt for tt in DEPLOY_TOKEN_TYPES
                   if self._deploy_type_allowed(user, tt)]
        return self.build_response(True,
                            {'token_types': allowed, 'status': True})

    def deploy_verify(self, username, sso_jwt, command_args):
        try:
            token_data = command_args['token_data']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            login_token_name = command_args['login_token_name']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
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
        # Bind the deploy target to the token that authenticated this
        # SSO session. Without this, a session-holder for Bob could
        # aim the sso-deploy token move at any of Bob's other tokens
        # (e.g. a hardware key) and silently replace it with a secret
        # they know from the just-completed deploy_begin flow.
        if config.auth_token is None \
        or login_token_name != config.auth_token.name:
            response = {'message':'LOGIN_TOKEN_MISMATCH', 'status':False}
            return self.build_response(False, response)
        if self._redeploy_refused(user):
            return self._redeploy_refused_response()
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="deploy_verify",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        # Password recovery: no DEPLOY_NAME staging. Create a new
        # password token at the login-token slot with the user's
        # chosen password in one shot (add_token replace=True handles
        # both same-type overwrite and cross-type replacement).
        # add_token bubbles a real policy error message if the
        # password is too weak -- that's exactly what we want to
        # surface to the user.
        token_type_hint = token_data.get('token_type')
        if token_type_hint == "password":
            new_password = token_data.get('password')
            confirm = token_data.get('password_confirm')
            if not isinstance(new_password, str) or not new_password:
                response = {'message':'Password required.', 'status':False}
                return self.build_response(False, response)
            if confirm is not None and confirm != new_password:
                response = {'message':'Passwords do not match.', 'status':False}
                return self.build_response(False, response)
            callback = self.get_callback()
            callback.raise_exception = True
            try:
                user.add_token(token_name=login_token_name,
                                token_type="password",
                                replace=True,
                                password=new_password,
                                no_token_infos=True,
                                force=True,
                                verify_acls=False,
                                run_policies=True,
                                callback=callback)
                user._write(callback=callback)
            except Exception as e:
                log_msg = _("SSO deploy password set failed for user '{user_name}': {e}", log=True)[1]
                log_msg = log_msg.format(user_name=user.name, e=e)
                self.logger.warning(log_msg)
                response = {'message': str(e), 'status':False}
                return self.build_response(False, response)
            response = {'message':'Token deployment successful.', 'status':True}
            return self.build_response(True, response)
        # OATH / FIDO2: verify the staging token this portal parked,
        # then move it into the login-token slot. Same portal that ran
        # deploy_begin, so the same name comes out.
        deploy_name = self._deploy_token_name(command_args)
        deploy_token = user.token(deploy_name)
        if not deploy_token:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        if deploy_token.token_type == "fido2":
            if not deploy_token.credential_data:
                response = {'message':'Security key not registered yet.', 'status':False}
                return self.build_response(False, response)
        elif deploy_token.token_type == "tiqr":
            # The token existing at all already means the phone
            # answered -- the enrollment creates it only on success.
            # has_auth_data() is the same check the fido2 branch above
            # makes on credential_data.
            if not deploy_token.has_auth_data():
                response = {'message':'Phone not enrolled yet.', 'status':False}
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
        # Credential verified - move sso-deploy token to replace the login token.
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
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            is_deploy = command_args['is_deploy']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
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
        # Stash the (serialized) reg state + token slot under an opaque
        # state-id in the shared dict. The browser only ever sees the
        # state-id, so an attacker with access to the Flask session
        # cookie can't replay the WebAuthn challenge.
        #
        # Registration lands on the master node (mgmt=True from the web
        # layer; no multi-master in OTPme), so begin and complete meet
        # on the same node anyway -- but only until the master moves,
        # which would strand a registration in progress. Synced across
        # the cluster so it survives that. The state-id names the dict
        # it belongs to; that is how clusterd finds the target on the
        # other side.
        expiry = 300
        fido2_state_id = f"fido2_reg_states:{stuff.gen_secret(len=32)}"
        add_cluster_state(multiprocessing.fido2_reg_states,
                        state_id=fido2_state_id,
                        state_data={'state':      reg_state,
                                    'token_uuid': fido2_token.uuid},
                        expiry=expiry)
        fido2_reg_data = {
                    'create_options'        : dict(create_options),
                    'fido2_state_id'        : fido2_state_id,
                }
        return self.build_response(True, fido2_reg_data)

    def fido2_register_complete(self, username, sso_jwt, command_args):
        try:
            rp_id = command_args['rp_id']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            fido2_state_id = command_args['fido2_state_id']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            registration_data = command_args['registration_data']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
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
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="fido2_register_complete",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        # Pop the reg state under fido2_state_id. delete() is single-use:
        # a second complete-call with the same state-id within the TTL
        # window will miss, foiling replay. The delete goes to the other
        # nodes too, or the copies the sync left there would still be
        # collectable.
        try:
            state_data = multiprocessing.fido2_reg_states.delete(
                                                    fido2_state_id)
        except KeyError:
            log_msg = _("Fido2 reg state missing.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False, {
                    'message': 'REGISTRATION_FAILED', 'status': False})
        cluster_sync_state_delete(fido2_state_id)
        reg_state = state_data['state']
        # fido2_add_begin stores its own shape in the same dict (it has
        # a token_name, not a uuid -- there is no token yet). Its state
        # ids belong to fido2_add_complete; handing one here is a client
        # mixing up two flows, not something to raise on.
        token_uuid = state_data.get('token_uuid')
        if not token_uuid:
            log_msg = _("Fido2 reg state is not from a deploy registration.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False, {
                    'message': 'REGISTRATION_FAILED', 'status': False})
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
                info_messages, \
                attestation_cert = verify_attestation_cert(registration_data)
            except OTPmeException as e:
                log_msg = _("FIDO2 attestation cert verification failed for token '{token}' of user '{user_name}': {error}", log=True)[1]
                log_msg = log_msg.format(token=fido2_token.rel_path,
                                        user_name=user.name,
                                        error=e)
                self.logger.warning(log_msg)
                auth_response = {'message':str(e), 'status':False}
                return self.build_response(False, auth_response)
            for info_msg in info_messages:
                self.logger.info(info_msg)
            # Keep what we accepted, same as the deploy path does.
            fido2_token.attestation_cert = attestation_cert
        # Store credential data on token.
        fido2_token.rp = rp_id
        fido2_token.credential_data = encode(auth_data.credential_data, "hex")
        fido2_token._write(callback=self.get_callback())
        log_msg = _("FIDO2 token '{token}' registered for user '{user_name}'.")
        log_msg = log_msg.format(token=fido2_token.rel_path, user_name=user.name)
        self.logger.info(log_msg)
        response = {'message':log_msg, 'status':True}
        return self.build_response(True, response)

    def _mirror_login_token_memberships(self, user, token, login_token,
        callback, flow):
        """ Give a fresh token the same reach as the login token.

        Roles, direct access groups and direct groups get copied from
        the token the user actually presented in the current SSO JWT
        (config.auth_token, set by verify_sso_jwt) -- that is the real
        "login token" for this session, not necessarily
        user.default_token. Without them, logging in with the new token
        fails with "token is not valid for accessgroup 'SSO'".

        Only the direct memberships: what comes via a role follows by
        itself once the role is mirrored.

        This writes the memberships of the local site only -- a site
        owns its own roles, groups and access groups, and no multi
        master means we cannot write another site's. So for a user of
        another site it runs twice, once at each end: the home site
        creates the token and mirrors its own reach, then hands the
        object config and this login token's uuid back, and the portal
        runs the same pass for its side (_token_sync_config() ->
        _mirror_remote_token()).

        What still has no coverage is a third site the user never
        registered the token at. There is no fan-out to every site in
        the realm, and inventing reach somewhere the user has not been
        would be the wrong default anyway -- they add the token at that
        portal when they need it there.
        """
        if login_token is None:
            return
        token_path = f"{user.name}/{token.name}"
        members = (
                ("role", login_token.get_roles(return_type="instance")),
                ("access group", login_token.get_access_groups(
                                                include_roles=False,
                                                return_type="instance")),
                ("group", login_token.get_groups(include_roles=False,
                                                return_type="instance")),
                )
        for label, objects in members:
            for member in objects:
                if member.site != config.site:
                    continue
                try:
                    member.add_token(token_path=token_path,
                                    force=True,
                                    verify_acls=False,
                                    run_policies=False,
                                    callback=callback)
                    member._write(callback=callback)
                except Exception as e:
                    log_msg = _("{flow}: failed to mirror {label} '{name}' onto '{token}': {e}", log=True)[1]
                    log_msg = log_msg.format(flow=flow,
                                            label=label,
                                            name=member.name,
                                            token=token.rel_path, e=e)
                    self.logger.warning(log_msg)

    def _sanitize_passkey_token_name(self, device_name, command_args):
        """ Build a valid passkey token name from a user-supplied label.

        Restricted to ``[a-z0-9-]`` for the same reasons as
        ``_sanitize_device_token_name`` — the same function, so the two
        cannot drift apart. """
        prefix = self._token_name_prefix("passkey", command_args)
        return sso_helpers.sanitize_token_name(device_name, prefix=prefix)

    def _from_other_site_node(self):
        """ Did a node of another site send this request?

        That is the home side of a cross-site passkey or tiqr request,
        and it has to pass the trust check whether it carries the
        originator's marker or not: a node that leaves the marker out
        must not end up being treated like a local request. Nodes of our
        own site forward within the cluster and are not asked. """
        if not self.from_peer_node:
            return False
        return self.peer.site != config.site

    def _site_trusts_site(self, site, trusts_parameter):
        """ Does the local site list ``site`` under the given trusts
        parameter (e.g. ``sso_allow_passkeys_trusts``)? Returns False when
        the trust list is unset/empty. """
        local_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
        if local_site is None:
            return False
        try:
            trusts = local_site.get_config_parameter(trusts_parameter)
        except Exception:
            trusts = None
        if not trusts:
            return False
        return site in trusts

    def _trusts_user_home_site(self, user, trusts_parameter):
        """ Originator side: does the local site list the user's home
        site under the given trusts parameter? Own-site users are
        implicitly trusted. (Not _site_trusts_user_home(): that one is
        the device token roles trust further down.) """
        if user.site == config.site:
            return True
        return self._site_trusts_site(user.site, trusts_parameter)

    def _site_trusts_user_home_for_passkeys(self, user):
        """ Originator side: does the local site list the user's home
        site under ``sso_allow_passkeys_trusts``? Own-site users are
        implicitly trusted. Returns False when the trust list is
        unset/empty. """
        return self._trusts_user_home_site(user, "sso_allow_passkeys_trusts")

    def _site_trusts_site_for_passkeys(self, site):
        """ Home side: does the local site list ``site`` under
        ``sso_allow_passkeys_trusts``? Used to accept a peer-forwarded
        passkey operation only when reciprocal trust exists. """
        return self._site_trusts_site(site, "sso_allow_passkeys_trusts")

    def _log_passkey_denied(self, command, reason, user):
        """ Say which of the passkey gates refused, and on what.

        All of them answer the caller with the same sentence, which is
        right -- there is nothing useful to tell a browser here -- but
        it left the log with nothing either. Four branches per command,
        one message, and the two sides of a cross-site request run
        different ones: what the portal decides is not what the home
        site checks. Working out which fired meant reading the source
        with the config in the other hand.
        """
        log_msg = _("Passkeys denied: {command}: {reason}: user={user} user_site={user_site} own_site={own_site} peer={peer} peer_site={peer_site}", log=True)[1]
        log_msg = log_msg.format(command=command,
                                reason=reason,
                                user=getattr(user, 'name', None),
                                user_site=getattr(user, 'site', None),
                                own_site=config.site,
                                peer=getattr(self.peer, 'name', None),
                                peer_site=getattr(self.peer, 'site', None))
        self.logger.warning(log_msg)

    def _resolve_passkeys_allowed(self, user):
        """ Resolve ``sso_allow_passkeys`` to a bool, honouring the
        local site's ``sso_allow_passkeys_trusts``:
          - user of our own site → ``user.get_config_parameter``
            (user → unit → site cascade).
          - foreign user whose home site we trust → the same cascade,
            anchored at their home site.
          - foreign user we do not trust → False.

        That last case used to fall back to the local site's own
        ``sso_allow_passkeys``, which is how a portal without
        ``sso_allow_passkeys_trusts`` came to show the passkey card to
        a foreign user and then refuse the add: the listing asked less
        than the write did. Adding one is the operator's decision, and
        until they make it there is nothing here for that user.

        ``get_config_parameter`` returns the value from the first
        cascade level that has the parameter explicitly set, else
        ``None`` -- the ``default_value=True`` registered at the
        config layer is NOT auto-applied at read time. Apply it
        ourselves so foreign users (whose home cascade often has no
        explicit value) don't fall through to a False-looking None
        and see "Passkeys are not enabled."

        Every caller is a settings page command, so the settings card
        also needs ``sso_allow_passkey_mgmt``. """
        if not self._site_trusts_user_home_for_passkeys(user):
            return False
        if not self._mgmt_allowed(user, "sso_allow_passkey_mgmt"):
            return False
        try:
            registered_default = bool(
                    config.get_config_parameter("sso_allow_passkeys")['default'])
        except Exception:
            registered_default = True
        try:
            value = user.get_config_parameter("sso_allow_passkeys")
        except Exception:
            value = None
        if value is None:
            return registered_default
        return bool(value)

    def list_passkeys(self, username, sso_jwt, command_args):
        """ Return the user's passkey tokens (name + friendly description).

        Gated by the ``sso_allow_passkeys`` config parameter, resolved
        under ``sso_allow_passkeys_trusts`` (mirrors the
        ``admin_access_trusts`` pattern: originator decides under
        its own trust policy before the cross-site redirect, home
        re-validates with a reciprocal trust check). When disabled,
        return ``allowed=False`` and an empty list so the frontend can
        hide the entire card. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        peer_allowed = command_args.get('_passkeys_allowed')
        if self._from_other_site_node():
            # Home, peer-forwarded. Accept the originator's decision
            # only when the peer's site is reciprocally trusted.
            if not self._site_trusts_site_for_passkeys(self.peer.site):
                self._log_passkey_denied("list_passkeys",
                                    "peer site not in sso_allow_passkeys_trusts",
                                    user)
                return self.build_response(True, {
                        'passkeys': [], 'allowed': False, 'status': True})
            if not bool(peer_allowed):
                self._log_passkey_denied("list_passkeys",
                                    "originator said not allowed", user)
                return self.build_response(True, {
                        'passkeys': [], 'allowed': False, 'status': True})
        elif user.site != config.site:
            # Originator, foreign user. Resolve under local trust policy
            # before redirecting so an untrusted home doesn't even get
            # asked.
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("list_passkeys",
                                    "originator: user home not in "
                                    "sso_allow_passkeys_trusts, or "
                                    "sso_allow_passkeys off", user)
                return self.build_response(True, {
                        'passkeys': [], 'allowed': False, 'status': True})
            forward_args = dict(command_args)
            forward_args['_passkeys_allowed'] = True
            return self.ssod_redirect_command(command="list_passkeys",
                                            user=user,
                                            command_args=forward_args)
        else:
            # Local user.
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("list_passkeys",
                                    "local: sso_allow_passkeys off", user)
                return self.build_response(True, {
                        'passkeys': [], 'allowed': False, 'status': True})
        passkeys = []
        passkey_prefix = self._token_name_prefix("passkey", command_args)
        for token_uuid in user.tokens:
            try:
                token = backend.get_object(object_type="token", uuid=token_uuid)
            except Exception as e:
                log_msg = _("Failed to read token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if not token or token.token_type != "passkey":
                continue
            # Only list deployed passkeys -- a slot without credential_data
            # is the residue of a flow that bypassed the new add-via-web
            # path (it now creates the slot only on successful complete).
            if not token.credential_data:
                continue
            # And only the ones registered here, which is what this
            # portal's prefix says. A passkey is bound to the RP ID of
            # the portal that created it, so one from another portal
            # cannot sign in here at all -- listing it would offer
            # buttons for something this page cannot do anything with,
            # and it is in that portal's list already.
            if not token.name.startswith(passkey_prefix):
                continue
            passkeys.append({
                        'name'          : token.name,
                        'device_name'   : self._token_label(token) or token.name,
                        'enabled'       : bool(token.enabled),
                        # The one this session is signed in with. Both
                        # deleting and disabling it are refused (see
                        # del_passkey), so the UI can say so up front
                        # instead of letting the user find out by
                        # pressing the button.
                        'is_current'    : _is_current_token(token),
                    })
        return self.build_response(True, {'passkeys': passkeys,
                        'allowed': True,
                        'max_tokens': self._max_card_tokens(user, "passkey"),
                        'status': True})

    def _get_user_passkey(self, user, token_name, command_args):
        """ One of the user's own passkeys, by name.

        Only the ones this portal created, which is what its prefix
        says. A passkey carries the RP ID of the portal it was
        registered at and cannot answer anywhere else, so one from
        another portal is not this page's to delete or switch off -- it
        belongs in that portal's list, where it works.

        No exception for the SSO token, unlike the fido2 side: a
        passkey is never one (see PROMOTABLE_TOKEN_TYPES). """
        token = user.token(token_name)
        if token is None:
            return None
        if token.token_type != "passkey":
            return None
        prefix = self._token_name_prefix("passkey", command_args)
        if not token.name.startswith(prefix):
            return None
        return token

    def passkey_register_begin(self, username, sso_jwt, command_args):
        """ Build WebAuthn create-options for a new passkey.

        residentKey + userVerification are forced to "required" (that is
        the passkey definition). excludeCredentials carries the user's
        already-bound FIDO2 + passkey credentials so the browser refuses
        to bind the same authenticator twice. No token slot is created
        here — the slot materializes in ``passkey_register_complete`` on
        a successful registration so a cancelled flow leaves no debris.
        """
        try:
            rp_id = command_args['rp_id']
            device_name = command_args['device_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        device_name = sso_helpers.sanitize_device_label(device_name)
        if not device_name:
            return self.build_response(False, {'message':'Device name required.', 'status':False})
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        step_up = self._step_up_required(user, "deploy_passkey_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        # Resolve sso_allow_passkeys under sso_allow_passkeys_trusts.
        # See list_passkeys for the full pattern.
        peer_allowed = command_args.get('_passkeys_allowed')
        if self._from_other_site_node():
            if not self._site_trusts_site_for_passkeys(self.peer.site):
                self._log_passkey_denied("passkey_register_begin",
                                    "peer site not in sso_allow_passkeys_trusts",
                                    user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
            if not bool(peer_allowed):
                self._log_passkey_denied("passkey_register_begin",
                                    "originator said not allowed", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
        elif user.site != config.site:
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("passkey_register_begin",
                                    "originator: user home not in "
                                    "sso_allow_passkeys_trusts, or "
                                    "sso_allow_passkeys off", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
            forward_args = dict(command_args)
            forward_args['_passkeys_allowed'] = True
            forward_args['_step_up_verified'] = True
            return self.ssod_redirect_command(command="passkey_register_begin",
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        else:
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("passkey_register_begin",
                                    "local: sso_allow_passkeys off", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
        token_name = self._sanitize_passkey_token_name(device_name,
                                                    command_args)
        if not token_name:
            return self.build_response(False, {'message':'Invalid device name.', 'status':False})
        if user.token(token_name):
            return self.build_response(False, {'message':'A passkey with this name already exists.', 'status':False})
        refused = self._card_token_limit_reached(user, "passkey", command_args)
        if refused is not None:
            return refused
        # excludeCredentials: any already-bound FIDO2 or passkey credential
        # of this user. Browsers honour this to stop the same authenticator
        # registering twice (UX: "this key is already registered").
        existing_credentials = []
        for tok_uuid in user.tokens:
            tok = backend.get_object(object_type="token", uuid=tok_uuid)
            if not tok:
                continue
            if tok.token_type not in ("fido2", "passkey"):
                continue
            if not tok.credential_data:
                continue
            try:
                cred_data = decode(tok.credential_data, "hex")
                existing_credentials.append(AttestedCredentialData(cred_data))
            except Exception:
                continue
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        # attestation="none" matches PasskeyToken — synced passkeys rarely
        # carry useful attestation, requiring it would lock them out.
        fido2_server = Fido2Server(rp_data, attestation="none")
        # user.id MUST be a stable byte string per WebAuthn — UUID survives
        # renames and is what cloud-synced passkeys key off internally.
        user_data = {"id":          user.uuid.encode(),
                    "name":         user.name,
                    "displayName":  user.name}
        try:
            create_options, reg_state = fido2_server.register_begin(
                user_data,
                credentials=existing_credentials,
                resident_key_requirement="required",
                user_verification="required",
            )
        except Exception as e:
            log_msg = _("Passkey register_begin failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to start passkey registration: {e}', 'status':False})
        # Stash the (serialized) reg state + name fields under an opaque
        # state-id in the shared dict. The browser only sees the
        # state-id, so an attacker with access to the Flask session
        # cookie can't replay the WebAuthn challenge or learn the
        # in-flight device name.
        #
        # Registration lands on the master node (mgmt=True from the web
        # layer; no multi-master in OTPme), so begin and complete meet
        # on the same node anyway -- but only until the master moves,
        # which would strand a registration in progress. Synced across
        # the cluster so it survives that. The state-id names the dict
        # it belongs to; that is how clusterd finds the target on the
        # other side.
        expiry = 300
        passkey_state_id = f"passkey_reg_states:{stuff.gen_secret(len=32)}"
        add_cluster_state(multiprocessing.passkey_reg_states,
                        state_id=passkey_state_id,
                        state_data={'state':       reg_state,
                                    'device_name': device_name,
                                    'token_name':  token_name},
                        expiry=expiry)
        return self.build_response(True, {
                    'create_options'        : dict(create_options),
                    'passkey_state_id'      : passkey_state_id,
                })

    def passkey_register_complete(self, username, sso_jwt, command_args):
        """ Verify the WebAuthn registration response and create the
        passkey token slot. The slot is born already deployed -- we
        don't allow an empty passkey slot to exist. """
        try:
            rp_id = command_args['rp_id']
            passkey_state_id = command_args['passkey_state_id']
            registration_data = command_args['registration_data']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        # Resolve sso_allow_passkeys under sso_allow_passkeys_trusts.
        # The originator already gated this in passkey_register_begin;
        # gate again here on complete because the redirect carries a
        # fresh command_args and we don't want a peer to skip the
        # check by calling complete directly.
        peer_allowed = command_args.get('_passkeys_allowed')
        if self._from_other_site_node():
            if not self._site_trusts_site_for_passkeys(self.peer.site):
                self._log_passkey_denied("passkey_register_complete",
                                    "peer site not in sso_allow_passkeys_trusts",
                                    user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
            if not bool(peer_allowed):
                self._log_passkey_denied("passkey_register_complete",
                                    "originator said not allowed", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
        elif user.site != config.site:
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("passkey_register_complete",
                                    "originator: user home not in "
                                    "sso_allow_passkeys_trusts, or "
                                    "sso_allow_passkeys off", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
            forward_args = dict(command_args)
            forward_args['_passkeys_allowed'] = True
            # _remote_ssod_call rather than ssod_redirect_command,
            # because we need the payload and not just something to
            # hand back: the home site creates the token -- no multi
            # master -- but only this site can put it into this site's
            # SSO accessgroup, and without that the passkey is offered
            # by no login here. See _mirror_remote_token().
            status, remote_resp = self._remote_ssod_call(user=user,
                                            command="passkey_register_complete",
                                            extra_args=forward_args,
                                            mgmt=True)
            if not status or not isinstance(remote_resp, dict):
                return self.build_response(False, remote_resp)
            self._mirror_remote_token(user, remote_resp, flow="Passkey")
            return self.build_response(True, {
                        'status'        : True,
                        'name'          : remote_resp.get('name'),
                        'device_name'   : remote_resp.get('device_name'),
                        # Only on this path. The memberships we just
                        # wrote have to reach the user's home site
                        # before a login with this passkey works --
                        # that is where it is decided. We nudged the
                        # sync, but cannot promise when. On the local
                        # path there is nothing to wait for and the UI
                        # says nothing.
                        'sync_pending'  : True,
                    })
        else:
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("passkey_register_complete",
                                    "local: sso_allow_passkeys off", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
        # Pop the reg state under passkey_state_id. delete() is
        # single-use; a second complete with the same state-id misses.
        # Told to the other nodes as well, or their copies would still
        # answer.
        try:
            state_data = multiprocessing.passkey_reg_states.delete(
                                                    passkey_state_id)
        except KeyError:
            log_msg = _("Passkey reg state missing.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False, {
                    'message': 'REGISTRATION_FAILED', 'status': False})
        cluster_sync_state_delete(passkey_state_id)
        reg_state = state_data['state']
        device_name = state_data['device_name']
        token_name = state_data['token_name']
        if user.token(token_name):
            return self.build_response(False, {'message':'A passkey with this name already exists.', 'status':False})
        refused = self._card_token_limit_reached(user, "passkey", command_args)
        if refused is not None:
            return refused
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="none")
        try:
            auth_data = fido2_server.register_complete(reg_state,
                            registration_data)
        except Exception as e:
            log_msg = _("Passkey registration failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'REGISTRATION_FAILED', 'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            user.add_token(token_name=token_name,
                            token_type="passkey",
                            no_token_infos=True,
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to add passkey token: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to create passkey token: {e}', 'status':False})
        token = user.token(token_name)
        if not token:
            return self.build_response(False, {'message':'Failed to create passkey token.', 'status':False})
        token.rp = rp_id
        token.credential_data = encode(auth_data.credential_data, "hex")
        # The setter, not a plain assignment: it is what keeps the
        # changelog and the audit trail in step with the object.
        token.change_device_name(device_name,
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
        token._write(callback=callback)
        # A passkey is meant to be a peer of the login token: same
        # authorization, just a different factor on a different device.
        self._mirror_login_token_memberships(user, token,
                                            config.auth_token,
                                            callback,
                                            flow="Passkey")
        cred_hash = hashlib.sha256(auth_data.credential_data).hexdigest()[:16]
        emit_audit("Crypto", "passkey_credential_added",
                        user=user.name,
                        token=token.rel_path,
                        credential_fingerprint=cred_hash)
        log_msg = _("Passkey '{token}' registered for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token.rel_path, user_name=user.name)
        self.logger.info(log_msg)
        response = {
                    'status'        : True,
                    'name'          : token.name,
                    'device_name'   : token.device_name,
                }
        # Peer-forwarded: the portal mirrors the token and, more to the
        # point, writes the memberships of its own site. We just wrote
        # ours, and a passkey that is only in this site's SSO
        # accessgroup is offered by no other portal's login.
        response = self._token_sync_config(token, response,
                                        config.auth_token)
        return self.build_response(True, response)

    # ---- FIDO2 security keys (self-service) ----------------------------
    #
    # The same span the passkey commands above cover, for the other kind
    # of WebAuthn credential. Two differences run through all of it:
    #
    #   * A security key is cross-platform and needs no resident
    #     credential. That is what tells the two apart, so the register
    #     options say so rather than demanding residentKey like a
    #     passkey does.
    #
    #   * The gate resolves fail-open. FIDO2 login predates
    #     sso_allow_fido2 and must not stop working because nobody has
    #     set it; see _sso_allow_fido2_for_user in auth1.py, which
    #     resolves the same cascade for the login path. There is no
    #     trusts mechanism either: sso_allow_passkeys_trusts exists
    #     because passkey *login* is decided per home site, which is a
    #     different question from who may manage their own keys.

    def _resolve_fido2_allowed(self, user):
        """ The sso_allow_fido2 cascade (user -> unit -> site).

        Every caller is a settings page command, so the settings card
        also needs sso_allow_fido2_mgmt. Deploying a key is not asked
        here, see _deploy_type_allowed(). """
        if not self._mgmt_allowed(user, "sso_allow_fido2_mgmt"):
            return False
        try:
            value = user.get_config_parameter("sso_allow_fido2")
        except Exception:
            return True
        if value is None:
            return True
        return bool(value)

    def _sanitize_fido2_token_name(self, device_name, command_args):
        """ Build a fido2 token name from a user-supplied label. """
        prefix = self._token_name_prefix("fido2", command_args)
        return sso_helpers.sanitize_token_name(device_name, prefix=prefix)

    def _get_user_fido2_token(self, user, token_name, sso_token_name,
        command_args):
        """ One of the user's own fido2 tokens, by name.

        Only the ones the portal lists: the SSO token, and keys carrying
        this portal's prefix because this page created them. A key an
        administrator provisioned under some other name, or one another
        portal created, is not the user's to delete or switch off from
        here, and leaving it out of the listing would be cosmetic if
        the commands still took it.

        ``sso_token_name`` comes from the caller because it belongs to
        the portal, not to the user -- see _sso_token_name(). """
        token = user.token(token_name)
        if token is None:
            return None
        if token.token_type != "fido2":
            return None
        prefix = self._token_name_prefix("fido2", command_args)
        if token.name != sso_token_name \
        and not token.name.startswith(prefix):
            return None
        return token

    def list_fido2_tokens(self, username, sso_jwt, command_args):
        """ The user's security keys.

        Like the tiqr listing this includes the SSO token when that is a
        fido2 one, flagged, so somebody with two keys sees both -- and
        the one that matters most is not the hidden one.

        Two kinds are left out. Keys without credential_data, which is
        the empty slot an administrator creates for the older
        fido2_register_begin path and nothing the user can act on. And
        keys under a name this page did not choose: an administrator can
        provision a fido2 token for a purpose of their own, and offering
        a delete button for it would be wrong. What remains is the SSO
        token plus everything carrying this portal's prefix. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            # Read only, so no need to go to the master.
            return self.ssod_redirect_command(command="list_fido2_tokens",
                                            user=user,
                                            command_args=command_args)
        if not self._resolve_fido2_allowed(user):
            return self.build_response(True, {'fido2_tokens': [],
                                            'allowed': False,
                                            'status': True})
        fido2_prefix = self._token_name_prefix("fido2", command_args)
        sso_token_name = self._sso_token_name(command_args)
        fido2_tokens = []
        for token_uuid in user.tokens:
            try:
                token = backend.get_object(object_type="token", uuid=token_uuid)
            except Exception as e:
                log_msg = _("Failed to read token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if not token or token.token_type != "fido2":
                continue
            if not token.credential_data:
                continue
            # The SSO token and the keys registered here, nothing else.
            # An administrator can give a user a fido2 token under any
            # name, for a purpose the user is not meant to undo from the
            # portal -- listing those would offer a delete button for
            # something that is not theirs to remove. What this page
            # created carries this portal's prefix and is fair game --
            # a key registered at another portal does not, and belongs
            # in that portal's list rather than this one.
            if token.name != sso_token_name \
            and not token.name.startswith(fido2_prefix):
                continue
            fido2_tokens.append({
                        'name'          : token.name,
                        'device_name'   : self._token_label(token) or token.name,
                        'enabled'       : bool(token.enabled),
                        'is_sso_token'  : token.name == sso_token_name,
                        'is_current'    : _is_current_token(token),
                    })
        sso_token = user.token(sso_token_name)
        sso_token_label = None
        sso_token_suggested_label = None
        sso_token_ask_label = True
        if sso_token is not None:
            sso_token_label = (self._token_label(sso_token)
                            or sso_token.name)
            sso_token_suggested_label, sso_token_ask_label = \
                            self._suggest_displaced_token_label(user,
                                                        sso_token,
                                                        command_args)
        return self.build_response(True, {
                            'fido2_tokens': fido2_tokens,
                            'max_tokens': self._max_card_tokens(user, "fido2"),
                            'allowed': True,
                            'sso_token_name': sso_token_name,
                            'sso_token_type': (sso_token.token_type
                                            if sso_token else None),
                            'sso_token_label': sso_token_label,
                            'sso_token_suggested_label': sso_token_suggested_label,
                            'sso_token_ask_label': sso_token_ask_label,
                            'sso_token_managed': self._sso_token_managed(user,
                                                                sso_token),
                            'status': True})

    def fido2_add_begin(self, username, sso_jwt, command_args):
        """ Start registering another security key.

        Unlike fido2_register_begin this needs no empty token slot to
        exist: like the passkey flow the token is created on success, so
        a cancelled registration leaves nothing behind. """
        try:
            rp_id = command_args['rp_id']
            device_name = command_args['device_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        device_name = sso_helpers.sanitize_device_label(device_name)
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        step_up = self._step_up_required(user, "deploy_fido2_token_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        if user.site != config.site:
            forward_args = dict(command_args)
            forward_args['_step_up_verified'] = True
            return self.ssod_redirect_command(command="fido2_add_begin",
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        if not self._resolve_fido2_allowed(user):
            return self.build_response(False,
                    {'message':'Security keys are not enabled.',
                    'status':False})
        token_name = self._sanitize_fido2_token_name(device_name, command_args)
        if not token_name:
            msg = 'Invalid device name.'
            if not device_name:
                msg = 'Device name required.'
            return self.build_response(False,
                            {'message': msg, 'status':False})
        if user.token(token_name):
            return self.build_response(False,
                    {'message':'A token with this name already exists.',
                    'status':False})
        refused = self._card_token_limit_reached(user, "fido2", command_args)
        if refused is not None:
            return refused
        # excludeCredentials: every credential this user already has, of
        # either kind. Browsers use it to refuse binding the same
        # authenticator twice, which is the difference between "you
        # already registered this key" and a second entry nobody can
        # tell apart from the first.
        existing_credentials = []
        for tok_uuid in user.tokens:
            tok = backend.get_object(object_type="token", uuid=tok_uuid)
            if not tok:
                continue
            if tok.token_type not in ("fido2", "passkey"):
                continue
            if not tok.credential_data:
                continue
            try:
                cred_data = decode(tok.credential_data, "hex")
                existing_credentials.append(AttestedCredentialData(cred_data))
            except Exception:
                continue
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        # "direct" like fido2_register_begin, not the "none" the passkey
        # flow uses: a security key is a device with an attestation
        # worth having, a synced passkey usually is not.
        fido2_server = Fido2Server(rp_data, attestation="direct")
        user_data = {"id":          user.uuid.encode(),
                    "name":         user.name,
                    "displayName":  user.name}
        try:
            create_options, reg_state = fido2_server.register_begin(
                user_data,
                credentials=existing_credentials,
                user_verification="preferred",
                authenticator_attachment="cross-platform",
            )
        except Exception as e:
            log_msg = _("FIDO2 register_begin failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':f'Failed to start registration: {e}',
                    'status':False})
        # Same shared dict the deploy flow uses, with a shape of its own
        # -- token_name because there is no token yet. Both completes
        # check which shape they got.
        expiry = 300
        fido2_state_id = f"fido2_reg_states:{stuff.gen_secret(len=32)}"
        add_cluster_state(multiprocessing.fido2_reg_states,
                        state_id=fido2_state_id,
                        state_data={'state':       reg_state,
                                    'device_name': device_name,
                                    'token_name':  token_name},
                        expiry=expiry)
        return self.build_response(True, {
                    'create_options'    : dict(create_options),
                    'fido2_state_id'    : fido2_state_id,
                })

    def fido2_add_complete(self, username, sso_jwt, command_args):
        """ Verify the registration and create the security key token.

        Born deployed, like a passkey: an empty slot is not something
        this path leaves behind. """
        try:
            rp_id = command_args['rp_id']
            fido2_state_id = command_args['fido2_state_id']
            registration_data = command_args['registration_data']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            # _remote_ssod_call, not ssod_redirect_command: the home
            # site creates the token, but only we can put it into our
            # own SSO accessgroup, and a key that is in nobody's is
            # offered by no login. See _mirror_remote_token().
            status, remote_resp = self._remote_ssod_call(user=user,
                                            command="fido2_add_complete",
                                            extra_args=command_args,
                                            mgmt=True)
            if not status or not isinstance(remote_resp, dict):
                return self.build_response(False, remote_resp)
            self._mirror_remote_token(user, remote_resp, flow="FIDO2")
            return self.build_response(True, {
                        'status'        : True,
                        'name'          : remote_resp.get('name'),
                        'device_name'   : remote_resp.get('device_name'),
                        # See passkey_register_complete: only the
                        # cross-site path has anything to wait for.
                        'sync_pending'  : True,
                    })
        if not self._resolve_fido2_allowed(user):
            return self.build_response(False,
                    {'message':'Security keys are not enabled.',
                    'status':False})
        # Single use: a second complete with the same state id inside
        # the TTL misses, which is what stops a replay. On every node,
        # not only this one.
        try:
            state_data = multiprocessing.fido2_reg_states.delete(fido2_state_id)
        except KeyError:
            log_msg = _("FIDO2 reg state missing.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':'REGISTRATION_FAILED', 'status':False})
        cluster_sync_state_delete(fido2_state_id)
        token_name = state_data.get('token_name')
        if not token_name:
            # A state id from the deploy flow, which registers into an
            # existing slot. Not ours to finish.
            log_msg = _("FIDO2 reg state is not from a self-service registration.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':'REGISTRATION_FAILED', 'status':False})
        device_name = state_data.get('device_name') or token_name
        reg_state = state_data['state']
        if user.token(token_name):
            # Somebody was faster, or the name was taken while the user
            # was touching the key.
            return self.build_response(False,
                    {'message':'A token with this name already exists.',
                    'status':False})
        refused = self._card_token_limit_reached(user, "fido2", command_args)
        if refused is not None:
            return refused
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        try:
            auth_data = fido2_server.register_complete(reg_state,
                                                    registration_data)
        except Exception as e:
            log_msg = _("FIDO2 registration failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':'REGISTRATION_FAILED', 'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            user.add_token(token_name=token_name,
                            token_type="fido2",
                            no_token_infos=True,
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to add fido2 token: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':f'Failed to create token: {e}', 'status':False})
        token = user.token(token_name)
        if not token:
            return self.build_response(False,
                    {'message':'Failed to create token.', 'status':False})
        token.rp = rp_id
        token.credential_data = encode(auth_data.credential_data, "hex")
        # The setter, not a plain assignment: it is what keeps the
        # changelog and the audit trail in step with the object.
        token.change_device_name(device_name,
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
        token._write(callback=callback)
        # Same reach as the token the user signed in with -- otherwise
        # the new key is not valid for the SSO accessgroup and the next
        # login with it fails.
        self._mirror_login_token_memberships(user, token,
                                            config.auth_token,
                                            callback,
                                            flow="FIDO2")
        cred_hash = hashlib.sha256(auth_data.credential_data).hexdigest()[:16]
        emit_audit("Crypto", "fido2_credential_added",
                        user=user.name,
                        token=token.rel_path,
                        credential_fingerprint=cred_hash)
        log_msg = _("Security key '{token}' registered for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token.rel_path, user_name=user.name)
        self.logger.info(log_msg)
        response = {
                    'status'        : True,
                    'name'          : token.name,
                    'device_name'   : token.device_name,
                }
        # Same handshake as the passkey flow: the portal mirrors the
        # token and writes the memberships of its own site, which is
        # the half we cannot do from here.
        response = self._token_sync_config(token, response,
                                        config.auth_token)
        return self.build_response(True, response)

    def del_fido2_token(self, username, sso_jwt, command_args):
        """ Delete one of the user's own security keys.

        Not the SSO token: losing it takes the recovery flow with it,
        which looks for a token of that name. Moving that role to
        another key is what promote_token is for. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command="del_fido2_token",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        if not self._resolve_fido2_allowed(user):
            return self.build_response(False,
                    {'message':'Security keys are not enabled.',
                    'status':False})
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_fido2_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        if token_name == sso_token_name:
            return self.build_response(False,
                    {'message':'Cannot delete the default token. Make another '
                            'token the default token first.',
                    'status':False})
        if _is_current_token(token):
            return self.build_response(False,
                    {'message':'Cannot delete the security key you are '
                            'currently signed in with. Sign in with another '
                            'factor first.',
                    'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            add_to_trash = self._add_to_trash(user, "add_fido2_token_to_trash")
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to delete security key '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        emit_audit("Crypto", "fido2_token_deleted",
                        user=user.name,
                        token=f"{user.name}/{token_name}")
        log_msg = _("Security key '{token}' deleted for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token_name, user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True, {'status':True})

    def _set_fido2_token_enabled(self, username, sso_jwt, command_args,
        enable):
        """ Shared body of enable_fido2_token / disable_fido2_token. """
        command = "enable_fido2_token" if enable else "disable_fido2_token"
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command=command,
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        if not self._resolve_fido2_allowed(user):
            return self.build_response(False,
                    {'message':'Security keys are not enabled.',
                    'status':False})
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_fido2_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        if not enable:
            if token_name == sso_token_name:
                return self.build_response(False,
                        {'message':'Cannot disable the default token.',
                        'status':False})
            if _is_current_token(token):
                return self.build_response(False,
                        {'message':'Cannot disable the security key you are '
                                'currently signed in with.',
                        'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            if enable:
                token.enable(force=True, verify_acls=False,
                            run_policies=True, callback=callback)
            else:
                token.disable(force=True, verify_acls=False,
                            run_policies=True, callback=callback)
            token._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to change security key '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        return self.build_response(True, {'status':True,
                                        'enabled':bool(token.enabled)})

    def enable_fido2_token(self, username, sso_jwt, command_args):
        return self._set_fido2_token_enabled(username, sso_jwt,
                                            command_args, True)

    def disable_fido2_token(self, username, sso_jwt, command_args):
        return self._set_fido2_token_enabled(username, sso_jwt,
                                            command_args, False)

    def _tiqr_service_name(self, my_site):
        """ What the app shows as the name of the service, and what it
        files the account under.

        Two values, because they are not the same thing: the display
        name keeps its case, the identifier is folded -- see
        tiqr_helpers.canonical_service_identifier() for why. Returned
        together so no caller uses one where it means the other. """
        display_name = my_site.get_config_parameter("tiqr_service_display_name")
        if not display_name:
            display_name = config.realm
        identifier = tiqr_helpers.canonical_service_identifier(display_name,
                                                            config.realm)
        return display_name, identifier

    def tiqr_enroll_begin(self, username, sso_jwt, command_args):
        """ Start enrolling a phone. Creates no token.

        Like the passkey flow, the slot materializes only on success, so
        a cancelled attempt leaves no debris. What the phone needs to
        create it travels in a signed grant instead. """
        try:
            device_name = command_args['device_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        device_name = sso_helpers.sanitize_device_label(device_name)
        if not device_name:
            return self.build_response(False,
                            {'message':'Device name required.', 'status':False})
        try:
            url_template = command_args['metadata_url_template']
        except Exception:
            url_template = None
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        step_up = self._step_up_required(user, "deploy_tiqr_token_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        if self._tiqr_refused_from_peer_site("tiqr_enroll_begin", user,
                                            command_args):
            return self.build_response(False,
                    {'message':'tiqr is not enabled.', 'status':False})
        my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if user.site != config.site:
            # Decided before the home site gets asked: the phone will
            # deliver its secret to us.
            if not self._resolve_tiqr_allowed(user):
                self._log_tiqr_denied("tiqr_enroll_begin",
                                    "originator: user home not in "
                                    "sso_allow_tiqr_trusts, or "
                                    "sso_allow_tiqr off", user)
                return self.build_response(False,
                        {'message':'tiqr is not enabled.', 'status':False})
            # The QR code has to point at us, not at the user's home
            # site, but the grant inside it is minted there. So the home
            # site gets the URL with only the key left open.
            url_template = tiqr_helpers.build_metadata_url_template(my_site.sso_fqdn)
            command_args['metadata_url_template'] = url_template
            command_args['_step_up_verified'] = True
            command_args['_tiqr_allowed'] = True
            # No mgmt: this writes nothing. Unlike the passkey flow it
            # keeps no state on the master either -- what the phone
            # needs travels in the signed grant -- so any node can
            # answer.
            # _remote_ssod_call, not ssod_redirect_command: the latter
            # returns a finished response, and we still have something
            # to add to the payload.
            status, message = self._remote_ssod_call(
                                            command="tiqr_enroll_begin",
                                            user=user,
                                            extra_args=command_args)
            # Decided here, shown later. The enrollment itself is
            # answered to the phone, so the browser can only be told
            # something at begin time or when its poll finds the token
            # -- and the poll is the moment the user is looking. The
            # web layer carries the flag from here to there.
            #
            # Set on this path only: the token gets created on the
            # user's home site, we mirror it and write our own
            # memberships, and those have to travel back before a login
            # with the phone works.
            if status and isinstance(message, dict):
                message['sync_pending'] = True
            return self.build_response(status, message)
        if not self._resolve_tiqr_allowed(user):
            return self.build_response(False,
                    {'message':'tiqr is not enabled.', 'status':False})

        tiqr_prefix = self._token_name_prefix("tiqr", command_args)
        token_name = sso_helpers.sanitize_token_name(device_name,
                                                    prefix=tiqr_prefix)
        if not token_name:
            return self.build_response(False,
                            {'message':'Invalid device name.', 'status':False})
        if user.token(token_name):
            return self.build_response(False,
                    {'message':'A tiqr token with this name already exists.',
                    'status':False})
        refused = self._card_token_limit_reached(user, "tiqr", command_args)
        if refused is not None:
            return refused

        # The token the user presented in this session, not
        # user.default_token. This is the only point in the flow where a
        # session exists to read it, so it travels in the grant.
        login_token = config.auth_token
        if login_token is None:
            return self.build_response(False,
                            {'message':'No login token.', 'status':False})
        expiry = time.time() + my_site.get_config_parameter("tiqr_enrollment_expiry")
        enroll_key = tiqr_helpers.build_enroll_key(
                                tiqr_token.get_site_secret(),
                                tiqr_helpers.ENROLL_SCOPE_METADATA,
                                expiry,
                                user_uuid=user.uuid,
                                token_name=token_name,
                                device_name=device_name,
                                login_token_uuid=login_token.uuid)
        if not url_template:
            url_template = tiqr_helpers.build_metadata_url_template(my_site.sso_fqdn)
        try:
            metadata_url = tiqr_helpers.build_metadata_url(url_template,
                                                        enroll_key)
        except ValueError as e:
            log_msg = _("tiqr: rejected metadata URL template: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'ENROLL_FAILED', 'status':False})
        enroll_scheme = my_site.get_config_parameter("tiqr_enroll_scheme")
        enroll_url = tiqr_helpers.build_enroll_url(enroll_scheme, metadata_url)
        # The same URL twice: as a QR for a second device, and as a link
        # the app opens directly when the browser is on the phone
        # itself. The custom scheme works for both -- a universal link
        # would need the app associated with our domain, which only
        # holds for an app published under your own name.
        try:
            qrcode_data = qrcode.gen_qrcode(enroll_url, fmt="svg")
            if isinstance(qrcode_data, bytes):
                qrcode_data = qrcode_data.decode('utf-8')
            qrcode_img = ("data:image/svg+xml;base64,"
                        + base64.b64encode(qrcode_data.encode()).decode())
        except Exception as e:
            log_msg = _("tiqr: QR code generation failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'ENROLL_FAILED', 'status':False})
        log_msg = _("tiqr enrollment started for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True, {
                    'status'        : True,
                    'enroll_url'    : enroll_url,
                    'qrcode_img'    : qrcode_img,
                    'token_name'    : token_name,
                    'device_name'   : device_name,
                })

    def tiqr_enroll_metadata(self, command_args):
        """ The phone fetching what it needs to enroll.

        Unauthenticated: the grant in the URL is the authorisation, and
        it buys nothing but this. The second grant handed out here is
        the only one that may deliver a secret, so photographing the QR
        is not enough without fetching this first. """
        enroll_key = command_args.get('enrollment_key')
        if not enroll_key:
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        # Decode JWT.
        payload = jwt.decode(jwt=enroll_key,
                            secret="",
                            algorithm="HS256",
                            options={"verify_signature": False})
        # Get user UUID.
        user_uuid = payload['user_uuid']
        user = backend.get_object(uuid=user_uuid)
        if user is None:
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if user.site != config.site:
            command_args['sso_fqdn'] = my_site.sso_fqdn
            service_display_name, service_identifier = self._tiqr_service_name(my_site)
            command_args['service_display_name'] = service_display_name
            command_args['service_identifier'] = service_identifier
            return self.ssod_redirect_command(command="tiqr_enroll_metadata",
                                            user=user,
                                            command_args=command_args)
        try:
            sso_fqdn = command_args['sso_fqdn']
        except KeyError:
            sso_fqdn = None
        try:
            service_display_name = command_args['service_display_name']
        except KeyError:
            service_display_name = None
        try:
            service_identifier = command_args['service_identifier']
        except KeyError:
            service_identifier = None
        site_secret = tiqr_token.get_site_secret()
        try:
            claims = tiqr_helpers.parse_enroll_key(site_secret, enroll_key,
                                    tiqr_helpers.ENROLL_SCOPE_METADATA)
        except ValueError as e:
            log_msg = _("tiqr: rejected enrollment key: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        if not sso_fqdn:
            sso_fqdn = my_site.sso_fqdn
        # A second grant, same claims, different scope. Its window
        # starts here rather than at begin, so a phone that scans late
        # still gets the full time to send its secret.
        expiry = time.time() + my_site.get_config_parameter("tiqr_enrollment_expiry")
        secret_key = tiqr_helpers.build_enroll_key(
                                site_secret,
                                tiqr_helpers.ENROLL_SCOPE_SECRET,
                                expiry,
                                user_uuid=claims['user_uuid'],
                                token_name=claims['token_name'],
                                device_name=claims.get('device_name'),
                                login_token_uuid=claims['login_token_uuid'])
        base_url = f"https://{sso_fqdn}"
        sdn, si = self._tiqr_service_name(my_site)
        if not service_display_name:
            service_display_name = sdn
        if not service_identifier:
            service_identifier = si
        metadata = {
                'service'   : {
                    # displayName is what the user reads, identifier is
                    # what the app looks the account up by when an
                    # authentication URL arrives. The two differ in case
                    # on purpose -- see
                    # tiqr_helpers.canonical_service_identifier().
                    'displayName'       : service_display_name,
                    'identifier'        : service_identifier,
                    'logoUrl'           : f"{base_url}/static/otpme.png",
                    'infoUrl'           : base_url,
                    'authenticationUrl' : f"{base_url}/tiqr/auth",
                    'ocraSuite'         : user.get_config_parameter("tiqr_ocra_suite"),
                    'enrollmentUrl'     : (f"{base_url}/tiqr/enroll"
                                        f"?enrollment_secret={quote(secret_key, safe='')}"),
                },
                'identity'  : {
                    'identifier'    : user.name,
                    'displayName'   : user.name,
                },
            }
        return self.build_response(True, {'status':True, 'metadata':metadata})

    def _mirror_remote_token(self, user, remote_resp, flow):
        """ Write a token the user's home site just created into our own
        backend and hang it on our copy of the user.

        Same handshake add_device_token uses across sites: the home site
        is where the token is created -- no multi master -- and it sends
        the object config back so the site the browser or phone actually
        talked to can serve a login right away instead of waiting for
        the cluster sync.

        And it is not only about being early. The memberships that make
        a token usable are per site, and the home site can only write
        its own -- see _mirror_login_token_memberships(). Without the
        second pass below, a credential registered from here would work
        nowhere: fido2_auth_begin() looks for tokens of *this* site's
        SSO accessgroup, and the new one is in the home site's.

        Never fatal. By the time we get here the registration has
        already succeeded on the home site and the user holds a working
        credential; failing the response now would tell them otherwise,
        and the sync would hand us the token a moment later anyway. So a
        problem here is logged and swallowed.

        Returns the mirrored token, or None. """
        token_full_oid = remote_resp.get('token_full_oid')
        token_oc = remote_resp.get('token_oc')
        if not token_full_oid or not token_oc:
            # An older home site, or one that did not consider us
            # entitled to the config. The sync brings the token later.
            log_msg = _("{flow}: home site sent no token config to mirror.", log=True)[1]
            log_msg = log_msg.format(flow=flow)
            self.logger.debug(log_msg)
            return None
        try:
            token_oid = oid.get(object_id=token_full_oid, resolve=True)
            backend.write_config(object_id=token_oid,
                                object_config=token_oc,
                                full_index_update=True,
                                full_data_update=True,
                                cluster=True)
        except Exception as e:
            log_msg = _("{flow}: failed to mirror remote token object: {e}", log=True)[1]
            log_msg = log_msg.format(flow=flow, e=e)
            self.logger.warning(log_msg)
            return None
        token = backend.get_object(token_oid)
        if token is None:
            log_msg = _("{flow}: mirrored token object not readable back.", log=True)[1]
            log_msg = log_msg.format(flow=flow)
            self.logger.warning(log_msg)
            return None
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            user.add_token(new_token=token,
                            no_token_infos=True,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("{flow}: failed to attach mirrored token to user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(flow=flow, user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return None
        # The memberships do not come with the object: the token is a
        # member of nothing on the home site either -- reach is per
        # site, and this is the site the user is logging in to. So the
        # same mirroring the home site does for its own groups has to
        # run here for ours, off the same login token.
        #
        # Absent for a deploy flow: there the token inherits the SSO
        # token's UUID and with it every membership.
        login_token_uuid = remote_resp.get('login_token_uuid')
        if login_token_uuid:
            try:
                login_token = backend.get_object(uuid=login_token_uuid)
                self._mirror_login_token_memberships(user, token,
                                                    login_token,
                                                    callback, flow=flow)
            except Exception as e:
                log_msg = _("{flow}: failed to mirror memberships onto '{token}': {e}", log=True)[1]
                log_msg = log_msg.format(flow=flow, token=token.rel_path, e=e)
                self.logger.warning(log_msg)
        log_msg = _("{flow}: mirrored token '{token}' from site '{site}'.", log=True)[1]
        log_msg = log_msg.format(flow=flow, token=token.rel_path, site=user.site)
        self.logger.info(log_msg)
        self._notify_sync_peers(flow)
        return token

    def _notify_sync_peers(self, flow):
        """ Ask hostd to tell the other sites there is something new.

        The memberships we just wrote live on our own access groups and
        roles, and the user's home site decides a login against those
        objects (user.get_tokens() -> accessgroup.is_assigned_token()).
        Until they have reached it, the token is real but answers
        nowhere -- so the sooner the home site pulls, the shorter that
        window.

        Only a nudge. hostd throttles notifications (notify_limit,
        30s) and the regular sync interval runs regardless, so this
        shortens the wait rather than removing it. That is also why the
        portal tells the user it can take a moment: nothing here can
        promise the other side has caught up.

        Never fatal: a failed notification costs time, not
        correctness. """
        try:
            self._send_daemon_msg("hostd", "sync_notify")
        except Exception as e:
            log_msg = _("{flow}: failed to send sync notification: {e}", log=True)[1]
            log_msg = log_msg.format(flow=flow, e=e)
            self.logger.warning(log_msg)

    def _token_sync_config(self, token, response, login_token):
        """ Put a token's object config into a peer-forwarded response.

        The peer mirrors it locally so a login there works before the
        cluster sync catches up -- see _mirror_remote_token(). Only for
        a cluster peer: the browser and the phone reach these commands
        directly too, and an object config is not theirs to have.

        get_sync_config, not read_config: it hands out what this peer
        is allowed to see, which is the sync relationship's business
        and not ours to decide here.

        ``login_token`` is the token whose reach the new one inherits,
        and the peer needs it to mirror its own memberships -- ours are
        already written, and the token is a member of nothing over
        there. Passed in rather than read off config.auth_token,
        because not every caller has a session: the tiqr enrollment is
        answered to the phone, and its login token comes out of the
        signed grant. None means there is nothing for the peer to
        mirror -- a deploy flow, where the token inherits the SSO
        token's UUID and with it every membership. """
        if not self.from_peer_node:
            return response
        try:
            oc_obj = token.get_sync_config(self.peer)
        except Exception as e:
            log_msg = _("Failed to read token object config for peer: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return response
        if not oc_obj:
            return response
        response['token_full_oid'] = token.oid.full_oid
        response['token_oc'] = oc_obj.copy()
        if login_token is not None:
            response['login_token_uuid'] = login_token.uuid
        return response

    def tiqr_enroll_finish(self, command_args):
        """ The phone delivering the secret it generated.

        Unauthenticated, and the only request in the flow that writes.
        It can create exactly the token the signed grant names, for the
        user it names, with the reach of the token it names -- nothing
        else. """
        enroll_secret = command_args.get('enrollment_secret')
        secret = command_args.get('secret')
        if not enroll_secret or not secret:
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        # Decode JWT.
        payload = jwt.decode(jwt=enroll_secret,
                            secret="",
                            algorithm="HS256",
                            options={"verify_signature": False})
        # Get user UUID.
        user_uuid = payload['user_uuid']
        user = backend.get_object(uuid=user_uuid)
        if user is None:
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        # The request that carries the secret. The home site accepts it
        # from another site only when it trusts that site, and a portal
        # does not forward a secret to a home site it does not trust.
        if self._tiqr_refused_from_peer_site("tiqr_enroll_finish", user,
                                            command_args):
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        if user.site != config.site:
            if not self._resolve_tiqr_allowed(user):
                self._log_tiqr_denied("tiqr_enroll_finish",
                                    "originator: user home not in "
                                    "sso_allow_tiqr_trusts, or "
                                    "sso_allow_tiqr off", user)
                return self.build_response(False,
                                {'message':'INVALID_REQUEST', 'status':False})
            command_args['_tiqr_allowed'] = True
            # To the master: this creates a token and writes the role,
            # access group and group memberships onto it. No multi
            # master in OTPme, so tree object writes have to land there.
            #
            # _remote_ssod_call rather than ssod_redirect_command,
            # because we need the payload and not just a response to
            # hand back: the home site sends the new token's object
            # config along, and mirroring it here is what lets a login
            # on this site find the token before the cluster sync has
            # caught up.
            status, remote_resp = self._remote_ssod_call(user=user,
                                            command="tiqr_enroll_finish",
                                            extra_args=command_args,
                                            mgmt=True)
            if not status or not isinstance(remote_resp, dict):
                return self.build_response(False, remote_resp)
            self._mirror_remote_token(user, remote_resp, flow="tiqr")
            return self.build_response(True, {'status':True})
        # Decode enroll secret.
        site_secret = tiqr_token.get_site_secret()
        try:
            claims = tiqr_helpers.parse_enroll_key(site_secret, enroll_secret,
                                        tiqr_helpers.ENROLL_SCOPE_SECRET)
        except ValueError as e:
            log_msg = _("tiqr: rejected enrollment secret: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        try:
            # The apps generate it as hex. Anything else would fail on
            # the first login instead of here.
            bytes.fromhex(secret)
        except (ValueError, TypeError):
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})

        token_name = claims['token_name']
        if user.token(token_name):
            # Somebody was faster with this grant. The first one wins;
            # the user starts over and gets a new one.
            log_msg = _("tiqr: token '{token}' already exists.", log=True)[1]
            log_msg = log_msg.format(token=token_name)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        # Not for a deploy: that one replaces the SSO token and adds
        # nothing to the card.
        if not self._is_deploy_token_name(token_name):
            refused = self._card_token_limit_reached(user, "tiqr",
                                                    command_args)
            if refused is not None:
                return refused

        # Without the token named in the grant there is nothing to
        # inherit reach from -- the settings flow mirrors its
        # memberships, the deploy flows replace it and take over its
        # UUID -- and the new token would be created unusable either
        # way. Better to fail than to leave that behind.
        login_token = backend.get_object(uuid=claims['login_token_uuid'])
        if login_token is None:
            log_msg = _("tiqr: login token of the enrollment is gone.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})

        callback = self.get_callback()
        # Same reason as everywhere else here: without it a refusal
        # inside add_token or, worse, inside the membership mirroring
        # below just returns. The phone would finish its enrollment and
        # end up with a token that cannot reach anything, and the only
        # sign of it would be the login failing later.
        callback.raise_exception = True
        try:
            user.add_token(token_name=token_name,
                            token_type="tiqr",
                            no_token_infos=True,
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("tiqr: failed to add token for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name, e=e)
            self.logger.critical(log_msg)
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})

        token = user.token(token_name)
        if token is None:
            return self.build_response(False,
                            {'message':'INVALID_REQUEST', 'status':False})
        token.secret = secret
        token.ocra_suite = user.get_config_parameter("tiqr_ocra_suite")
        token.identity_id = user.name
        # The setter, like every other flow: the changelog and the
        # audit trail are what say where this label came from.
        token.change_device_name(claims.get('device_name'),
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
        # Stored for a push implementation that does not exist yet;
        # pushing to the stock apps would need SURF's credentials.
        token.notification_type = command_args.get('notification_type')
        token.notification_address = command_args.get('notification_address')
        token.deployed = True
        token._write(callback=callback)

        # Only the settings flow mirrors. The deploy flows name their
        # token DEPLOY_NAME, and their verify step moves it onto the
        # SSO token with replace=True -- Token.move() then hands over
        # the replaced token's UUID, and roles, groups and access
        # groups are keyed by exactly that UUID, so the reach comes
        # along by itself. Mirroring first would write this token's
        # temporary UUID into those objects and leave it behind as a
        # dangling member the moment the UUID is swapped.
        #
        # Asked by shape, not by name: the grant may have been issued
        # by another site, and its staging name carries that site. A
        # user-chosen device name can never look like one -- those all
        # come out of _token_name_prefix() with a type in front.
        if not self._is_deploy_token_name(token_name):
            self._mirror_login_token_memberships(user, token, login_token,
                                                callback, flow="tiqr")

        emit_audit("Crypto", "tiqr_token_enrolled",
                        user=user.name,
                        token=token.rel_path,
                        device_name=token.device_name)
        log_msg = _("tiqr token '{token}' enrolled for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token.rel_path, user_name=user.name)
        self.logger.info(log_msg)

        response = {'status':True}
        # Peer-forwarded: the site the phone actually talked to wants to
        # mirror the token, so that a login there finds it without
        # waiting for the cluster sync -- and so that it gets the
        # memberships of its own site, which we cannot write.
        #
        # The login token goes along only outside a deploy flow, the
        # same condition as the membership mirroring above and for the
        # same reason: there the token takes over the replaced token's
        # UUID and with it every membership, on either site.
        mirror_login_token = login_token
        if self._is_deploy_token_name(token_name):
            mirror_login_token = None
        response = self._token_sync_config(token, response,
                                        mirror_login_token)
        return self.build_response(True, response)

    def _deploy_type_allowed(self, user, token_type):
        """ May this token type be deployed for this user?

        Two questions, not one: whether deploying it is allowed
        (sso_allow_*_deploy) and, for the types that have such a switch,
        whether it may be used in the portal at all (sso_allow_fido2 /
        sso_allow_tiqr, which also govern signing in with one).

        A type we do not gate at all passes: deploy_begin lets an
        unknown type through on purpose, so that add_token() is the one
        place that decides what a real token type is. """
        deploy_param = DEPLOY_ALLOW_PARAMS.get(token_type)
        if deploy_param is None:
            return True
        if not user.get_config_parameter(deploy_param):
            return False
        enabled_param = DEPLOY_TYPE_ENABLED_PARAMS.get(token_type)
        if enabled_param is None:
            return True
        value = user.get_config_parameter(enabled_param)
        # Fail-open, matching _resolve_fido2_allowed /
        # _resolve_tiqr_allowed: only an explicit False blocks.
        if value is None:
            return True
        return bool(value)

    def _resolve_tiqr_allowed(self, user):
        """ The sso_allow_tiqr cascade (user -> unit -> site).

        Fail-open, like the FIDO2 one -- an explicit False blocks. What
        keeps tiqr off an install that never set it up is
        sso_allow_tiqr_deploy, which is off by default.

        A user of another site only if the local site lists their home
        site under sso_allow_tiqr_trusts. Unlike the cascade this one is
        not fail-open: the phone delivers its secret to the site whose QR
        code it scanned, and which sites may see it is the operator's
        decision.

        Every caller is a settings page command, so the settings card
        also needs sso_allow_tiqr_mgmt. """
        if not self._trusts_user_home_site(user, "sso_allow_tiqr_trusts"):
            return False
        if not self._mgmt_allowed(user, "sso_allow_tiqr_mgmt"):
            return False
        try:
            value = user.get_config_parameter("sso_allow_tiqr")
        except Exception:
            return True
        if value is None:
            return True
        return bool(value)

    def _log_tiqr_denied(self, command, reason, user):
        """ Say which of the tiqr trust gates refused, and on what. See
        _log_passkey_denied(). """
        log_msg = _("tiqr denied: {command}: {reason}: user={user} user_site={user_site} own_site={own_site} peer={peer} peer_site={peer_site}", log=True)[1]
        log_msg = log_msg.format(command=command,
                                reason=reason,
                                user=getattr(user, 'name', None),
                                user_site=getattr(user, 'site', None),
                                own_site=config.site,
                                peer=getattr(self.peer, 'name', None),
                                peer_site=getattr(self.peer, 'site', None))
        self.logger.warning(log_msg)

    def _tiqr_refused_from_peer_site(self, command, user, command_args):
        """ Home side of a tiqr request forwarded by another site.

        Such a request is accepted only when the local site lists the
        forwarding site under sso_allow_tiqr_trusts (the reciprocal half
        of the trust) and the forwarding site said it allows tiqr for the
        user (_tiqr_allowed). See _from_other_site_node(). """
        if not self._from_other_site_node():
            return False
        if not self._site_trusts_site(self.peer.site, "sso_allow_tiqr_trusts"):
            self._log_tiqr_denied(command,
                                "peer site not in sso_allow_tiqr_trusts",
                                user)
            return True
        if not command_args.get('_tiqr_allowed'):
            self._log_tiqr_denied(command, "originator did not allow it", user)
            return True
        return False

    def _get_user_tiqr_token(self, user, token_name, sso_token_name,
        command_args):
        """ One of the user's own tiqr tokens, by name.

        Only the ones the portal lists: the SSO token, and phones
        carrying this portal's prefix because an enrollment here named
        them. Same rule as _get_user_fido2_token, and for the same
        reason -- leaving a token out of the listing is cosmetic while
        the commands still take its name from the request. """
        token = user.token(token_name)
        if token is None:
            return None
        if token.token_type != "tiqr":
            return None
        prefix = self._token_name_prefix("tiqr", command_args)
        if token.name != sso_token_name \
        and not token.name.startswith(prefix):
            return None
        return token

    def _get_user_managed_token(self, user, token_name, command_args):
        """ One of the user's own tokens, by name, of a type they are
        allowed to manage themselves. Anything else is not ours to
        touch from the portal.

        And only one this portal created, i.e. one carrying its prefix
        -- the same rule the listings follow. An administrator hands out
        TOTP tokens under names of their own, for purposes the user is
        not meant to redirect: promoting one would make it the SSO
        token. """
        token = user.token(token_name)
        if token is None:
            return None
        if token.token_type not in PROMOTABLE_TOKEN_TYPES:
            return None
        if not self._mgmt_allowed(user, MGMT_ALLOW_PARAMS[token.token_type]):
            return None
        prefix = self._token_name_prefix(token.token_type, command_args)
        if not token.name.startswith(prefix):
            return None
        return token

    def _sso_token_managed(self, user, sso_token):
        """ Is the user's current SSO token one the portal manages?

        Only then may promote_token() hand its role to another token and
        rename it. Otherwise the administrator chose it -- a password or
        HOTP token, or a type whose management is off for this user --
        and the rename would give it a name of the portal's scheme, and
        maybe a delete button in a card, behind their back. No SSO token
        at all leaves nothing to displace. """
        if sso_token is None:
            return True
        if sso_token.token_type not in PROMOTABLE_TOKEN_TYPES:
            return False
        return self._mgmt_allowed(user,
                                MGMT_ALLOW_PARAMS[sso_token.token_type])

    def list_tiqr_tokens(self, username, sso_jwt, command_args):
        """ The user's enrolled phones.

        The SSO token is in here too when it is a tiqr one, flagged so
        the UI can mark it and leave out the delete button. Hiding it
        would be worse: somebody with two phones would see one, and the
        one they cannot see is the one that matters most.

        Everything else has to carry this portal's prefix, which is
        what an enrollment here gives it. A token under another name
        did not come from this page -- or came from another portal --
        and offering a delete button for it would be wrong; the
        security key card draws the same line. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if self._tiqr_refused_from_peer_site("list_tiqr_tokens", user,
                                            command_args):
            return self.build_response(True, {'tiqr_tokens': [],
                                            'allowed': False,
                                            'status': True})
        if user.site != config.site:
            if not self._resolve_tiqr_allowed(user):
                self._log_tiqr_denied("list_tiqr_tokens",
                                    "originator: user home not in "
                                    "sso_allow_tiqr_trusts, or "
                                    "sso_allow_tiqr off", user)
                return self.build_response(True, {'tiqr_tokens': [],
                                                'allowed': False,
                                                'status': True})
            forward_args = dict(command_args)
            forward_args['_tiqr_allowed'] = True
            # Read only, so no need to go to the master.
            return self.ssod_redirect_command(command="list_tiqr_tokens",
                                            user=user,
                                            command_args=forward_args)
        if not self._resolve_tiqr_allowed(user):
            return self.build_response(True, {'tiqr_tokens': [],
                                            'allowed': False,
                                            'status': True})
        sso_token_name = self._sso_token_name(command_args)
        tiqr_prefix = self._token_name_prefix("tiqr", command_args)
        tiqr_tokens = []
        for token_uuid in user.tokens:
            try:
                token = backend.get_object(object_type="token", uuid=token_uuid)
            except Exception as e:
                log_msg = _("Failed to read token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if not token or token.token_type != "tiqr":
                continue
            # Enrollment creates the token only on success, so anything
            # without a secret is residue from an older path.
            if not token.has_auth_data():
                continue
            # The SSO token and the phones enrolled here, nothing else.
            # An enrollment names its token itself, so today this only
            # catches one an administrator renamed or filled through
            # set_token_data -- but it is the same rule the security key
            # card follows, and one rule for both is easier to hold in
            # mind than an exception nobody remembers the reason for.
            if token.name != sso_token_name \
            and not token.name.startswith(tiqr_prefix):
                continue
            tiqr_tokens.append({
                        'name'          : token.name,
                        'device_name'   : self._token_label(token) or token.name,
                        'enabled'       : bool(token.enabled),
                        'is_sso_token'  : token.name == sso_token_name,
                        # Not the same thing as is_sso_token: since a
                        # second phone can sign in as well, the one you
                        # are holding need not be the one that carries
                        # the SSO role.
                        'is_current'    : _is_current_token(token),
                    })
        # What holds the SSO role right now, even when it is not a phone
        # and therefore not in the list above. Promoting a phone renames
        # that token, so the UI has to be able to ask the user what to
        # call it -- and to say which thing it is asking about.
        sso_token = user.token(sso_token_name)
        sso_token_type = sso_token.token_type if sso_token else None
        sso_token_label = None
        sso_token_suggested_label = None
        sso_token_ask_label = True
        if sso_token is not None:
            # Both are labels, and they still differ: this one names
            # the thing in the question we ask and falls back to the
            # SSO name when there is nothing better, while the
            # suggestion goes into the input and must never be that
            # name -- it is the one the token is losing.
            sso_token_label = (self._token_label(sso_token)
                            or sso_token.name)
            sso_token_suggested_label, sso_token_ask_label = \
                            self._suggest_displaced_token_label(user,
                                                        sso_token,
                                                        command_args)
        return self.build_response(True, {
                            'tiqr_tokens': tiqr_tokens,
                            'max_tokens': self._max_card_tokens(user, "tiqr"),
                            'allowed': True,
                            'sso_token_name': sso_token_name,
                            'sso_token_type': sso_token_type,
                            'sso_token_label': sso_token_label,
                            'sso_token_suggested_label': sso_token_suggested_label,
                            'sso_token_ask_label': sso_token_ask_label,
                            'sso_token_managed': self._sso_token_managed(user,
                                                                sso_token),
                            'status': True})

    def del_tiqr_token(self, username, sso_jwt, command_args):
        """ Delete one of the user's own tiqr tokens.

        Not the SSO token: losing it takes the recovery flow with it,
        which looks for a token of that name. Moving that role to
        another phone is what promote_token is for. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command="del_tiqr_token",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        if not self._resolve_tiqr_allowed(user):
            return self.build_response(False,
                    {'message':'tiqr is not enabled.', 'status':False})
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_tiqr_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        if token_name == sso_token_name:
            return self.build_response(False,
                    {'message':'Cannot delete the default token. Make another '
                            'phone the default token first.',
                    'status':False})
        # Refuse to delete the token of the current session, the same
        # way del_passkey does. The JWT would still carry its UUID and
        # the next request's verify_sso_jwt would fail to load
        # config.auth_token -- the user would be locked out instead of
        # getting a clean re-auth prompt.
        #
        # Not covered by the SSO-token check above: since tiqr, a second
        # phone can sign in as well, so the token you are holding need
        # not be the one named by default_sso_token_name.
        if _is_current_token(token):
            return self.build_response(False,
                    {'message':'Cannot delete the phone you are currently '
                            'signed in with. Sign in with another factor first.',
                    'status':False})
        callback = self.get_callback()
        # Or a refusal inside del_token -- a policy, say -- would go
        # through callback.error(), which only returns unless this is
        # set, and the except below would never see it. The phone would
        # be reported as deleted and still be there.
        callback.raise_exception = True
        try:
            add_to_trash = self._add_to_trash(user, "add_tiqr_token_to_trash")
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("tiqr: failed to delete token '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        emit_audit("Crypto", "tiqr_token_deleted",
                        user=user.name,
                        token=token_name)
        return self.build_response(True, {'status':True})

    def _set_tiqr_token_enabled(self, username, sso_jwt, command_args,
        enable):
        """ Shared body of enable_tiqr_token / disable_tiqr_token. """
        command = "enable_tiqr_token" if enable else "disable_tiqr_token"
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if self._tiqr_refused_from_peer_site(command, user, command_args):
            return self.build_response(False,
                    {'message':'tiqr is not enabled.', 'status':False})
        if user.site != config.site:
            if not self._resolve_tiqr_allowed(user):
                self._log_tiqr_denied(command,
                                    "originator: user home not in "
                                    "sso_allow_tiqr_trusts, or "
                                    "sso_allow_tiqr off", user)
                return self.build_response(False,
                        {'message':'tiqr is not enabled.', 'status':False})
            forward_args = dict(command_args)
            forward_args['_tiqr_allowed'] = True
            return self.ssod_redirect_command(command=command,
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        if not self._resolve_tiqr_allowed(user):
            return self.build_response(False,
                    {'message':'tiqr is not enabled.', 'status':False})
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_tiqr_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        # Disabling the SSO token would leave the portal without one
        # that works, and the user without a way back in.
        if not enable:
            if token_name == sso_token_name:
                return self.build_response(False,
                        {'message':'Cannot disable the default token.',
                        'status':False})
            # Nor the phone of the current session, which the check
            # above does not cover -- a second phone can sign in too.
            # Same guard the passkey flow has on both its paths.
            if _is_current_token(token):
                return self.build_response(False,
                        {'message':'Cannot disable the phone you are currently '
                                'signed in with.',
                        'status':False})
        callback = self.get_callback()
        try:
            if enable:
                token.enable(force=True, verify_acls=False,
                            run_policies=True, callback=callback)
            else:
                token.disable(force=True, verify_acls=False,
                            run_policies=True, callback=callback)
            token._write(callback=callback)
        except Exception as e:
            log_msg = _("tiqr: failed to change token '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        return self.build_response(True, {'status':True,
                                        'enabled':bool(enable)})

    def enable_tiqr_token(self, username, sso_jwt, command_args):
        """ Enable one of the user's own tiqr tokens. """
        return self._set_tiqr_token_enabled(username, sso_jwt,
                                            command_args, True)

    def disable_tiqr_token(self, username, sso_jwt, command_args):
        """ Disable one of the user's own tiqr tokens. """
        return self._set_tiqr_token_enabled(username, sso_jwt,
                                            command_args, False)

    def _resolve_totp_allowed(self, user):
        """ The sso_allow_totp cascade (user -> unit -> site).

        Fail-open like the tiqr one. A user of another site only if the
        local site lists their home site under sso_allow_totp_trusts --
        the secret is handed out by, and passes through, the portal the
        user stands in front of. See _resolve_tiqr_allowed().

        Every caller is a settings page command, so the settings card
        also needs sso_allow_totp_mgmt. """
        if not self._trusts_user_home_site(user, "sso_allow_totp_trusts"):
            return False
        if not self._mgmt_allowed(user, "sso_allow_totp_mgmt"):
            return False
        try:
            value = user.get_config_parameter("sso_allow_totp")
        except Exception:
            return True
        if value is None:
            return True
        return bool(value)

    def _log_totp_denied(self, command, reason, user):
        """ Say which of the TOTP trust gates refused, and on what. See
        _log_passkey_denied(). """
        log_msg = _("TOTP denied: {command}: {reason}: user={user} user_site={user_site} own_site={own_site} peer={peer} peer_site={peer_site}", log=True)[1]
        log_msg = log_msg.format(command=command,
                                reason=reason,
                                user=getattr(user, 'name', None),
                                user_site=getattr(user, 'site', None),
                                own_site=config.site,
                                peer=getattr(self.peer, 'name', None),
                                peer_site=getattr(self.peer, 'site', None))
        self.logger.warning(log_msg)

    def _totp_refused_from_peer_site(self, command, user, command_args):
        """ Home side of a TOTP request forwarded by another site. Same
        rule as _tiqr_refused_from_peer_site(), under
        sso_allow_totp_trusts and _totp_allowed. """
        if not self._from_other_site_node():
            return False
        if not self._site_trusts_site(self.peer.site, "sso_allow_totp_trusts"):
            self._log_totp_denied(command,
                                "peer site not in sso_allow_totp_trusts",
                                user)
            return True
        if not command_args.get('_totp_allowed'):
            self._log_totp_denied(command, "originator did not allow it", user)
            return True
        return False

    def _totp_not_enabled(self):
        """ The answer to a TOTP command the gates refused. """
        return self.build_response(False,
                {'message':'Authenticator apps are not enabled.',
                'status':False})

    def _get_user_totp_token(self, user, token_name, sso_token_name,
        command_args):
        """ One of the user's own TOTP tokens, by name.

        Only the ones the portal lists: the SSO token, and apps carrying
        this portal's prefix. An administrator hands out TOTP tokens
        under names of their own -- device tokens among them -- and
        those are not the user's to delete or switch off from here. """
        token = user.token(token_name)
        if token is None:
            return None
        if token.token_type != "totp":
            return None
        prefix = self._token_name_prefix("totp", command_args)
        if token.name != sso_token_name \
        and not token.name.startswith(prefix):
            return None
        return token

    def list_totp_tokens(self, username, sso_jwt, command_args):
        """ The user's authenticator apps.

        Same shape and the same rule as list_tiqr_tokens(): the SSO token
        when it is a TOTP one, flagged, plus everything carrying this
        portal's prefix. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        not_allowed = self.build_response(True, {'totp_tokens': [],
                                                'allowed': False,
                                                'status': True})
        if self._totp_refused_from_peer_site("list_totp_tokens", user,
                                            command_args):
            return not_allowed
        if user.site != config.site:
            if not self._resolve_totp_allowed(user):
                self._log_totp_denied("list_totp_tokens",
                                    "originator: user home not in "
                                    "sso_allow_totp_trusts, or "
                                    "sso_allow_totp off", user)
                return not_allowed
            forward_args = dict(command_args)
            forward_args['_totp_allowed'] = True
            # Read only, so no need to go to the master.
            return self.ssod_redirect_command(command="list_totp_tokens",
                                            user=user,
                                            command_args=forward_args)
        if not self._resolve_totp_allowed(user):
            return not_allowed
        sso_token_name = self._sso_token_name(command_args)
        totp_prefix = self._token_name_prefix("totp", command_args)
        totp_tokens = []
        for token_uuid in user.tokens:
            try:
                token = backend.get_object(object_type="token", uuid=token_uuid)
            except Exception as e:
                log_msg = _("Failed to read token object: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if not token or token.token_type != "totp":
                continue
            if token.name != sso_token_name \
            and not token.name.startswith(totp_prefix):
                continue
            totp_tokens.append({
                        'name'          : token.name,
                        'device_name'   : self._token_label(token) or token.name,
                        'enabled'       : bool(token.enabled),
                        'is_sso_token'  : token.name == sso_token_name,
                        'is_current'    : _is_current_token(token),
                    })
        sso_token = user.token(sso_token_name)
        sso_token_label = None
        sso_token_suggested_label = None
        sso_token_ask_label = True
        if sso_token is not None:
            sso_token_label = (self._token_label(sso_token)
                            or sso_token.name)
            sso_token_suggested_label, sso_token_ask_label = \
                            self._suggest_displaced_token_label(user,
                                                        sso_token,
                                                        command_args)
        return self.build_response(True, {
                            'totp_tokens': totp_tokens,
                            'max_tokens': self._max_card_tokens(user, "totp"),
                            'allowed': True,
                            'sso_token_name': sso_token_name,
                            'sso_token_type': (sso_token.token_type
                                            if sso_token else None),
                            'sso_token_label': sso_token_label,
                            'sso_token_suggested_label': sso_token_suggested_label,
                            'sso_token_ask_label': sso_token_ask_label,
                            'sso_token_managed': self._sso_token_managed(user,
                                                                sso_token),
                            'status': True})

    def _totp_enroll_state(self, user, token_name, device_name, secret, pin,
        attempts, expiry):
        """ Park a TOTP enrollment until its first code arrives.

        A new state id every time, also for a retry: the delete of the
        old one is not waited for (cluster_sync_state_delete()), and a
        re-add under the same id could be overtaken by it on the other
        nodes. """
        state_id = f"totp_enroll_states:{stuff.gen_secret(len=32)}"
        add_cluster_state(multiprocessing.totp_enroll_states,
                        state_id=state_id,
                        state_data={'user_uuid':   user.uuid,
                                    'token_name':  token_name,
                                    'device_name': device_name,
                                    'secret':      secret,
                                    'pin':         pin,
                                    'attempts':    attempts},
                        expiry=expiry)
        return state_id

    def totp_enroll_begin(self, username, sso_jwt, command_args):
        """ Start adding an authenticator app. Creates no token.

        Rolls the secret and the PIN and keeps both in
        totp_enroll_states. totp_enroll_verify() creates the token only
        once the app has shown with a first code that it got the secret
        right, so a scan that went wrong leaves nothing behind. """
        try:
            device_name = command_args['device_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        device_name = sso_helpers.sanitize_device_label(device_name)
        if not device_name:
            return self.build_response(False,
                            {'message':'Device name required.', 'status':False})
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        step_up = self._step_up_required(user, "deploy_totp_token_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        if self._totp_refused_from_peer_site("totp_enroll_begin", user,
                                            command_args):
            return self._totp_not_enabled()
        if user.site != config.site:
            # Decided here: the secret comes back through us.
            if not self._resolve_totp_allowed(user):
                self._log_totp_denied("totp_enroll_begin",
                                    "originator: user home not in "
                                    "sso_allow_totp_trusts, or "
                                    "sso_allow_totp off", user)
                return self._totp_not_enabled()
            forward_args = dict(command_args)
            forward_args['_step_up_verified'] = True
            forward_args['_totp_allowed'] = True
            # To the master, where totp_enroll_verify creates the token.
            return self.ssod_redirect_command(command="totp_enroll_begin",
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        if not self._resolve_totp_allowed(user):
            return self._totp_not_enabled()
        totp_prefix = self._token_name_prefix("totp", command_args)
        token_name = sso_helpers.sanitize_token_name(device_name,
                                                    prefix=totp_prefix)
        if not token_name:
            return self.build_response(False,
                            {'message':'Invalid device name.', 'status':False})
        if user.token(token_name):
            return self.build_response(False,
                    {'message':'A token with this name already exists.',
                    'status':False})
        refused = self._card_token_limit_reached(user, "totp", command_args)
        if refused is not None:
            return refused
        # What TotpToken._add() would roll, from the same parameters.
        secret_len = user.get_config_parameter("totp_secret_len")
        pin_len = user.get_config_parameter("totp_default_pin_len")
        secret = stuff.gen_secret(secret_len, "base32")
        pin = stuff.gen_pin(pin_len)
        # The URI TotpToken.gen_qrcode() builds, for a token that does
        # not exist yet.
        user_string = f"{user.name}/{token_name}@{config.realm}"
        oath_uri = TOTP(secret).provisioning_uri(name=user_string,
                                                issuer_name=config.my_name)
        try:
            qrcode_data = qrcode.gen_qrcode(oath_uri, fmt="svg")
            if isinstance(qrcode_data, bytes):
                qrcode_data = qrcode_data.decode('utf-8')
            qrcode_img = ("data:image/svg+xml;base64,"
                        + base64.b64encode(qrcode_data.encode()).decode())
        except Exception as e:
            log_msg = _("TOTP: QR code generation failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'ENROLL_FAILED', 'status':False})
        state_id = self._totp_enroll_state(user, token_name, device_name,
                                        secret, pin, attempts=0,
                                        expiry=TOTP_ENROLL_EXPIRY)
        log_msg = _("TOTP enrollment started for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True, {
                    'status'        : True,
                    'state_id'      : state_id,
                    'token_name'    : token_name,
                    'device_name'   : device_name,
                    'secret'        : secret,
                    'pin'           : pin,
                    'qrcode_img'    : qrcode_img,
                })

    def totp_enroll_verify(self, username, sso_jwt, command_args):
        """ Check the first code of an enrollment and create the token.

        A wrong code hands back a new state id to try again with, up to
        TOTP_ENROLL_MAX_ATTEMPTS. The token gets the secret and PIN the
        app was set up with, and the reach of the token the user signed
        in with. """
        try:
            state_id = command_args['state_id']
            otp = command_args['otp']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if self._totp_refused_from_peer_site("totp_enroll_verify", user,
                                            command_args):
            return self._totp_not_enabled()
        if user.site != config.site:
            if not self._resolve_totp_allowed(user):
                self._log_totp_denied("totp_enroll_verify",
                                    "originator: user home not in "
                                    "sso_allow_totp_trusts, or "
                                    "sso_allow_totp off", user)
                return self._totp_not_enabled()
            forward_args = dict(command_args)
            forward_args['_totp_allowed'] = True
            # _remote_ssod_call, not ssod_redirect_command: the home site
            # creates the token, we mirror it and write the memberships
            # of our own site. See fido2_add_complete().
            status, remote_resp = self._remote_ssod_call(user=user,
                                            command="totp_enroll_verify",
                                            extra_args=forward_args,
                                            mgmt=True)
            if not status or not isinstance(remote_resp, dict):
                return self.build_response(False, remote_resp)
            if not remote_resp.get('verified'):
                # A wrong code: nothing was created, pass the retry on.
                return self.build_response(True, remote_resp)
            self._mirror_remote_token(user, remote_resp, flow="TOTP")
            return self.build_response(True, {
                        'status'        : True,
                        'verified'      : True,
                        'name'          : remote_resp.get('name'),
                        'device_name'   : remote_resp.get('device_name'),
                        'sync_pending'  : True,
                    })
        if not self._resolve_totp_allowed(user):
            return self._totp_not_enabled()
        expired = self.build_response(False,
                {'message':'Enrollment expired. Please start again.',
                'status':False})
        if not isinstance(state_id, str) \
        or not state_id.startswith("totp_enroll_states:"):
            return expired
        # Single use, on every node -- see fido2_add_complete().
        try:
            state_data = multiprocessing.totp_enroll_states.delete(state_id)
        except KeyError:
            return expired
        cluster_sync_state_delete(state_id)
        if state_data.get('user_uuid') != user.uuid:
            log_msg = _("TOTP enroll state of another user presented by '{user_name}'.", log=True)[1]
            log_msg = log_msg.format(user_name=user.name)
            self.logger.warning(log_msg)
            return expired
        token_name = state_data['token_name']
        device_name = state_data.get('device_name') or token_name
        secret = state_data['secret']
        pin = state_data['pin']
        otp = str(otp).strip()
        try:
            verified = otp.isdigit() and TOTP(secret).verify(otp)
        except Exception:
            verified = False
        if not verified:
            attempts = state_data.get('attempts', 0) + 1
            remaining = state_data.get('state_expires', 0) - time.time()
            if attempts >= TOTP_ENROLL_MAX_ATTEMPTS or remaining < 1:
                return self.build_response(False,
                        {'message':'Too many invalid codes. Please start again.',
                        'status':False})
            new_state_id = self._totp_enroll_state(user, token_name,
                                                device_name, secret, pin,
                                                attempts=attempts,
                                                expiry=int(remaining))
            return self.build_response(True, {
                        'status'    : True,
                        'verified'  : False,
                        'state_id'  : new_state_id,
                        'message'   : 'Invalid code. Please try again.',
                    })
        if user.token(token_name):
            return self.build_response(False,
                    {'message':'A token with this name already exists.',
                    'status':False})
        refused = self._card_token_limit_reached(user, "totp", command_args)
        if refused is not None:
            return refused
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            user.add_token(token_name=token_name,
                            token_type="totp",
                            mode="mode1",
                            no_token_infos=True,
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("TOTP: failed to add token for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':f'Failed to create token: {e}', 'status':False})
        token = user.token(token_name)
        if token is None:
            return self.build_response(False,
                    {'message':'Failed to create token.', 'status':False})
        # The secret and PIN the app was set up with, not the ones
        # add_token() just rolled.
        token.secret = secret
        token.pin = pin
        token.pin_len = len(pin)
        token.change_device_name(device_name,
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
        token._write(callback=callback)
        # The code that proved the app works is not good for a login.
        token.add_used_otp(otp=f"{pin}{otp}")
        token.add_used_otp(otp=otp)
        self._mirror_login_token_memberships(user, token,
                                            config.auth_token,
                                            callback,
                                            flow="TOTP")
        emit_audit("Crypto", "totp_token_enrolled",
                        user=user.name,
                        token=token.rel_path,
                        device_name=token.device_name)
        log_msg = _("TOTP token '{token}' enrolled for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token.rel_path, user_name=user.name)
        self.logger.info(log_msg)
        response = {
                    'status'        : True,
                    'verified'      : True,
                    'name'          : token.name,
                    'device_name'   : token.device_name,
                }
        response = self._token_sync_config(token, response,
                                        config.auth_token)
        return self.build_response(True, response)

    def del_totp_token(self, username, sso_jwt, command_args):
        """ Delete one of the user's own authenticator apps.

        Not the SSO token and not the one of the current session, for
        the reasons del_tiqr_token() gives. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command="del_totp_token",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        if not self._resolve_totp_allowed(user):
            return self._totp_not_enabled()
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_totp_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        if token_name == sso_token_name:
            return self.build_response(False,
                    {'message':'Cannot delete the default token. Make another '
                            'token the default token first.',
                    'status':False})
        if _is_current_token(token):
            return self.build_response(False,
                    {'message':'Cannot delete the authenticator app you are '
                            'currently signed in with. Sign in with another '
                            'factor first.',
                    'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            add_to_trash = self._add_to_trash(user, "add_totp_token_to_trash")
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("TOTP: failed to delete token '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        emit_audit("Crypto", "totp_token_deleted",
                        user=user.name,
                        token=f"{user.name}/{token_name}")
        return self.build_response(True, {'status':True})

    def _set_totp_token_enabled(self, username, sso_jwt, command_args,
        enable):
        """ Shared body of enable_totp_token / disable_totp_token. """
        command = "enable_totp_token" if enable else "disable_totp_token"
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if self._totp_refused_from_peer_site(command, user, command_args):
            return self._totp_not_enabled()
        if user.site != config.site:
            if not self._resolve_totp_allowed(user):
                self._log_totp_denied(command,
                                    "originator: user home not in "
                                    "sso_allow_totp_trusts, or "
                                    "sso_allow_totp off", user)
                return self._totp_not_enabled()
            forward_args = dict(command_args)
            forward_args['_totp_allowed'] = True
            return self.ssod_redirect_command(command=command,
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        if not self._resolve_totp_allowed(user):
            return self._totp_not_enabled()
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_totp_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        if not enable:
            if token_name == sso_token_name:
                return self.build_response(False,
                        {'message':'Cannot disable the default token.',
                        'status':False})
            if _is_current_token(token):
                return self.build_response(False,
                        {'message':'Cannot disable the authenticator app you '
                                'are currently signed in with.',
                        'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            if enable:
                token.enable(force=True, verify_acls=False,
                            run_policies=True, callback=callback)
            else:
                token.disable(force=True, verify_acls=False,
                            run_policies=True, callback=callback)
            token._write(callback=callback)
        except Exception as e:
            log_msg = _("TOTP: failed to change token '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        return self.build_response(True, {'status':True,
                                        'enabled':bool(enable)})

    def enable_totp_token(self, username, sso_jwt, command_args):
        """ Enable one of the user's own TOTP tokens. """
        return self._set_totp_token_enabled(username, sso_jwt,
                                            command_args, True)

    def disable_totp_token(self, username, sso_jwt, command_args):
        """ Disable one of the user's own TOTP tokens. """
        return self._set_totp_token_enabled(username, sso_jwt,
                                            command_args, False)

    def change_totp_pin(self, username, sso_jwt, command_args):
        """ Set a new PIN on one of the user's own TOTP tokens.

        No current PIN asked: the step-up (deploy_totp_token_reauth) is
        the proof, and it lets a user who forgot the PIN set a new one.
        The token's secret stays, so the app keeps working. """
        try:
            token_name = command_args['token_name']
            new_pin = command_args['new_pin']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        step_up = self._step_up_required(user, "deploy_totp_token_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        if self._totp_refused_from_peer_site("change_totp_pin", user,
                                            command_args):
            return self._totp_not_enabled()
        if user.site != config.site:
            # Decided here: the new PIN comes through us.
            if not self._resolve_totp_allowed(user):
                self._log_totp_denied("change_totp_pin",
                                    "originator: user home not in "
                                    "sso_allow_totp_trusts, or "
                                    "sso_allow_totp/sso_allow_totp_mgmt off",
                                    user)
                return self._totp_not_enabled()
            forward_args = dict(command_args)
            forward_args['_step_up_verified'] = True
            forward_args['_totp_allowed'] = True
            return self.ssod_redirect_command(command="change_totp_pin",
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        if not self._resolve_totp_allowed(user):
            return self._totp_not_enabled()
        sso_token_name = self._sso_token_name(command_args)
        token = self._get_user_totp_token(user, token_name, sso_token_name,
                                        command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        # Token.change_pin() asks interactively for an empty PIN, and
        # accepts anything else unless a PIN policy says otherwise.
        new_pin = str(new_pin)
        if not new_pin.isdigit():
            return self.build_response(False,
                    {'message':'PIN must be numerical.', 'status':False})
        # In mode2 the PIN is part of the secret: a new one needs the
        # app set up again, which is not what this form is for.
        if token.mode != "mode1":
            return self.build_response(False,
                    {'message':'Token does not support PIN change.',
                    'status':False})
        client_ip = command_args.get('client_ip')
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            # check_pin() inside applies the PIN policies.
            token.change_pin(pin=new_pin,
                            run_policies=False,
                            verify_acls=False,
                            callback=callback)
            token._write(callback=callback)
        except Exception as e:
            log_msg = _("TOTP: PIN change failed for token '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token.rel_path, e=e)
            self.logger.warning(log_msg)
            emit_audit("Auth", "pin_change_failed",
                            level='warning',
                            user=user.name,
                            token=token.rel_path,
                            reason='policy_or_write_error',
                            error=str(e),
                            ip=client_ip)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        emit_audit("Auth", "pin_changed",
                        user=user.name,
                        token=token.rel_path,
                        ip=client_ip)
        return self.build_response(True, {'status':True})

    def _deploy_device_name(self, user, token_type, command_args):
        """ The label a token gets at deploy time, checked up front.

        Not decoration: it is what the rename dialog offers when the
        SSO role is later handed to another token, and the name that
        one gets. So a label that does not survive sanitizing, or whose
        name is already taken, has to be said now -- at promotion time
        the user is somewhere else entirely and would have no idea what
        the dialog is complaining about.

        Returns ``(device_name, error_response)``; exactly one of the
        two is set. """
        device_name = command_args.get('device_name')
        device_name = sso_helpers.sanitize_device_label(device_name)
        # The same prefix _displaced_token_name() will use, so what is
        # checked here is the name that will actually be taken.
        promote_name = sso_helpers.sanitize_token_name(device_name,
                        prefix=self._token_name_prefix(token_type, command_args))
        if not promote_name:
            msg = _("Invalid device name.")
            if not device_name:
                msg = _("Device name required.")
            return None, self.build_response(False,
                            {'message': msg, 'status': False})
        if user.token(promote_name):
            msg = _("A token with this name already exists.")
            return None, self.build_response(False,
                            {'message': msg, 'status': False})
        return device_name, None

    def _token_label(self, token):
        """ What its owner calls this token, or None.

        device_name is where every flow the portal offers puts the
        label now. The description is read after it because that is
        where the ones created before device_name existed have theirs,
        and nobody is going to migrate a user's security keys.

        Not the token name: that is derived from the label, carries the
        type and site prefix, and is the one thing the promote dialog
        must not offer back. Callers that need something to display
        fall back to it themselves. """
        return token.device_name or token.description or None

    def _max_card_tokens(self, user, token_type):
        """ sso_max_<type>_token for this user, or None for no limit. """
        max_tokens = user.get_config_parameter(f"sso_max_{token_type}_token")
        if max_tokens is None:
            return None
        return int(max_tokens)

    def _count_card_tokens(self, user, token_type, command_args):
        """ How many tokens of this type the settings card lists.

        The same rule the listings follow: the SSO token and what
        carries this portal's prefix, without the residue of flows that
        never finished (no credential, no tiqr secret). """
        sso_token_name = self._sso_token_name(command_args)
        prefix = self._token_name_prefix(token_type, command_args)
        count = 0
        for token_uuid in user.tokens:
            token = backend.get_object(object_type="token", uuid=token_uuid)
            if token is None or token.token_type != token_type:
                continue
            if token.name != sso_token_name \
            and not token.name.startswith(prefix):
                continue
            if token_type in ("fido2", "passkey") \
            and not token.credential_data:
                continue
            if token_type == "tiqr" and not token.has_auth_data():
                continue
            count += 1
        return count

    def _card_token_limit_reached(self, user, token_type, command_args):
        """ The refusal when the user already holds sso_max_<type>_token
        tokens of this type in the card, or None.

        Asked where the token is created -- the user's home site -- at
        the start of an add, so the user hears it before scanning or
        touching anything, and again when it completes, because two adds
        may have been started side by side. """
        max_tokens = self._max_card_tokens(user, token_type)
        if max_tokens is None:
            return None
        if self._count_card_tokens(user, token_type, command_args) < max_tokens:
            return None
        msg = _("You already have the maximum number of tokens of this type ({max_tokens}).")
        msg = msg.format(max_tokens=max_tokens)
        return self.build_response(False, {'message': msg, 'status': False})

    def _add_to_trash(self, user, parameter):
        """ Does a token the user deletes here go to the trash?

        The default of a config parameter lives in its registration,
        and that default is written into a site object only when the
        site is created -- a site older than the parameter has nothing
        to say and the cascade comes back None. None is falsy, and
        "nobody ever configured this" must not read as "delete it
        permanently", so it means the registered default: yes. """
        add_to_trash = user.get_config_parameter(parameter)
        if add_to_trash is None:
            return True
        return bool(add_to_trash)

    def _token_rename_blocked(self, token):
        """ Why this token cannot be renamed, or None.

        Only the reason Token.rename() refuses on its own. Checking it
        up front lets promote_token find out before it has renamed
        anything -- afterwards is too late, see there. """
        if not token.is_default_token():
            return None
        if token.get_config_parameter('allow_default_token_rename'):
            return None
        msg = _("Token '{name}' is your default token and renaming it is not allowed.")
        return msg.format(name=token.name)

    def _displaced_token_name(self, token, wanted_name, command_args):
        """ The name the token losing the SSO role should carry.

        ``wanted_name`` is what the user typed, and it is what we use
        when there is one -- sanitized, because it arrives from a
        browser and goes into an object name. Falling back: the device
        name for a phone, the description for a passkey, which is where
        each flow puts the label the user gave the thing.

        The prefix carries the token's own type, so the name says what
        the entry is -- a displaced security key must not end up called
        'tiqr-something' -- and this portal's realm and site, so it
        lands in the card it came from. """
        label = wanted_name
        if not label:
            label = self._token_label(token)
        if not label:
            return None
        prefix = self._token_name_prefix(token.token_type, command_args)
        return sso_helpers.sanitize_token_name(label, prefix=prefix)

    def _suggest_displaced_token_label(self, user, token, command_args):
        """ The label the token losing the SSO role should keep.

        A label, not a name. The input asks what the add dialogs ask --
        what do you call this thing -- and _displaced_token_name() puts
        the type prefix on the answer. Offering the finished name here
        would send the prefix back through sanitize_token_name(), and
        somebody who simply presses OK ends up with
        'fido2-fido2a3f9'.

        The label the token already carries, because that is what its
        owner calls it. Its current name is no help: that is the SSO
        name it is losing. Failing a label, and whenever the name it
        would turn into is taken, a random one -- still free, still of
        the right shape, and short enough that replacing it is no
        effort.

        Returns ``(label, ask)``. ``ask`` is True when the label is one
        we made up, and then the user has to see it before the rename
        happens -- it is the name they will look for in their own list
        afterwards. When the token brought its own label there is
        nothing to ask about, so the promotion runs without a dialog. """
        label = self._token_label(token)
        if label and self._displaced_name_free(user, token, label,
                                            command_args):
            return label, False
        for _attempt in range(8):
            label = stuff.gen_secret(len=2, encoding="hex")
            if self._displaced_name_free(user, token, label, command_args):
                return label, True
        return None, True

    def _displaced_name_free(self, user, token, label, command_args):
        """ Would this label give the displaced token a usable name? """
        token_name = self._displaced_token_name(token, label, command_args)
        if not token_name:
            return False
        return user.token(token_name) is None

    def promote_token(self, username, sso_jwt, command_args):
        """ Make another of the user's tokens the SSO token.

        Works for any type the portal lets a user manage themselves
        (PROMOTABLE_TOKEN_TYPES), so the role can move from a phone to a
        security key and back.

        The role is decided by the name alone -- default_sso_token_name
        -- so this is two renames and nothing else. Nothing is deleted:
        the token that held the role keeps working under a name of its
        own, which the caller should have shown the user beforehand.

        Order matters: the SSO name has to be free before the new token
        can take it. Which is also why everything that can refuse is
        asked first. Renaming the old one and then finding out that the
        new one cannot take the name would leave the user with no SSO
        token at all -- and that is the token their recovery flow looks
        for. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        old_token_name = command_args.get('old_token_name')
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command="promote_token",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)

        sso_token_name = self._sso_token_name(command_args)
        if token_name == sso_token_name:
            return self.build_response(False,
                    {'message':'This is already the default token.',
                    'status':False})
        token = self._get_user_managed_token(user, token_name, command_args)
        if token is None:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})

        callback = self.get_callback()
        # Without this every refusal inside rename() -- a policy, a name
        # that turns out to be taken, an expired lock -- goes through
        # callback.error(), which only *returns* unless it is set. The
        # renames then quietly do nothing while this method carries on
        # to log a promotion that never happened.
        callback.raise_exception = True
        old_token = user.token(sso_token_name)

        # Everything that can refuse, before anything is renamed.
        if not self._sso_token_managed(user, old_token):
            return self.build_response(False,
                    {'message':'Your default token is managed by your '
                            'administrator and cannot be replaced here.',
                    'status':False})
        blocked = self._token_rename_blocked(token)
        if blocked is not None:
            return self.build_response(False,
                    {'message': blocked, 'status':False})
        if old_token is not None:
            old_token_name = self._displaced_token_name(old_token,
                                                        old_token_name,
                                                        command_args)
            if not old_token_name:
                return self.build_response(False,
                        {'message':'A name for the current default token is required.',
                        'status':False})
            if user.token(old_token_name):
                return self.build_response(False,
                        {'message':'A token with this name already exists.',
                        'status':False})
            blocked = self._token_rename_blocked(old_token)
            if blocked is not None:
                return self.build_response(False,
                        {'message': blocked, 'status':False})

        if old_token is not None:
            try:
                old_token.rename(new_name=old_token_name,
                                force=True,
                                verify_acls=False,
                                callback=callback)
            except Exception as e:
                log_msg = _("Failed to rename the SSO token: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                return self.build_response(False,
                                {'message':str(e), 'status':False})

        try:
            token.rename(new_name=sso_token_name,
                        force=True,
                        verify_acls=False,
                        callback=callback)
        except Exception as e:
            log_msg = _("Failed to promote token '{token}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':str(e), 'status':False})
        emit_audit("Crypto", "token_promoted",
                        user=user.name,
                        token=sso_token_name,
                        token_type=token.token_type,
                        previous=old_token_name)
        log_msg = _("Token '{token}' ({token_type}) is now the SSO token of '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token_name,
                                token_type=token.token_type,
                                user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True, {'status':True,
                                        'name':sso_token_name,
                                        'old_name':old_token_name})

    def del_passkey(self, username, sso_jwt, command_args):
        """ Delete one of the user's own passkey tokens. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command="del_passkey",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        token = self._get_user_passkey(user, token_name, command_args)
        if not token or token.owner_uuid != user.uuid:
            return self.build_response(False, {'message':'UNKNOWN_TOKEN', 'status':False})
        # Refuse to delete the token of the current session. The JWT
        # would still carry its UUID and the next request's
        # verify_sso_jwt would fail to load config.auth_token -- the
        # user would be locked out instead of getting a clean re-auth
        # prompt. Force them to sign in with another factor first.
        if _is_current_token(token):
            return self.build_response(False, {
                'message': 'Cannot delete the passkey you are currently '
                           'signed in with. Sign in with another factor first.',
                'status': False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            add_to_trash = self._add_to_trash(user, "add_passkey_to_trash")
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to delete passkey '{token}' for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'Failed to delete passkey.', 'status':False})
        log_msg = _("Passkey '{token}' deleted for user '{user_name}'.", log=True)[1]
        log_msg = log_msg.format(token=token_name, user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True, {'status': True})

    def _site_trusts_site_for_admin_access(self, site):
        """ Does this site (config.site) list ``site`` under
        ``admin_access_trusts``? Used on the user's home site to
        decide whether to accept an admin-access modification from a
        peer ssod (originator's SSO portal site). """
        local_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
        if local_site is None:
            return False
        try:
            trusts = local_site.get_config_parameter("admin_access_trusts")
        except Exception:
            trusts = None
        if not trusts:
            return False
        return site in trusts

    def get_admin_access_state(self, username, sso_jwt, command_args):
        """ Tell the settings page whether admin access is applicable
        for this user and what its current state is. Delegates the
        read to ``user.admin_access_available`` /
        ``user.admin_access_enabled`` (both anchored on the user's
        home-site config cascade). Foreign users get redirected to
        the home site so the authoritative read runs there;
        cluster-peer-forwarded reads require reciprocal trust
        (``admin_access_trusts``). """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if self.from_peer_node:
            if not self._site_trusts_site_for_admin_access(self.peer.site):
                return self.build_response(False, {
                    'message': 'Admin access not available: peer site is not '
                               'listed in admin_access_trusts.',
                    'status': False})
        # Foreign user: redirect to the home site so the config
        # cascade + allow_temp_passwords read run authoritatively
        # there. Not reachable in the cluster-peer branch above --
        # peer forwarding always targets the home site, so by then
        # user.site == config.site.
        if user.site != config.site:
            return self.ssod_redirect_command(command="get_admin_access_state",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        return self.build_response(True, {
                'available': user.admin_access_available(),
                'enabled':   user.admin_access_enabled(),
                'status':    True})

    def set_admin_access_state(self, username, sso_jwt, command_args):
        """ Self-service: flip admin access on the user via
        ``user.enable_admin_access`` / ``user.disable_admin_access``.
        Role resolution + mutations + audit emission are done by the
        User object; this method is the protocol wrapper -- JWT
        verify, cross-site redirect for foreign users, reciprocal
        trust check on the home site for cluster-peer-forwarded
        writes. """
        try:
            enabled = bool(command_args['enabled'])
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        # Cluster-peer-forwarded write: the originator side already
        # decided the operation was allowed under its own trust list;
        # here on the home side we require reciprocal trust so a peer
        # can't drive admin-access changes on our users without an
        # explicit admin_access_trusts entry.
        if self.from_peer_node:
            if not self._site_trusts_site_for_admin_access(self.peer.site):
                return self.build_response(False, {
                    'message': 'Admin access not available: peer site is not '
                               'listed in admin_access_trusts.',
                    'status': False})
        # Foreign users: writes are authoritative on the home site.
        # (Not reachable in the cluster-peer branch above -- peer
        # forwarding always targets the home site.)
        if user.site != config.site:
            return self.ssod_redirect_command(command="set_admin_access_state",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            if enabled:
                user.enable_admin_access(force=True,
                                         verify_acls=False,
                                         run_policies=False,
                                         callback=callback)
            else:
                user.disable_admin_access(force=True,
                                          verify_acls=False,
                                          run_policies=False,
                                          callback=callback)
        except Exception as e:
            log_msg = _("Admin-access toggle failed for user '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message': str(e), 'status': False})
        user._write(callback=callback)
        return self.build_response(True, {'enabled': enabled, 'status': True})

    def _step_up_max_age(self, user):
        """ How long a reauth stays fresh for this user, in seconds.

        sso_reauth_timeout, resolved over the user's cascade. None --
        a site older than the parameter -- means the registered
        default, for the same reason as in _add_to_trash(). """
        max_age = user.get_config_parameter("sso_reauth_timeout")
        if max_age is None:
            return STEP_UP_MAX_AGE
        return int(max_age)

    def _require_fresh_step_up(self, user, session_uuid, max_age=None):
        """ Verify that the SSO session ``session_uuid`` was step-up-
        reauth'ed within the last ``max_age`` seconds. Runs on the
        originator site (the SSO session lives there, never crosses
        to the user's home site -- ``ssod_redirect_command`` strips
        ``session_uuid``). Used to gate sensitive self-service actions
        (recovery mail change, ...) behind a fresh proof-of-possession
        via /reauth, so a forgotten-unlocked browser cannot silently
        pivot into an account-takeover setting.

        Raises OTPmeException("STEP_UP_REQUIRED") on any failure --
        the caller returns that verbatim so the web layer can drive
        the user through /reauth?next=... and retry.

        ``max_age`` defaults to the user's sso_reauth_timeout. """
        if max_age is None:
            max_age = self._step_up_max_age(user)
        # Every refusal says why. They all look the same from the
        # browser -- another trip through /reauth -- and a loop of those
        # is otherwise impossible to tell apart from a reauth that
        # simply did not happen.
        def refuse(reason):
            log_msg = _("Step-up missing for '{user}' (session {session}): {reason}", log=True)[1]
            log_msg = log_msg.format(user=user.name,
                                    session=session_uuid,
                                    reason=reason)
            self.logger.debug(log_msg)
            raise OTPmeException("STEP_UP_REQUIRED")
        if not session_uuid:
            refuse("no session uuid in the request")
        session = backend.get_object(uuid=session_uuid)
        if not session:
            refuse("session not found on this site")
        if session.user_uuid != user.uuid:
            refuse(f"session belongs to user {session.user_uuid}, not {user.uuid}")
        if not session.reauth_time:
            refuse("session has no reauth_time")
        age = time.time() - session.reauth_time
        if age > max_age:
            refuse(f"reauth is {int(age)}s old, allowed {max_age}s")

    def _step_up_required(self, user, parameter, command_args):
        """ Make the user prove themselves again, if this flow says so.

        Returns a STEP_UP_REQUIRED response to hand back, or None when
        the way is clear. Every caller of it is about to give out a new
        credential -- a token, a phone, a key -- and that credential
        outlives the session it was made in, which is why an unlocked
        browser alone must not be enough.

        Unset means yes: the default lives in the registration and is
        written into a site object only when the site is created, so an
        older site answers None, and None must not read as "no gate"
        (same reason as _add_to_trash()).

        Checked on the portal, because that is where the SSO session
        lives -- ssod_redirect_command() does not carry session_uuid
        across sites. A foreign user's home site is told the answer
        with the _step_up_verified marker, which is only worth
        anything from a node. """
        if not self._step_up_missing(user, parameter, command_args):
            return None
        log_msg = _("Step-up required for '{user}': {parameter}", log=True)[1]
        log_msg = log_msg.format(user=user.name, parameter=parameter)
        self.logger.debug(log_msg)
        return self.build_response(False, {
                'message': 'STEP_UP_REQUIRED',
                'status':  False,
            })

    def get_step_up_state(self, username, sso_jwt, command_args):
        """ Which add flows need a fresh reauth right now.

        Asked by the settings page when an add button is pressed, so it
        can ask for the reauth before the user types a name instead of
        after they pressed the button that registers. A
        security key or a passkey is only registered in answer to a
        real click, and the trip to /reauth reloads the page -- asked at
        the button, it would cost the user a second click on the same
        button, which nobody expects even when the page says so.

        All four add flows. For a security key or a passkey there is no
        other way; for a phone and a device token it is simply the
        nicer order -- prove yourself first, then type the name.

        Answered here and never forwarded: the SSO session lives on
        this site, and the user's reauth parameters are synced to us
        with the user, unit and site objects. Nothing here is a
        permission -- the add commands still check for themselves. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        # With STEP_UP_ADD_MARGIN: the form this opens still has a name
        # to be typed and a key to be touched, so a reauth that is about
        # to run out counts as gone already.
        missing = {
                'fido2'     : self._step_up_missing(user,
                                            "deploy_fido2_token_reauth",
                                            command_args,
                                            margin=STEP_UP_ADD_MARGIN),
                'passkey'   : self._step_up_missing(user,
                                            "deploy_passkey_reauth",
                                            command_args,
                                            margin=STEP_UP_ADD_MARGIN),
                'tiqr'      : self._step_up_missing(user,
                                            "deploy_tiqr_token_reauth",
                                            command_args,
                                            margin=STEP_UP_ADD_MARGIN),
                'totp'      : self._step_up_missing(user,
                                            "deploy_totp_token_reauth",
                                            command_args,
                                            margin=STEP_UP_ADD_MARGIN),
                'device'    :self._step_up_missing(user,
                                            "deploy_device_token_reauth",
                                            command_args,
                                            margin=STEP_UP_ADD_MARGIN),
            }
        return self.build_response(True, {
                'step_up_missing'   : missing,
                'step_up_max_age'   : self._step_up_max_age(user),
                'status'            : True,
            })

    def _step_up_missing(self, user, parameter, command_args, margin=0):
        """ The question _step_up_required() answers, as a plain yes.

        For the callers that only need to know in advance -- the deploy
        page asks before it shows the choice of token types, so that
        the user proves themselves first and then picks, instead of
        picking, being sent away, and landing on the choice again.

        ``margin`` seconds of the window have to be left for it to
        count, see STEP_UP_ADD_MARGIN. Never more than half of it: a
        margin that ate the whole window would call every reauth stale
        the moment it happened, and send the user round in a circle. """
        if self.from_peer_node and command_args.get('_step_up_verified'):
            return False
        required = user.get_config_parameter(parameter)
        if required is None:
            required = True
        if not required:
            return False
        max_age = self._step_up_max_age(user)
        max_age = max(max_age - margin, max_age // 2)
        try:
            self._require_fresh_step_up(user,
                                        command_args.get('session_uuid'),
                                        max_age=max_age)
        except OTPmeException:
            return True
        return False

    def get_recovery_mail(self, username, sso_jwt, command_args):
        """ Return the user's recovery e-mail address (LDIF attribute
        ``otpmeRecoveryMail`` on the user object), plus the step-up
        max-age so the UI knows how long a fresh /reauth stays valid.
        Foreign users get redirected to their home site so the read
        is authoritative on the site that owns the write, matching
        the ``list_device_tokens`` / ``get_admin_access_state``
        pattern. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.ssod_redirect_command(command="get_recovery_mail",
                                            user=user,
                                            command_args=command_args)
        values = user.get_attribute("otpmeRecoveryMail") or []
        recovery_mail = values[0] if values else None
        return self.build_response(True, {
                'recovery_mail':   recovery_mail,
                'step_up_max_age': self._step_up_max_age(user),
                'status':          True,
            })

    def set_recovery_mail(self, username, sso_jwt, command_args):
        """ Self-service write of the user's recovery e-mail address.
        Gated behind a fresh step-up reauth on the originator site
        (``session.reauth_time`` within ``sso_reauth_timeout``), then
        forwarded to the user's home site for the actual attribute
        write. Empty/None ``recovery_mail`` clears the attribute.

        Cross-site: step-up is verified on the originator (the SSO
        session lives there and never crosses via
        ``ssod_redirect_command``). Home accepts the peer-forwarded
        write when the ``_step_up_verified`` marker is set and the
        peer is a cluster node -- the same infrastructure trust
        already implicit in every cluster op. """
        raw_value = command_args.get('recovery_mail')
        if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
            new_value = None
        elif isinstance(raw_value, str):
            new_value = raw_value.strip()
        else:
            new_value = raw_value
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})
        peer_verified = command_args.get('_step_up_verified')
        skip_step_up_check = bool(self.from_peer_node and peer_verified)
        if not skip_step_up_check:
            # Originator (or direct socket): the SSO session lives here,
            # so the reauth freshness is checked here. On failure the
            # web layer drives the user through /reauth and retries.
            try:
                self._require_fresh_step_up(user,
                                            command_args.get('session_uuid'))
            except OTPmeException:
                return self.build_response(False, {
                        'message': 'STEP_UP_REQUIRED',
                        'status':  False,
                    })
        if new_value is not None and not stuff.is_email(new_value):
            return self.build_response(False, {
                    'message': 'INVALID_RECOVERY_MAIL',
                    'status':  False,
                })
        if user.site != config.site:
            # Originator -> forward to home. Step-up already verified
            # above; tell home to accept the write without re-checking
            # (session_uuid does not cross sites anyway).
            forward_args = dict(command_args)
            forward_args['_step_up_verified'] = True
            return self.ssod_redirect_command(command="set_recovery_mail",
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            existing = user.get_attribute("otpmeRecoveryMail") or []
            if existing:
                user.del_attribute("otpmeRecoveryMail",
                                    force=True,
                                    verify_acls=False,
                                    ignore_missing=True,
                                    callback=callback)
            if new_value is not None:
                user.add_attribute("otpmeRecoveryMail",
                                    new_value,
                                    force=True,
                                    verify_acls=False,
                                    callback=callback)
        except Exception as e:
            log_msg = _("Recovery-mail change failed for user '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message': str(e), 'status': False})
        user._write(callback=callback)
        return self.build_response(True, {
                'recovery_mail': new_value,
                'status':        True,
            })

    # ---- SSO-token recovery (unauth "forgot my token" flow) ------------
    #
    # Design notes:
    #   * All state (recovery_token hash + created timestamp) lives on
    #     the user object -- cluster-replicated, survives node restart,
    #     any node can validate.
    #   * The raw token never touches persistent storage: only the
    #     SHA256 hash is written. The raw form lives briefly in the
    #     mail body and the user's browser URL.
    #   * Every command runs on the user's home site. Foreign users
    #     trigger a cluster-peer ssod redirect so token generation and
    #     mail send happen on home (never on the calling partner
    #     site's operator-triggered code path).
    #   * The recovery-mail link URL is constructed on home from the
    #     calling peer's site FQDN -- never from an A-supplied
    #     parameter. That closes the "A operator with node access can
    #     inject an attacker-controlled link" vector: the peer is a
    #     cluster peer whose identity we already trust structurally.
    #   * Every observable code path (unknown user, no default SSO
    #     token, disallowed type, missing recovery mail, missing
    #     mail_from, SMTP failure) returns the same generic-OK
    #     response so an attacker cannot enumerate users or infer
    #     their recovery state through response-shape differences.
    #   * Prerequisite checks are ordered admin-config → user-config →
    #     heavy work (token gen + user write + mail send). Missing
    #     admin config means recovery is disabled for the whole site,
    #     so short-circuit there before touching per-user state.

    def _recovery_generic_ok(self):
        """ Enum-safe generic response used for every path in
        request_sso_token_recovery. """
        return self.build_response(True, {'status': True, 'message': 'OK'})

    def _recovery_invalid(self):
        """ Uniform response for every failed recovery-token validation
        (unknown user, wrong token, expired token, disallowed type).
        Same shape regardless of *why* it failed. """
        return self.build_response(False, {'valid': False, 'status': False})

    def _recovery_link_host(self):
        """ FQDN for the recovery-mail link URL. Derived from the peer
        site (cluster-peer-forwarded case) or the local site
        (same-site request). Never from a request parameter -- see
        the design notes above. Emits a DEBUG line naming which site
        was checked so a missing sso_fqdn is diagnosable without
        leaking to the client.

        ``self.peer.site`` holds a site NAME (matches the convention
        used by admin_access_trusts / sso_allow_passkeys_trusts etc.
        elsewhere in this file), so we look it up by name. Local-site
        fallback uses ``config.site`` (also a name). """
        site = None
        if (self.peer is not None
                and self.peer.type == "node"
                and self.peer.site
                and self.peer.site != config.site):
            result = backend.search(object_type="site",
                                    attribute="name",
                                    value=self.peer.site,
                                    realm=config.realm,
                                    return_type="instance")
            if result:
                site = result[0]
        if site is None:
            site = backend.get_object(object_type="site",
                                     uuid=config.site_uuid)
        if site is None:
            log_msg = _("SSO-token recovery: link-host site lookup failed (peer={p}, local uuid={u}).", log=True)[1]
            log_msg = log_msg.format(p=getattr(self.peer, 'site', None),
                                     u=config.site_uuid)
            self.logger.debug(log_msg)
            return None
        if not site.sso_fqdn:
            log_msg = _("SSO-token recovery: site '{s}' has no sso_fqdn set (fix with 'otpme-site sso_fqdn {s} <fqdn>').", log=True)[1]
            log_msg = log_msg.format(s=site.name)
            self.logger.debug(log_msg)
            return None
        return site.sso_fqdn

    def _recovery_lookup_target_token(self, user, command_args):
        """ Return the user's configured SSO token instance (named by
        the portal's default_sso_token_name), or None if not present.

        The portal's name, not the user's site's: a recovery started at
        site B has to restore B's token. """
        sso_token_name = self._sso_token_name(command_args)
        if not sso_token_name:
            return None
        return user.token(sso_token_name)

    def _recovery_type_allowed(self, user, sso_token):
        """ True iff:
              * the SSO-token type is one the recovery deploy flow
                actually implements (SSO_RECOVERY_DEPLOY_TYPES), and
              * the user's site/unit/user cascade lists that type in
                ``allow_sso_token_recovery``.
        The admin's cascade is authoritative for policy; the
        implementation gate only refuses types the deploy handlers
        don't have a branch for. Default cascade (empty list)
        disables recovery entirely. """
        if sso_token is None:
            return False
        if sso_token.token_type not in SSO_RECOVERY_DEPLOY_TYPES:
            return False
        allowed = user.get_config_parameter("allow_sso_token_recovery") or []
        return sso_token.token_type in allowed

    def _recovery_hash(self, raw_token):
        """ Persistent storage form of a raw recovery token. """
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def _recovery_verify_stored(self, user, raw_token):
        """ Constant-time compare of the presented raw token against
        the stored SHA256 hash + TTL check. Returns True on match+fresh
        only. """
        if not user.recovery_token or not user.recovery_token_created:
            return False
        ttl = user.get_config_parameter("sso_recovery_link_ttl", apply_getter=False) or 900
        if time.time() - user.recovery_token_created > ttl:
            return False
        computed = self._recovery_hash(raw_token)
        return hmac.compare_digest(computed, user.recovery_token)

    def request_sso_token_recovery(self, username, sso_jwt, command_args):
        """ Unauth: emit an SSO-token recovery mail for the named user.
        Runs on user home (cross-site forward for foreign users). See
        the design notes above.

        Every early-return path stays enum-safe (generic OK to the
        client) but logs an admin-only DEBUG line naming the reason
        so a broken deployment can be diagnosed without leaking the
        state to attackers.
        """
        def _skip(reason):
            log_msg = _("SSO-token recovery skipped: {reason}", log=True)[1]
            log_msg = log_msg.format(reason=reason)
            self.logger.debug(log_msg)
            return self._recovery_generic_ok()

        if not isinstance(username, str) or not username:
            return _skip("empty username")
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm)
        if user is None:
            return _skip(f"unknown user '{username}'")
        # Foreign user: forward to home so token generation + mail send
        # happen where the user's object and config actually live.
        if user.site != config.site:
            self.logger.debug(_("SSO-token recovery: forwarding to home site for user '{u}'.", log=True)[1].format(u=user.name))
            return self.ssod_redirect_command(command="request_sso_token_recovery",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        if not user.get_config_parameter("allow_sso_account_recovery"):
            return _skip(f"allow_sso_account_recovery=False for user '{user.name}'")
        # ---- Admin-config prerequisites (site level) --------------------
        # Missing anything in this block means the site's admin has not
        # wired up recovery at all -- short-circuit here so we do not
        # generate + persist a token that no one can act on.
        mail_from = user.get_config_parameter("sso_recovery_mail_from")
        if not mail_from:
            return _skip(f"sso_recovery_mail_from not configured for '{user.name}'")
        smtp_server = user.get_config_parameter("smtp_relay_server")
        if not smtp_server:
            return _skip(f"smtp_relay_server not configured for '{user.name}'")
        smtp_port = user.get_config_parameter("smtp_relay_port") or 25
        smtp_starttls = bool(user.get_config_parameter("smtp_relay_starttls"))
        smtp_auth = bool(user.get_config_parameter("smtp_relay_auth"))
        smtp_username = None
        smtp_password = None
        if smtp_auth:
            smtp_username = user.get_config_parameter("smtp_relay_username")
            smtp_password = user.get_config_parameter("smtp_relay_password")
            if not smtp_username or not smtp_password:
                return _skip(f"smtp_relay_auth=True but username/password not set for '{user.name}'")
        link_host = self._recovery_link_host()
        if not link_host:
            return _skip(f"could not derive sso_fqdn for link host (user '{user.name}')")
        # ---- User-config prerequisites ---------------------------------
        sso_token = self._recovery_lookup_target_token(user, command_args)
        if sso_token is None:
            sso_token_name = self._sso_token_name(command_args)
            return _skip(f"user '{user.name}' has no token named '{sso_token_name}' (default_sso_token_name)")
        if not self._recovery_type_allowed(user, sso_token):
            allowed = user.get_config_parameter("allow_sso_token_recovery") or []
            return _skip(f"SSO token '{sso_token.name}' type '{sso_token.token_type}' for user '{user.name}' not in allow_sso_token_recovery={allowed} (deploy-supported: {list(SSO_RECOVERY_DEPLOY_TYPES)})")
        values = user.get_attribute("otpmeRecoveryMail") or []
        recovery_mail = values[0] if values else None
        if not recovery_mail:
            return _skip(f"user '{user.name}' has no otpmeRecoveryMail attribute set")
        # ---- Heavy path: generate, persist, send -----------------------
        raw_token = stuff.gen_secret(len=SSO_RECOVERY_TOKEN_BYTES)
        token_hash = self._recovery_hash(raw_token)
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            user.recovery_token = token_hash
            user.recovery_token_created = int(time.time())
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("SSO-token recovery: failed to persist token for user '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            return self._recovery_generic_ok()
        ttl = user.get_config_parameter("sso_recovery_link_ttl", apply_getter=False) or 900
        reset_url = (f"https://{link_host}/recover/complete"
                     f"?t={raw_token}&u={user.name}")
        subject = _("SSO token recovery")
        body_template = _("Hello,\n\nwe received a request to recover the SSO token for the account '{user_name}'.\n\nTo set up a fresh SSO token, open the following link within the next {minutes} minutes:\n\n{reset_url}\n\nIf you did not request this, you can ignore this message -- your existing token stays untouched.\n")
        body = body_template.format(user_name=user.name,
                                    minutes=max(1, ttl // 60),
                                    reset_url=reset_url)
        try:
            from otpme.lib.mail import send_mail
            send_mail(mail_from=mail_from,
                      mail_to=recovery_mail,
                      subject=subject,
                      message=body,
                      server=smtp_server,
                      port=smtp_port,
                      starttls=smtp_starttls,
                      username=smtp_username,
                      password=smtp_password)
        except Exception as e:
            log_msg = _("SSO-token recovery: failed to send mail for user '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            # Response stays generic -- attacker shouldn't be able to
            # infer whether the mail actually went out. Admin sees the
            # failure in logs.
            return self._recovery_generic_ok()
        log_msg = _("SSO-token recovery: mail dispatched for user '{u}'.", log=True)[1]
        log_msg = log_msg.format(u=user.name)
        self.logger.info(log_msg)
        return self._recovery_generic_ok()

    def get_sso_token_recovery_info(self, username, sso_jwt, command_args):
        """ Unauth: validate a raw recovery token against the stored
        hash+TTL and return the SSO-token metadata needed to render
        the deploy form. All failure paths return the same 'invalid'
        response shape -- no distinguishing state for attackers. """
        raw_token = command_args.get('recovery_token')
        if not isinstance(username, str) or not username:
            return self._recovery_invalid()
        if not isinstance(raw_token, str) or not raw_token:
            return self._recovery_invalid()
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm)
        if user is None:
            return self._recovery_invalid()
        if user.site != config.site:
            return self.ssod_redirect_command(command="get_sso_token_recovery_info",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        if not user.get_config_parameter("allow_sso_account_recovery"):
            return self._recovery_invalid()
        if not self._recovery_verify_stored(user, raw_token):
            return self._recovery_invalid()
        sso_token = self._recovery_lookup_target_token(user, command_args)
        if not self._recovery_type_allowed(user, sso_token):
            return self._recovery_invalid()
        # Deploy-time type choices: same site/unit/user gate map as
        # the auth-flow get_allowed_deploy_token_types uses, so the
        # recovery-complete UI renders the same button set the
        # regular /deploy page would.
        allowed_deploy_types = [tt for tt in DEPLOY_TOKEN_TYPES
                                if self._deploy_type_allowed(user, tt)]
        return self.build_response(True, {
                'valid':                True,
                'status':               True,
                'sso_token_name':       sso_token.name,
                'sso_token_type':       sso_token.token_type,
                'allowed_deploy_types': allowed_deploy_types,
            })

    def _recovery_gate(self, username, command_args):
        """ Shared prelude for every recovery-deploy command: input
        validation + user lookup. Returns ``(user, err_response)``:
        on failure ``user`` is None and the caller returns
        ``err_response`` verbatim; on success ``err_response`` is
        None and the caller proceeds (cross-site forwarding + the
        recovery-token/hash/TTL check happen in the per-handler
        continuation via ``_recovery_gate_home``). """
        raw_token = command_args.get('recovery_token')
        if not isinstance(username, str) or not username:
            return None, self._recovery_invalid()
        if not isinstance(raw_token, str) or not raw_token:
            return None, self._recovery_invalid()
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm)
        if user is None:
            return None, self._recovery_invalid()
        return user, None

    def _recovery_gate_home(self, user, command_args):
        """ Second half of the gate, only called after any cross-site
        forwarding was already resolved by the caller. Verifies the
        stored token hash + freshness and returns the SSO target
        token (never None on success). """
        if not user.get_config_parameter("allow_sso_account_recovery"):
            return None, self._recovery_invalid()
        raw_token = command_args.get('recovery_token')
        if not self._recovery_verify_stored(user, raw_token):
            return None, self._recovery_invalid()
        sso_token = self._recovery_lookup_target_token(user, command_args)
        if not self._recovery_type_allowed(user, sso_token):
            return None, self._recovery_invalid()
        return sso_token, None

    def recovery_deploy_begin(self, username, sso_jwt, command_args):
        """ Unauth deploy-begin variant driven by a valid recovery
        token. Recovery-gated equivalent of ``deploy_begin``: creates
        an sso-deploy token of the requested type under the user, so
        the user can provision it (secret+QR for OATH, WebAuthn
        register-begin/complete for FIDO2) before
        ``recovery_deploy_verify`` moves it in place of the user's
        default_sso_token_name. """
        token_type = command_args.get('token_type')
        if not isinstance(token_type, str) or not token_type:
            return self._recovery_invalid()
        user, err = self._recovery_gate(username, command_args)
        if err is not None:
            return err
        if user.site != config.site:
            return self.ssod_redirect_command(command="recovery_deploy_begin",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        sso_token, err = self._recovery_gate_home(user, command_args)
        if err is not None:
            return err
        # Type gate: user may pick any type the site admin has enabled
        # -- deliberately independent of the SSO-token's own type, so a
        # fido2 user can recover as password (or vice versa) when admin
        # policy allows it. Unlike deploy_begin an unknown type is
        # refused here rather than left to add_token: this path is
        # unauthenticated, and it answers everything the same way.
        if token_type not in DEPLOY_ALLOW_PARAMS:
            return self._recovery_invalid()
        if not self._deploy_type_allowed(user, token_type):
            return self._recovery_invalid()
        # Password: no staging token. recovery_deploy_verify creates
        # the token with the user's chosen credential in one shot via
        # add_token(replace=True). No placeholder, no double-policy-
        # check hack, no cleanup path.
        if token_type == "password":
            response = {
                        'token_type'                : token_type,
                        'deploy_login_token_name'   : sso_token.name,
                        'status'                    : True,
                    }
            log_msg = _("Recovery deploy started for user '{u}' (type 'password', no staging token).", log=True)[1]
            log_msg = log_msg.format(u=user.name)
            self.logger.info(log_msg)
            return self.build_response(True, response)
        callback = self.get_callback()
        callback.raise_exception = True
        # Remove leftover sso-deploy token from a previous attempt. Our
        # own staging slot only, and not into the trash -- see
        # deploy_begin() for both reasons.
        deploy_name = self._deploy_token_name(command_args)
        old_deploy = user.token(deploy_name)
        if old_deploy:
            try:
                user.del_token(token_name=deploy_name,
                                force=True,
                                verify_acls=False,
                                run_policies=True,
                                add_to_trash=False,
                                callback=callback)
                user._write(callback=callback)
            except Exception as e:
                log_msg = _("Recovery deploy: failed to clear stale sso-deploy token for '{u}': {e}", log=True)[1]
                log_msg = log_msg.format(u=user.name, e=e)
                self.logger.warning(log_msg)
                return self._recovery_invalid()
        # tiqr: no staging token here either. The signed enrollment
        # grant names DEPLOY_NAME, so the regular unauth enrollment
        # path (tiqr_enroll_metadata -> tiqr_enroll_finish) creates the
        # token once the phone has delivered its secret, and
        # recovery_deploy_verify finds it waiting.
        #
        # There is no logged-in token in this flow, so the grant names
        # the lost SSO token. It is not mirrored from -- the move in
        # recovery_deploy_verify takes over its UUID and with it every
        # membership -- but naming it makes the enrollment refuse if it
        # disappeared in the meantime, which would leave the move with
        # nothing to replace and the new token without any reach.
        # Same as in deploy_begin: the types the SSO role can move
        # between are named by their owner, and the name has to be
        # usable before anything is created.
        #
        # These are the only spots in the recovery flow that answer
        # with a real message instead of the uniform 'invalid'. It is
        # something the user typed and can fix, and by the time we are
        # here the recovery token has already been verified -- so
        # nobody learns anything from it who could not already see the
        # deploy form. Telling them the link expired would just send
        # them back for another mail.
        device_name = None
        if token_type in DEVICE_NAME_TOKEN_TYPES:
            device_name, error = self._deploy_device_name(user, token_type,
                                                        command_args)
            if error is not None:
                return error
        if token_type == "tiqr":
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            expiry = time.time() + my_site.get_config_parameter("tiqr_enrollment_expiry")
            enroll_key = tiqr_helpers.build_enroll_key(
                                    tiqr_token.get_site_secret(),
                                    tiqr_helpers.ENROLL_SCOPE_METADATA,
                                    expiry,
                                    user_uuid=user.uuid,
                                    token_name=deploy_name,
                                    device_name=device_name,
                                    login_token_uuid=sso_token.uuid)
            url_template = tiqr_helpers.build_metadata_url_template(my_site.sso_fqdn)
            metadata_url = tiqr_helpers.build_metadata_url(url_template,
                                                        enroll_key)
            enroll_scheme = my_site.get_config_parameter("tiqr_enroll_scheme")
            enroll_url = tiqr_helpers.build_enroll_url(enroll_scheme,
                                                    metadata_url)
            try:
                qrcode_data = qrcode.gen_qrcode(enroll_url, fmt="svg")
                if isinstance(qrcode_data, bytes):
                    qrcode_data = qrcode_data.decode('utf-8')
                qrcode_img = ("data:image/svg+xml;base64,"
                            + base64.b64encode(qrcode_data.encode()).decode())
            except Exception as e:
                log_msg = _("Recovery deploy: tiqr QR code generation failed for '{u}': {e}", log=True)[1]
                log_msg = log_msg.format(u=user.name, e=e)
                self.logger.warning(log_msg)
                return self._recovery_invalid()
            response = {
                        'token_type'                : token_type,
                        'deploy_token_name'         : deploy_name,
                        'deploy_login_token_name'   : sso_token.name,
                        'enroll_url'                : enroll_url,
                        'qrcode_img'                : qrcode_img,
                        'status'                    : True,
                    }
            log_msg = _("Recovery deploy started for user '{u}' (type 'tiqr').", log=True)[1]
            log_msg = log_msg.format(u=user.name)
            self.logger.info(log_msg)
            return self.build_response(True, response)
        try:
            user.add_token(token_name=deploy_name,
                            token_type=token_type,
                            no_token_infos=True,
                            mode="mode1",
                            gen_qrcode=False,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            tb = traceback.format_exc()
            log_msg = _("Recovery deploy: add_token failed for '{u}' (type '{t}'): {e}\n{tb}", log=True)[1]
            log_msg = log_msg.format(u=user.name, t=token_type, e=e, tb=tb)
            self.logger.warning(log_msg)
            return self._recovery_invalid()
        deploy_token = user.token(deploy_name)
        if not deploy_token:
            return self._recovery_invalid()
        response = {
                    'token_type'                : token_type,
                    'deploy_token_name'         : deploy_name,
                    'deploy_login_token_name'   : sso_token.name,
                    'status'                    : True,
                }
        # FIDO2: WebAuthn dance provides the credential, no secret/QR.
        if token_type == "fido2":
            # Same place deploy_begin and the self-service flow put it.
            deploy_token.change_device_name(device_name,
                                        force=True,
                                        verify_acls=False,
                                        run_policies=False,
                                        callback=callback)
            deploy_token._write(callback=callback)
            return self.build_response(True, response)
        # TOTP: return the shared secret + PIN + QR image.
        if device_name:
            deploy_token.change_device_name(device_name,
                                        force=True,
                                        verify_acls=False,
                                        run_policies=False,
                                        callback=callback)
        deploy_token._write(callback=callback)
        try:
            secret = deploy_token.get_secret(pin=deploy_token.pin,
                                             encoding="base32")
            qrcode_data = deploy_token.gen_qrcode(pin=deploy_token.pin,
                                                  fmt="svg",
                                                  run_policies=False,
                                                  verify_acls=False)
            if isinstance(qrcode_data, bytes):
                qrcode_data = qrcode_data.decode('utf-8')
            qrcode_data_uri = ("data:image/svg+xml;base64,"
                    + base64.b64encode(qrcode_data.encode()).decode())
        except Exception as e:
            log_msg = _("Recovery deploy: QR/secret gen failed for '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            return self._recovery_invalid()
        response['secret'] = secret
        response['pin'] = deploy_token.pin
        response['qrcode_img'] = qrcode_data_uri
        log_msg = _("Recovery deploy started for user '{u}' (type '{t}').", log=True)[1]
        log_msg = log_msg.format(u=user.name, t=token_type)
        self.logger.info(log_msg)
        return self.build_response(True, response)

    def recovery_fido2_register_begin(self, username, sso_jwt, command_args):
        """ Unauth FIDO2 register-begin variant for the recovery flow.
        Analogous to ``fido2_register_begin`` with ``is_deploy=True``:
        finds the sso-deploy FIDO2 token created by
        ``recovery_deploy_begin`` (credential_data still empty),
        starts a WebAuthn registration, stashes the reg state under
        an opaque id in the fido2_reg_states shared dict and syncs it
        across the cluster. begin and complete land on the same node
        anyway, because both are forwarded with mgmt=True (master
        node) -- the sync is what carries a registration in progress
        over a master switch."""
        rp_id = command_args.get('rp_id')
        if not isinstance(rp_id, str) or not rp_id:
            return self._recovery_invalid()
        user, err = self._recovery_gate(username, command_args)
        if err is not None:
            return err
        if user.site != config.site:
            return self.ssod_redirect_command(command="recovery_fido2_register_begin",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        sso_token, err = self._recovery_gate_home(user, command_args)
        if err is not None:
            return err
        del sso_token  # metadata not needed on the fido2 register path
        # Locate the empty FIDO2 sso-deploy token for this user.
        user_tokens = backend.search(object_type="token",
                                    attribute="owner_uuid",
                                    value=user.uuid,
                                    return_type="instance")
        fido2_token = None
        for token in user_tokens:
            if token.token_type != "fido2":
                continue
            if not token.credential_data and fido2_token is None:
                fido2_token = token
        if not fido2_token:
            return self._recovery_invalid()
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        user_data = {"id": user.name.encode(),
                    "name": user.name,
                    "displayName": user.name}
        # is_deploy semantics: no existing-credentials list; the user
        # is intentionally re-using their authenticator to replace the
        # login token they lost access to.
        create_options, reg_state = fido2_server.register_begin(
            user_data,
            credentials=[],
            user_verification=fido2_token.uv or "preferred",
            authenticator_attachment="cross-platform",
        )
        expiry = 300
        fido2_state_id = f"fido2_reg_states:{stuff.gen_secret(len=32)}"
        add_cluster_state(multiprocessing.fido2_reg_states,
                        state_id=fido2_state_id,
                        state_data={'state':      reg_state,
                                    'token_uuid': fido2_token.uuid},
                        expiry=expiry)
        return self.build_response(True, {
                    'create_options': dict(create_options),
                    'fido2_state_id': fido2_state_id,
                    'status':         True,
                })

    def recovery_fido2_register_complete(self, username, sso_jwt, command_args):
        """ Unauth FIDO2 register-complete variant. Stores the
        attested credential on the sso-deploy FIDO2 token. Does NOT
        move the token to the login-token slot yet -- that happens
        in ``recovery_deploy_verify`` so the same code path handles
        OATH and FIDO2 uniformly. """
        rp_id = command_args.get('rp_id')
        fido2_state_id = command_args.get('fido2_state_id')
        registration_data = command_args.get('registration_data')
        if not isinstance(rp_id, str) or not rp_id:
            return self._recovery_invalid()
        if not isinstance(fido2_state_id, str) or not fido2_state_id:
            return self._recovery_invalid()
        if not registration_data:
            return self._recovery_invalid()
        user, err = self._recovery_gate(username, command_args)
        if err is not None:
            return err
        if user.site != config.site:
            return self.ssod_redirect_command(command="recovery_fido2_register_complete",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        sso_token, err = self._recovery_gate_home(user, command_args)
        if err is not None:
            return err
        del sso_token  # metadata not needed on the fido2 register path
        try:
            state_data = multiprocessing.fido2_reg_states.delete(fido2_state_id)
        except KeyError:
            return self._recovery_invalid()
        cluster_sync_state_delete(fido2_state_id)
        reg_state = state_data['state']
        token_uuid = state_data['token_uuid']
        fido2_token = backend.get_object(uuid=token_uuid)
        if not fido2_token:
            return self._recovery_invalid()
        if fido2_token.owner_uuid != user.uuid:
            return self._recovery_invalid()
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        try:
            auth_data = fido2_server.register_complete(reg_state,
                                                        registration_data)
        except Exception as e:
            log_msg = _("Recovery FIDO2 registration failed for '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            return self._recovery_invalid()
        # Attestation cert check mirrors the regular register_complete
        # path so the recovery flow enforces the same policy.
        check_attestation_cert = user.get_config_parameter("check_fido2_attestation_cert")
        if check_attestation_cert:
            from otpme.lib.token.fido2.fido2 import verify_attestation_cert
            try:
                info_messages, \
                attestation_cert = verify_attestation_cert(registration_data)
            except OTPmeException as e:
                log_msg = _("Recovery FIDO2 attestation verification failed for '{u}': {e}", log=True)[1]
                log_msg = log_msg.format(u=user.name, e=e)
                self.logger.warning(log_msg)
                return self._recovery_invalid()
            for info_msg in info_messages:
                self.logger.info(info_msg)
            fido2_token.attestation_cert = attestation_cert
        fido2_token.rp = rp_id
        fido2_token.credential_data = encode(auth_data.credential_data, "hex")
        fido2_token._write(callback=self.get_callback())
        return self.build_response(True, {'status': True})

    def recovery_deploy_verify(self, username, sso_jwt, command_args):
        """ Unauth deploy-verify variant driven by a valid recovery
        token. Verifies the just-provisioned sso-deploy token (OTP
        entry for OATH, credential-present check for FIDO2), then
        moves it in place of the user's default_sso_token_name
        (never a client-supplied target -- prevents pivoting). On
        success clears the recovery token from the user object so
        the link is single-use. """
        user, err = self._recovery_gate(username, command_args)
        if err is not None:
            return err
        if user.site != config.site:
            return self.ssod_redirect_command(command="recovery_deploy_verify",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        sso_token, err = self._recovery_gate_home(user, command_args)
        if err is not None:
            return err
        callback = self.get_callback()
        callback.raise_exception = True
        token_data = command_args.get('token_data') or {}
        # Password: no DEPLOY_NAME staging. Create the new password
        # token directly at the SSO-token slot with add_token(
        # replace=True). Works for both same-type (was password) and
        # cross-type (was fido2/totp -> password). Real password
        # policy failures surface with a proper message.
        token_type_hint = token_data.get('token_type')
        if token_type_hint == "password":
            new_password = token_data.get('password')
            confirm = token_data.get('password_confirm')
            if not isinstance(new_password, str) or not new_password:
                return self._recovery_invalid()
            if confirm is not None and confirm != new_password:
                return self._recovery_invalid()
            try:
                user.add_token(token_name=sso_token.name,
                                token_type="password",
                                replace=True,
                                password=new_password,
                                no_token_infos=True,
                                force=True,
                                verify_acls=False,
                                run_policies=True,
                                callback=callback)
                user._write(callback=callback)
            except Exception as e:
                log_msg = _("Recovery deploy: password set failed for '{u}': {e}", log=True)[1]
                log_msg = log_msg.format(u=user.name, e=e)
                self.logger.warning(log_msg)
                return self._recovery_invalid()
        else:
            # OATH / FIDO2: verify the staging token this portal
            # parked, then move it into the SSO-token slot
            # (server-derived name -- client-supplied token name never
            # taken).
            deploy_name = self._deploy_token_name(command_args)
            deploy_token = user.token(deploy_name)
            if not deploy_token:
                return self._recovery_invalid()
            if deploy_token.token_type == "fido2":
                if not deploy_token.credential_data:
                    return self._recovery_invalid()
            elif deploy_token.token_type == "tiqr":
                # Same check the fido2 branch makes on credential_data:
                # the enrollment creates this token only after the
                # phone delivered its secret, so this is the proof that
                # the phone is done.
                #
                # A real message rather than the uniform 'invalid', for
                # the same reason as the device name in
                # recovery_deploy_begin: the recovery token is already
                # verified at this point, and this is the one failure
                # the user can act on -- they simply have not finished
                # in the app yet.
                if not deploy_token.has_auth_data():
                    msg = _("Phone not enrolled yet.")
                    return self.build_response(False,
                                    {'message': msg, 'status': False})
            else:
                otp = str(token_data.get('otp', ''))
                if not otp:
                    return self._recovery_invalid()
                try:
                    pin = deploy_token.pin or ""
                    verify_result = deploy_token.verify_otp(otp=f"{pin}{otp}")
                except Exception as e:
                    log_msg = _("Recovery deploy: OTP verify failed for '{u}': {e}", log=True)[1]
                    log_msg = log_msg.format(u=user.name, e=e)
                    self.logger.warning(log_msg)
                    return self._recovery_invalid()
                if not verify_result:
                    return self._recovery_invalid()
            target_path = f"{user.name}/{sso_token.name}"
            try:
                deploy_token.move(target_path,
                                replace=True,
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
            except Exception as e:
                log_msg = _("Recovery deploy: token move failed for '{u}': {e}", log=True)[1]
                log_msg = log_msg.format(u=user.name, e=e)
                self.logger.critical(log_msg)
                return self._recovery_invalid()
        # Single-shot: clear the recovery slot so the link stops
        # working immediately.
        try:
            user.recovery_token = None
            user.recovery_token_created = None
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("Recovery deploy: failed to clear recovery slot for '{u}': {e}", log=True)[1]
            log_msg = log_msg.format(u=user.name, e=e)
            self.logger.warning(log_msg)
            # Don't fail the whole flow -- deploy succeeded, only the
            # cleanup didn't. TTL will still expire the token.
        log_msg = _("Recovery deploy complete for user '{u}'.", log=True)[1]
        log_msg = log_msg.format(u=user.name)
        self.logger.info(log_msg)
        return self.build_response(True, {'status': True})

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
                    {'message': 'SSOD_INCOMPLETE_COMMAND', 'status': False})
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message': 'JWT_INVALID', 'status': False})
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
                                 force=True,
                                 verify_acls=False,
                                 callback=callback)
        except Exception as e:
            message, log_msg = _("Language change failed for user '{user_name}': {e}", log=True)
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
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            new_password = command_args['new_password']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
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
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="change_password",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        # Get token.
        token = config.auth_token
        token_path = token.rel_path
        client_ip = command_args.get('client_ip')
        # Verify current password against the token.
        verify_result = token.verify_static(password=current_password,
                                            ignore_2f_token=True)
        if not verify_result:
            emit_audit("Auth", "password_change_failed",
                            level='warning',
                            user=user.name,
                            token=token_path,
                            reason='current_password_invalid',
                            ip=client_ip)
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
            emit_audit("Auth", "password_change_failed",
                            level='warning',
                            user=user.name,
                            token=token_path,
                            reason='policy_or_write_error',
                            error=str(e),
                            ip=client_ip)
            message = message.format(token_path=token_path, e=e)
            response = {'message':message, 'status':False}
            return self.build_response(False, response)
        # Write token.
        token._write(callback=callback)
        emit_audit("Auth", "password_changed",
                        user=user.name,
                        token=token_path,
                        ip=client_ip)
        message = _("Token password changed successfully.")
        return self.build_response(True, message)

    def change_pin(self, username, sso_jwt, command_args):
        try:
            current_pin = command_args['current_pin']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            new_pin = command_args['new_pin']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
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
        # Check for command redirection.
        if user.site != config.site:
            return self.ssod_redirect_command(command="change_pin",
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)
        # Get token.
        token = config.auth_token
        token_path = token.rel_path
        client_ip = command_args.get('client_ip')
        if not token:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        # Verify token belongs to user.
        if token.owner_uuid != user.uuid:
            emit_audit("Auth", "pin_change_failed",
                            level='warning',
                            user=user.name,
                            token=token_path,
                            reason='token_owner_mismatch',
                            ip=client_ip)
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        if token.pass_type != "otp":
            response = {'message':'Token does not support PIN change.', 'status':False}
            return self.build_response(False, response)
        # Only for tokens an administrator manages. With
        # sso_allow_totp_mgmt on the TOTP card sets PINs itself
        # (change_totp_pin).
        if self._mgmt_allowed(user, "sso_allow_totp_mgmt"):
            response = {'message':'PIN change is not enabled.', 'status':False}
            return self.build_response(False, response)
        # Verify current PIN against the token.
        if not token.pin or str(token.pin) != str(current_pin):
            emit_audit("Auth", "pin_change_failed",
                            level='warning',
                            user=user.name,
                            token=token_path,
                            reason='current_pin_invalid',
                            ip=client_ip)
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
            emit_audit("Auth", "pin_change_failed",
                            level='warning',
                            user=user.name,
                            token=token_path,
                            reason='policy_or_write_error',
                            error=str(e),
                            ip=client_ip)
            message = message.format(token_path=token_path, e=e)
            response = {'message':message, 'status':False}
            return self.build_response(False, response)
        # Write token.
        token._write(callback=callback)
        emit_audit("Auth", "pin_changed",
                        user=user.name,
                        token=token_path,
                        ip=client_ip)
        message = _("Token PIN changed successfully.")
        return self.build_response(True, message)

    def _device_token_role_paths_to_instances(self, role_paths):
        """ Convert a list of "<site>/<role>" paths (bare names default
        to the local site) into role instances. Unknown roles are
        silently skipped. """
        if not role_paths:
            return []
        roles = []
        for role_path in role_paths:
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
                continue
            roles.append(result[0])
        return roles

    def _get_device_token_roles(self, user):
        """ Resolve the device_token_roles config parameter to a list of role
        instances via ``user.get_config_parameter`` (walks user → unit(s)
        → site). Must be called on the user's home site. """
        try:
            role_paths = user.get_config_parameter("device_token_roles")
        except Exception as e:
            log_msg = _("Failed to read device_token_roles: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return []
        return self._device_token_role_paths_to_instances(role_paths)

    def _device_token_roles_trusts(self, command_args):
        """ The trust list of the site whose portal is asking.

        Off the portal's site object, not off ours: for a foreign user
        the command runs on their home site, and it is still the portal
        that decides which of its roles it hands out to whom. An
        unknown site leaves the list empty, which grants nothing. """
        portal_site = self._portal_site(command_args)
        site = backend.get_object(object_type="site",
                                realm=config.realm,
                                name=portal_site)
        if site is None:
            log_msg = _("Unknown portal site '{site}'.", log=True)[1]
            log_msg = log_msg.format(site=portal_site)
            self.logger.warning(log_msg)
            return []
        try:
            trusts = site.get_config_parameter("device_token_roles_trusts")
        except Exception as e:
            log_msg = _("Failed to read device_token_roles_trusts: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return []
        return trusts or []

    def _site_trusts_user_home(self, user, command_args):
        """ May users of this user's home site carry device token roles
        at this portal at all?

        The bare site entry in the portal's ``device_token_roles_trusts``
        is that permission, and it is only the first half: which of the
        portal's roles they actually get is decided per role in
        _portal_device_token_roles(). Own-site users need no entry. """
        portal_site = self._portal_site(command_args)
        if user.site == portal_site:
            return True
        return user.site in self._device_token_roles_trusts(command_args)

    def _portal_device_token_roles(self, user, roles, command_args):
        """ The roles of ``roles`` this portal shows this user.

        Two filters. A portal offers the roles of its own site and no
        others -- the user's device_token_roles may name roles anywhere
        in the realm, and each portal shows its own slice, so the same
        user config serves every site they use. And a foreign user gets
        one of our roles only where the portal says so by name:
        "<their site>:<our role>" in device_token_roles_trusts, on top
        of the bare site entry that lets them in at all. """
        portal_site = self._portal_site(command_args)
        foreign_user = user.site != portal_site
        trusts = self._device_token_roles_trusts(command_args)
        if foreign_user and user.site not in trusts:
            return []
        allowed = []
        for role in roles:
            if role.site != portal_site:
                continue
            if foreign_user and f"{user.site}:{role.name}" not in trusts:
                log_msg = _("Device token role '{role}' not listed for site "
                            "'{site}' in device_token_roles_trusts of "
                            "'{portal}'.", log=True)[1]
                log_msg = log_msg.format(role=role.name,
                                        site=user.site,
                                        portal=portal_site)
                self.logger.debug(log_msg)
                continue
            allowed.append(role)
        return allowed

    def _resolve_device_token_roles(self, user, command_args):
        """ The device token roles this portal offers this user.

        The user's own cascade decides which roles they may carry at
        all -- read on their home site, because user.get_config_parameter
        walks the user's parents and only that site has them. What of it
        this portal shows is then _portal_device_token_roles().

        Both ends therefore have to agree, and each states its half in
        its own objects: the home site by naming the role in the user's
        device_token_roles, the portal by listing the user's site and
        that role in device_token_roles_trusts. """
        if not self._site_trusts_user_home(user, command_args):
            return []
        if user.site == config.site:
            roles = self._get_device_token_roles(user)
            return self._portal_device_token_roles(user, roles, command_args)
        status, resp = self._remote_ssod_call(user=user,
                                            command="sso_get_device_token_role_uuids",
                                            extra_args=command_args)
        if not status or not isinstance(resp, dict):
            return []
        role_uuids = resp.get('role_uuids') or []
        roles = []
        for role_uuid in role_uuids:
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if role is None:
                continue
            roles.append(role)
        return self._portal_device_token_roles(user, roles, command_args)

    def sso_get_device_token_role_uuids(self, username, sso_jwt, command_args):
        """ Internal cross-site command: resolve device_token_roles on the
        user's home site and return the list of role UUIDs. The caller
        loads the role objects locally (cluster-synced).

        The user's whole cascade, roles of every site included -- what
        the asking portal shows of it is its own decision, and it makes
        it in _portal_device_token_roles() with the list it gets back.
        Nothing here is a permission: every role still has to survive
        that filter. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.build_response(False, {'message':'WRONG_SITE', 'status':False})
        roles = self._get_device_token_roles(user)
        role_uuids = [role.uuid for role in roles]
        return self.build_response(True, {'role_uuids': role_uuids, 'status': True})

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

    def _fetch_home_language(self, user, command_args):
        """ Cross-site fetch of ``user.language`` from the user's home
        site. Used by ``_resolve_language`` when the request is served
        for a foreign user: the local User replica may lag behind the
        home site (a language change persisted on the home site
        replicates asynchronously), so the local replica's
        ``user.language`` cannot be trusted for the render decision.

        Returns the language code or ``None`` when the home site has
        no explicit language pref for this user, or when the cross-
        site call fails (caller then falls back to accept-language). """
        try:
            ssod_conn = connections.get("ssod",
                                        realm=config.realm,
                                        site=user.site,
                                        auto_preauth=True,
                                        auto_auth=False)
        except Exception as e:
            log_msg = _("Home-site language fetch: connect failed: {e}",
                        log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        forward_args = dict(command_args or {})
        # session_uuid belongs to the originating site's session store;
        # the home ssod would fail to look it up. Mirrors the strip in
        # ``ssod_redirect_command``.
        forward_args.pop('session_uuid', None)
        try:
            status, _sc, response, _bin = ssod_conn.send(
                                command="resolve_user_language",
                                command_args=forward_args)
        except Exception as e:
            log_msg = _("Home-site language fetch failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        finally:
            try:
                ssod_conn.close()
            except Exception:
                pass
        if not status or not isinstance(response, dict):
            return None
        return response.get('language') or None

    def resolve_user_language(self, username, sso_jwt, command_args):
        """ Return the authoritative UI language of ``username`` from
        this site's User backend. Used cross-site by
        ``_fetch_home_language`` so foreign-user renders don't rely
        on a possibly-stale local replica. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message': 'JWT_INVALID', 'status': False})
        # Should not happen -- the caller only fires this cross-site
        # when the user is foreign and lands here on their home. But
        # if the caller misroutes, re-forward to the actual home
        # rather than lying about the language.
        if user.site != config.site:
            return self.ssod_redirect_command(
                                command="resolve_user_language",
                                user=user,
                                command_args=command_args)
        language = None
        if getattr(user, 'language_set', False) and user.language:
            language = user.language
        return self.build_response(True, {
            'status': True,
            'language': language,
        })

    def _resolve_language(self, user, command_args):
        """ Determine which language to render localized object fields in.
        Priority: an explicit `language` from the caller (CLI flag or
        API arg) wins, then the user's persisted language preference
        (fetched from the user's home site when foreign, read locally
        when local), then a soft `accept_language` hint sent by the
        web layer, else "en".

        The home-site fetch matters for foreign users because the
        local User replica lags after a language change (persistence
        happens on the home site; replication is asynchronous). A
        user.language that is only the default ('en' with
        language_set=False) is intentionally ignored so the browser's
        Accept-Language still steers the render. """
        args = command_args or {}
        explicit = args.get('language')
        if explicit:
            return explicit
        if user.site != config.site:
            home_lang = self._fetch_home_language(user, command_args)
            if home_lang:
                return home_lang
        else:
            try:
                if getattr(user, 'language_set', False) and user.language:
                    return user.language
            except Exception:
                pass
        hint = args.get('accept_language')
        if hint:
            return hint
        return "en"

    def _sanitize_device_token_name(self, device_name, command_args):
        """ Build a valid token name from a user-supplied device name.

        Restricted to ``[a-z0-9-]`` so the resulting OTPme token name
        survives every code path (LDAP, file system, URL paths, ...)
        without surprises. The web layer enforces the same alphabet
        on input; this is the defensive copy.

        The caller appends the role's device_token_suffix, which is
        already site-specific in practice -- but only in practice, and
        only while no two sites pick the same suffix. Realm and site go
        in front for the same reason they do everywhere else here: one
        user, one device name, two portals. """
        prefix = self._token_name_prefix("device", command_args)
        return sso_helpers.sanitize_token_name(device_name, prefix=prefix)

    def _mgmt_allowed(self, user, parameter):
        """ Resolve one of the ``sso_allow_*_mgmt`` parameters for the
        given user.

        The same cascade as the other portal parameters (user -> unit
        -> site, anchored at the user's home). get_config_parameter()
        returns None when no level sets it, so the registered default
        -- off -- has to be applied here. """
        try:
            registered_default = bool(
                config.get_config_parameter(parameter)['default'])
        except Exception:
            registered_default = False
        try:
            value = user.get_config_parameter(parameter)
        except Exception:
            value = None
        if value is None:
            return registered_default
        return bool(value)

    def _get_user_sessions(self, user):
        """ The sessions of the given user on this site.

        A session lives on the site the login happened on, so these are
        the ones this portal can show and end -- the same span the
        passkey listing has. """
        try:
            sessions = backend.search(object_type="session",
                                    attributes={'user_uuid':
                                                {'value': user.uuid}},
                                    return_type="instance")
        except Exception as e:
            log_msg = _("Failed to search sessions of user '{user}': {e}", log=True)[1]
            log_msg = log_msg.format(user=user.name, e=e)
            self.logger.warning(log_msg)
            return []
        return sessions or []

    def _resolve_session_name(self, object_uuid, name_cache,
        object_type=None, return_type="name"):
        """ Resolve a UUID a session refers to to its name.

        The client of a session may be a client or a host object, so
        that one is searched without an object type -- the same way the
        session listing of the CLI does it. The UUID is the fallback: a
        session may well outlive the object it was created for. """
        if not object_uuid:
            return ""
        if object_uuid in name_cache:
            return name_cache[object_uuid]
        name = object_uuid
        search_args = {}
        if object_type:
            search_args['object_type'] = object_type
        try:
            result = backend.search(attribute="uuid",
                                    value=object_uuid,
                                    return_type=return_type,
                                    **search_args)
        except Exception as e:
            log_msg = _("Failed to resolve session attribute '{uuid}': {e}", log=True)[1]
            log_msg = log_msg.format(uuid=object_uuid, e=e)
            self.logger.debug(log_msg)
            result = None
        if result:
            name = result[0]
        name_cache[object_uuid] = name
        return name

    def _session_info(self, session, current_session_uuid, name_cache):
        """ What the settings page shows for one session. """
        try:
            expire_time = session.expire_time()
        except Exception:
            expire_time = 0
        try:
            last_used = float(session.last_used)
        except Exception:
            last_used = 0
        client = self._resolve_session_name(session.client, name_cache)
        token = self._resolve_session_name(session.auth_token, name_cache,
                                        object_type="token",
                                        return_type="rel_path")
        session_info = {
                    'uuid'          : session.uuid,
                    'session_type'  : session.session_type or "",
                    'access_group'  : session.access_group or "",
                    'client'        : client,
                    'client_ip'     : session.client_ip or "",
                    'token'         : token,
                    'creation_time' : float(session.creation_time or 0),
                    'expire_time'   : float(expire_time or 0),
                    'last_used'     : last_used,
                    # The session this page is served from. Marked rather
                    # than hidden: seeing where one is logged in should
                    # include here, but ending it would log the user out
                    # in the middle of managing their sessions.
                    'current'       : session.uuid == current_session_uuid,
                    }
        return session_info

    def list_sessions(self, username, sso_jwt, command_args):
        """ Return the user's sessions on this site.

        Gated by ``sso_allow_session_mgmt``. When disabled, answer
        ``allowed=False`` and an empty list so the frontend can hide
        the whole card. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'JWT_INVALID', 'status': False,
            })
        if not self._mgmt_allowed(user, "sso_allow_session_mgmt"):
            return self.build_response(True, {'sessions': [],
                                            'allowed': False,
                                            'status': True})
        current_session_uuid = command_args.get('session_uuid')
        name_cache = {}
        sessions = []
        for session in self._get_user_sessions(user):
            sessions.append(self._session_info(session,
                                            current_session_uuid,
                                            name_cache))
        sessions.sort(key=lambda x: x['creation_time'], reverse=True)
        return self.build_response(True, {'sessions': sessions,
                                        'allowed': True,
                                        'status': True})

    def delete_session(self, username, sso_jwt, command_args):
        """ End one of the user's own sessions. """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'JWT_INVALID', 'status': False,
            })
        if not self._mgmt_allowed(user, "sso_allow_session_mgmt"):
            return self.build_response(False, {
                'message': 'NOT_ALLOWED', 'status': False,
            })
        target_session = command_args.get('target_session')
        if not target_session:
            return self.build_response(False, {
                'message': 'target_session missing', 'status': False,
            })
        if target_session == command_args.get('session_uuid'):
            return self.build_response(False, {
                'message': 'CURRENT_SESSION', 'status': False,
            })
        session = backend.get_object(uuid=target_session)
        if session is None or session.type != "session" \
        or session.user_uuid != user.uuid:
            # Same answer for a session of someone else: whether it
            # exists is none of this user's business.
            log_msg = _("User '{user}' tried to end a session that is not theirs: {session}", log=True)[1]
            log_msg = log_msg.format(user=user.name, session=target_session)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'UNKNOWN_SESSION', 'status': False,
            })
        try:
            # Recursive: the child sessions (one per accessgroup) and
            # the OIDC sessions below it are what the login actually
            # got the user, and the user asked for it to end.
            session.delete(force=True,
                        recursive=True,
                        verify_acls=False,
                        callback=self.get_callback())
        except Exception as e:
            log_msg = _("Failed to delete session '{session}': {e}", log=True)[1]
            log_msg = log_msg.format(session=target_session, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'DELETE_FAILED', 'status': False,
            })
        emit_audit("SSO", 'session_deleted',
                        user=user.name,
                        session=target_session)
        return self.build_response(True, {'status': True})

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
                'message': 'JWT_INVALID', 'status': False,
            })
        # Consent state is authoritative on the user's home site -- the
        # local replica may be stale or empty. Redirect for foreign users.
        if user.site != config.site:
            return self.ssod_redirect_command(command="list_oidc_consents",
                                              user=user,
                                              command_args=command_args,
                                              mgmt=True)
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
                'message': 'JWT_INVALID', 'status': False,
            })
        client_uuid = command_args.get('client_uuid')
        if not client_uuid:
            return self.build_response(False, {
                'message': 'client_uuid missing', 'status': False,
            })
        # Consent persistence belongs on the user's home site; writing
        # the revoke to the local replica would be a no-op against the
        # authoritative copy. Redirect for foreign users -- the home
        # site will run its own session sweep too.
        if user.site != config.site:
            return self.ssod_redirect_command(command="revoke_oidc_consent",
                                              user=user,
                                              command_args=command_args,
                                              mgmt=True)
        removed = user.revoke_oidc_consent(client_uuid)
        if removed:
            try:
                user._write(callback=self.get_callback())
            except Exception as e:
                log_msg = _("Failed to persist OIDC consent revocation for user '{user}': {err}", log=True)[1]
                log_msg = log_msg.format(user=user.name, err=e)
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'PERSIST_FAILED', 'status': False,
                })
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
                log_msg = _("Failed to terminate OIDC session '{sid}' during consent revocation: {err}",
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

    def oidc_get_consent_for_client(self, username, sso_jwt, command_args):
        """ Return the stored OIDC consent record for (user, client_uuid)
        on the user's home site. Targeted RPC used by
        ``oidc_authorize_validate`` when the OP site is not the user's
        home -- the authorize endpoint stays local (client + access
        group are site-local) but the consent state is read from home.
        """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'JWT_INVALID', 'status': False,
            })
        client_uuid = command_args.get('client_uuid')
        if not client_uuid:
            return self.build_response(False, {
                'message': 'client_uuid missing', 'status': False,
            })
        record = user.get_oidc_consent(client_uuid) or {}
        return self.build_response(True, {
            'status':  True,
            'consent': record,
        })

    def oidc_set_consent_for_client(self, username, sso_jwt, command_args):
        """ Persist an OIDC consent record for (user, client_uuid) on
        the user's home site. Counterpart to
        ``oidc_get_consent_for_client``; called by the OP from a
        foreign site after the user clicked Allow on the consent
        screen.
        """
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'JWT_INVALID', 'status': False,
            })
        client_uuid = command_args.get('client_uuid')
        if not client_uuid:
            return self.build_response(False, {
                'message': 'client_uuid missing', 'status': False,
            })
        scopes = command_args.get('scopes') or []
        user.set_oidc_consent(client_uuid, scopes)
        try:
            user._write(callback=self.get_callback())
        except Exception as e:
            log_msg = _("Failed to persist OIDC consent for user '{user}' / client '{cid}': {err}", log=True)[1]
            log_msg = log_msg.format(user=user.name,
                                      cid=client_uuid, err=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {
                'message': 'PERSIST_FAILED', 'status': False,
            })
        return self.build_response(True, {'status': True})

    def list_device_tokens(self, username, sso_jwt, command_args):
        # Verify SSO jwt. Use JWT_INVALID so the Flask wrapper redirects
        # to /login on expiry instead of returning a generic 400.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'JWT_INVALID', 'status':False}
            return self.build_response(False, auth_response)
        # A foreign user is answered by their home site: only there does
        # user.get_config_parameter see the user's own cascade. What of
        # it this portal shows is decided in the same call, against the
        # portal's site -- which travels as portal_site -- so the answer
        # is the same wherever it is computed.
        if user.site != config.site:
            return self.ssod_redirect_command(command="list_device_tokens",
                                            user=user,
                                            command_args=command_args)
        roles = self._resolve_device_token_roles(user, command_args)
        # Roles without a device_token_suffix have no way to render a
        # usable token name and are therefore hidden from the portal.
        roles = [r for r in roles if r.get_config_parameter("device_token_suffix")]
        if not roles:
            # Report this as a successful response with roles_configured=False
            # so the frontend can show a single disabled hint instead of an
            # empty list and a load error.
            response = {
                        'roles'             : [],
                        'roles_configured'  : False,
                        'status'            : True,
                    }
            return self.build_response(True, response)
        language = self._resolve_language(user, command_args)
        # Build one group per configured role, keyed by role UUID so we
        # can assign each user-owned token to the matching group(s) in a
        # single pass over user.tokens.
        role_groups = {}
        for role in roles:
            role_groups[role.uuid] = {
                        'role_uuid'         : role.uuid,
                        'role_name'         : role.name,
                        'role_info'         : self._localized_info(role, language),
                        'token_types'       : self._role_device_token_types(role),
                        'max_device_tokens' : self._role_max_device_tokens(role),
                        'device_tokens'     : [],
                    }
        # Iterate the user's own tokens and check role membership on each.
        # This is cheaper than walking role.tokens when a role holds many
        # tokens (e.g. lots of users sharing the same device_token_roles entry).
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
            if token.token_type not in DEVICE_TOKEN_TYPES:
                continue
            # No is_current here, unlike the passkey and tiqr listings:
            # a device token is for WLAN, IMAP, SMTP, CardDAV and the
            # like, never a portal login, so it is never the token this
            # session holds.
            entry = {
                        'name'          : token.name,
                        'device_name'   : self._token_label(token) or token.name,
                        'token_type'    : token.token_type,
                        'enabled'       : bool(token.enabled),
                    }
            for role_uuid in token.get_roles(return_type="uuid"):
                group = role_groups.get(role_uuid)
                if group is None:
                    continue
                group['device_tokens'].append(entry)
        response = {
                    'roles'             : list(role_groups.values()),
                    'roles_configured'  : True,
                    'status'            : True,
                }
        return self.build_response(True, response)

    def _role_device_token_types(self, role):
        """ The token types this role's device tokens may be, in the
        order the role lists them -- the first is the default. Unset, or
        nothing usable, means password: that is what a device token was
        before roles could say anything else. """
        token_types = role.get_config_parameter("device_token_types") or []
        token_types = [x for x in token_types if x in DEVICE_TOKEN_TYPES]
        if not token_types:
            token_types = ["password"]
        return token_types

    def _role_max_device_tokens(self, role):
        """ How many device tokens one user may hold in this role, or
        None for no limit. """
        max_tokens = role.get_config_parameter("max_device_tokens")
        if max_tokens is None:
            return None
        return int(max_tokens)

    def _count_role_device_tokens(self, user, role):
        """ How many device tokens this user holds in this role.

        Walks the user's tokens rather than the role's: a role shared by
        many users holds many more. """
        role_tokens = set(role.tokens or [])
        count = 0
        for token_uuid in user.tokens:
            if token_uuid not in role_tokens:
                continue
            token = backend.get_object(object_type="token", uuid=token_uuid)
            if token is None:
                continue
            if token.token_type not in DEVICE_TOKEN_TYPES:
                continue
            count += 1
        return count

    def _device_token_refused(self, user, role, token_type):
        """ Why this device token may not be created, or None.

        The requested type has to be one the role offers, and the user
        must still have room under max_device_tokens. Asked on both ends
        of a cross-site add: the portal first, so the user hears it
        without a round trip, the home site again because that is where
        the token is written. """
        if token_type not in self._role_device_token_types(role):
            return _("This token type is not allowed for this role.")
        max_tokens = self._role_max_device_tokens(role)
        if max_tokens is not None:
            if self._count_role_device_tokens(user, role) >= max_tokens:
                msg = _("You already have the maximum number of device tokens for this role ({max_tokens}).")
                return msg.format(max_tokens=max_tokens)
        return None

    def _local_create_device_token(self, user, token_name, device_name,
        callback, token_type="password"):
        """ Create a device token for the given user on this node.

        Returns (token_instance, reveal): what the user has to be shown
        now, since nothing hands it out again -- the password of a
        password token, the secret and its QR code of a TOTP one. The
        token is already written to the local backend.

        A TOTP device token has its PIN disabled. It goes into a device
        that has to produce the OTP by itself, and there is nobody at
        that device to type a PIN in front of it. """
        if token_type not in DEVICE_TOKEN_TYPES:
            raise OTPmeException(f"Invalid device token type: {token_type}")
        add_args = {
                'token_name'        : token_name,
                'token_type'        : token_type,
                'no_token_infos'    : True,
                'gen_qrcode'        : False,
                'force'             : True,
                'verify_acls'       : False,
                'run_policies'      : True,
                'callback'          : callback,
            }
        if token_type == "password":
            add_args['enable_mschap'] = True
        else:
            # mode1: the secret is kept on the server, so the QR code can
            # be built from it without anybody entering a PIN.
            add_args['mode'] = "mode1"
        new_password = user.add_token(**add_args)
        user._write(callback=callback)
        token = user.token(token_name)
        if not token:
            raise OTPmeException("Failed to create device token.")
        reveal = {}
        if token_type == "password":
            reveal['password'] = new_password
        else:
            token.disable_pin(force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
            reveal['secret'] = token.get_secret(pin=token.pin,
                                                encoding="base32")
            qrcode_data = token.gen_qrcode(pin=token.pin,
                                        fmt="svg",
                                        run_policies=False,
                                        verify_acls=False)
            if isinstance(qrcode_data, bytes):
                qrcode_data = qrcode_data.decode('utf-8')
            reveal['qrcode_img'] = ("data:image/svg+xml;base64,"
                            + base64.b64encode(qrcode_data.encode()).decode())
        # The setter, not a plain assignment: it is what keeps the
        # changelog and the audit trail in step with the object.
        token.change_device_name(device_name,
                                force=True,
                                verify_acls=False,
                                run_policies=False,
                                callback=callback)
        token._write(callback=callback)
        return token, reveal

    def sso_create_device_token(self, username, sso_jwt, command_args):
        """ Internal cross-site command: create a device token on
        the user's home site and add it to the requested role. The
        caller passes the target role_uuid (chosen from the per-role
        section in the SSO portal); we re-validate it against the
        user's device_token_roles here and derive the final token name
        from the role's device_token_suffix. The home site is the
        authoritative location for both: device_token_roles walks up the
        user hierarchy, and we don't want callers to pick the token
        name freely. The token OID/OC is returned so the calling site
        can mirror the token locally without waiting for cluster sync. """
        try:
            device_name = command_args['device_name']
            role_uuid = command_args['role_uuid']
        except KeyError:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        token_type = command_args.get('token_type')
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.build_response(False, {'message':'WRONG_SITE', 'status':False})
        # sso_create_device_token is only ever reached from another
        # site's ssod via the mgmt port (cluster peer), and the peer has
        # checked the role against its own trust list already. We check
        # it again, and against both halves: the user's own cascade,
        # which is ours to read, and the portal's trust list, which we
        # can read as well -- so a peer naming a role nobody granted
        # gets nowhere, whatever it checked on its side.
        role = None
        for candidate in self._resolve_device_token_roles(user, command_args):
            if candidate.uuid == role_uuid:
                role = candidate
                break
        if not role:
            return self.build_response(False, {'message':'Invalid role.', 'status':False})
        suffix = role.get_config_parameter("device_token_suffix")
        if not suffix:
            return self.build_response(False, {'message':'Role has no device_token_suffix configured.', 'status':False})
        sanitized = self._sanitize_device_token_name(device_name, command_args)
        if not sanitized:
            return self.build_response(False, {'message':'Invalid device name.', 'status':False})
        token_name = f"{sanitized}-{suffix}"
        if user.token(token_name):
            return self.build_response(False, {'message':'A device with this name already exists.', 'status':False})
        # Again here, where the token is written -- the peer asked too,
        # but the count that matters is the one of this site.
        if not token_type:
            token_type = self._role_device_token_types(role)[0]
        refused = self._device_token_refused(user, role, token_type)
        if refused:
            return self.build_response(False, {'message': refused, 'status': False})
        callback = self.get_callback()
        callback.raise_exception = True
        try:
            token, reveal = self._local_create_device_token(user=user,
                                                    token_name=token_name,
                                                    device_name=device_name,
                                                    token_type=token_type,
                                                    callback=callback)
        except Exception as e:
            log_msg = _("Failed to create device token for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to create device token: {e}', 'status':False})
        # Read the object config so the calling site can mirror it locally.
        oc_obj = token.get_sync_config(self.peer)
        if not oc_obj:
            return self.build_response(False, {'message':'Failed to read token object config.', 'status':False})
        # Add token to local role to get it on list_device_tokens even if sync of remote
        # role was not done yet.
        try:
            role.add_token(token_path=token.rel_path,
                            force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
            role._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to add device token to role '{role}': {e}", log=True)[1]
            log_msg = log_msg.format(role=role.name, e=e)
            self.logger.warning(log_msg)
            try:
                add_to_trash = self._add_to_trash(user, "add_device_token_to_trash")
                user.del_token(token_name=token.name,
                                force=True,
                                verify_acls=False,
                                run_policies=True,
                                add_to_trash=add_to_trash,
                                callback=callback)
                user._write(callback=callback)
            except Exception:
                pass
        response = {
                    'status'        : True,
                    'token_type'    : token_type,
                    'token_full_oid': token.oid.full_oid,
                    'token_oc'      : oc_obj.copy(),
                    'role_uuid'     : role.uuid,
                }
        # The password, or the TOTP secret and its QR code -- for the
        # portal to show the user once.
        response.update(reveal)
        return self.build_response(True, response)

    def sso_delete_device_token(self, username, sso_jwt, command_args):
        """ Internal cross-site command: delete a password device token on
        the user's home site. """
        try:
            token_name = command_args['token_name']
        except KeyError:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':'JWT_INVALID', 'status':False})
        if user.site != config.site:
            return self.build_response(False, {'message':'WRONG_SITE', 'status':False})
        callback = self.get_callback()
        callback.raise_exception = True
        add_to_trash = self._add_to_trash(user, "add_device_token_to_trash")
        try:
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
            user._write(callback=callback)
        except Exception as e:
            log_msg = _("Failed to delete device token '{token}' for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(token=token_name, user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False, {'message':f'Failed to delete device token: {e}', 'status':False})
        return self.build_response(True, {'status': True})

    def _remote_ssod_call(self, user, command, extra_args, mgmt=False):
        """ Run an ssod command on the user's home site. """
        # The session_uuid only exists on the redirecting site (where the
        # SSO portal lives). The foreign ssod must not try to look it up
        # in its local backend -- strip it before forwarding.
        forward_args = dict(extra_args)
        forward_args.pop('session_uuid', None)
        # Same as in ssod_redirect_command(): the home site has to know
        # which portal is asking, not just which site it is itself.
        forward_args['portal_site'] = config.site
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
            binary_data = ssod_conn.send(command=command, command_args=forward_args)
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
            role_uuid = command_args['role_uuid']
        except Exception:
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(False, message)
        # One of the role's device_token_types. None means the role's
        # first, which is all a role with a single type needs.
        token_type = command_args.get('token_type')
        device_name = sso_helpers.sanitize_device_label(device_name)
        if not device_name:
            response = {'message':'Device name required.', 'status':False}
            return self.build_response(False, response)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'JWT_INVALID', 'status':False}
            return self.build_response(False, auth_response)
        step_up = self._step_up_required(user, "deploy_device_token_reauth",
                                        command_args)
        if step_up is not None:
            return step_up
        sanitized = self._sanitize_device_token_name(device_name, command_args)
        if not sanitized:
            response = {'message':'Invalid device name.', 'status':False}
            return self.build_response(False, response)
        callback = self.get_callback()
        callback.raise_exception = True
        reveal = {}
        role = None
        token_name = None
        if user.site != config.site:
            # Token creation must happen on the user's home site (authoritative
            # write). We are the originator: validate role_uuid against the
            # roles this portal offers the user BEFORE forwarding, so a
            # user cannot pick an arbitrary role_uuid. The home site
            # resolves the same list again and derives the token name
            # from the role's device_token_suffix.
            role = None
            for candidate in self._resolve_device_token_roles(user, command_args):
                if candidate.uuid == role_uuid:
                    role = candidate
                    break
            if not role:
                response = {'message':'Invalid role.', 'status':False}
                return self.build_response(False, response)
            if not token_type:
                token_type = self._role_device_token_types(role)[0]
            refused = self._device_token_refused(user, role, token_type)
            if refused:
                return self.build_response(False, {'message': refused, 'status': False})
            remote_args = dict(command_args)
            remote_args['device_name'] = device_name
            remote_args['role_uuid'] = role_uuid
            remote_args['token_type'] = token_type
            # Drop any caller-supplied token_name — the remote derives
            # it authoritatively from the role's suffix.
            remote_args.pop('token_name', None)
            status, remote_resp = self._remote_ssod_call(user=user,
                                                    command="sso_create_device_token",
                                                    extra_args=remote_args,
                                                    mgmt=True)
            if not status or not isinstance(remote_resp, dict):
                return self.build_response(False, remote_resp)
            reveal = {x: remote_resp[x]
                    for x in ('password', 'secret', 'qrcode_img')
                    if remote_resp.get(x)}
            token_full_oid = remote_resp.get('token_full_oid')
            token_oc = remote_resp.get('token_oc')
            confirmed_role_uuid = remote_resp.get('role_uuid')
            if not token_full_oid or not token_oc or not confirmed_role_uuid:
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
            # Final name (incl. suffix) comes from the mirrored object —
            # the remote is authoritative.
            token_name = token.name
            user.add_token(new_token=token,
                        no_token_infos=True,
                        force=True,
                        verify_acls=False,
                        run_policies=True,
                        callback=callback)
            user._write(callback=callback)
            # Load the role (UUID confirmed by remote) for the local
            # add-to-role step.
            role = backend.get_object(object_type="role", uuid=confirmed_role_uuid)
            if not role:
                return self.build_response(False, {'message':'device_token_roles role not found locally.', 'status':False})
        else:
            # Validate the requested role_uuid against what this portal
            # offers the user -- their own cascade, narrowed to the
            # roles of this site.
            for candidate in self._resolve_device_token_roles(user, command_args):
                if candidate.uuid == role_uuid:
                    role = candidate
                    break
            if not role:
                response = {'message':'Invalid role.', 'status':False}
                return self.build_response(False, response)
            # Append the role's device_token_suffix to disambiguate
            # tokens that belong to different device_token_roles (e.g.
            # "device-iphone-wlan" vs "device-iphone-vpn"). Roles
            # without a suffix are hidden from list_device_tokens, so
            # a missing suffix here means a race against an admin
            # config change — surface it as a hard error.
            suffix = role.get_config_parameter("device_token_suffix")
            if not suffix:
                response = {'message':'Role has no device_token_suffix configured.', 'status':False}
                return self.build_response(False, response)
            token_name = f"{sanitized}-{suffix}"
            if user.token(token_name):
                response = {'message':'A device with this name already exists.', 'status':False}
                return self.build_response(False, response)
            if not token_type:
                token_type = self._role_device_token_types(role)[0]
            refused = self._device_token_refused(user, role, token_type)
            if refused:
                return self.build_response(False, {'message': refused, 'status': False})
            try:
                _token, reveal = self._local_create_device_token(user=user,
                                                    token_name=token_name,
                                                    device_name=device_name,
                                                    token_type=token_type,
                                                    callback=callback)
            except Exception as e:
                log_msg = _("Failed to add device token for user '{user_name}': {e}", log=True)[1]
                log_msg = log_msg.format(user_name=user.name, e=e)
                self.logger.warning(log_msg)
                response = {'message':f'Failed to add device token: {e}', 'status':False}
                return self.build_response(False, response)
        # Add the token to the chosen role on this node. role._write()
        # propagates the change back to the role's home site via the cluster.
        token_path = f"{user.name}/{token_name}"
        try:
            role.add_token(token_path=token_path,
                            force=True,
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
                    add_to_trash = self._add_to_trash(user, "add_device_token_to_trash")
                    user.del_token(token_name=token_name,
                                    force=True,
                                    verify_acls=False,
                                    run_policies=True,
                                    add_to_trash=add_to_trash,
                                    callback=callback)
                    user._write(callback=callback)
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
                    'token_type'    : token_type,
                }
        # Shown once: the password, or the TOTP secret and its QR code.
        response.update(reveal)
        return self.build_response(True, response)

    def del_device_token(self, username, sso_jwt, command_args):
        try:
            token_name = command_args['token_name']
        except Exception:
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(False, message)
        # Verify SSO jwt.
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            auth_response = {'message':'JWT_INVALID', 'status':False}
            return self.build_response(False, auth_response)
        roles = self._resolve_device_token_roles(user, command_args)
        if not roles:
            response = {'message':'device_token_roles is not configured.', 'status':False}
            return self.build_response(False, response)
        token = user.token(token_name)
        if not token:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        if token.owner_uuid != user.uuid:
            response = {'message':'UNKNOWN_TOKEN', 'status':False}
            return self.build_response(False, response)
        # Only allow deletion of tokens that are part of any configured
        # device_token_roles role.
        if not any(token.uuid in role.tokens for role in roles):
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
            add_to_trash = False
        else:
            add_to_trash = self._add_to_trash(user, "add_device_token_to_trash")
        # We need to delete device token even if user is from other site.
        try:
            user.del_token(token_name=token_name,
                            force=True,
                            verify_acls=False,
                            run_policies=True,
                            add_to_trash=add_to_trash,
                            callback=callback)
            user._write(callback=callback)
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

    def enable_device_token(self, username, sso_jwt, command_args):
        return self._set_device_token_enabled(username, sso_jwt,
                                                command_args, enable=True)

    def disable_device_token(self, username, sso_jwt, command_args):
        return self._set_device_token_enabled(username, sso_jwt,
                                                command_args, enable=False)

    def _set_device_token_enabled(self, username, sso_jwt, command_args, enable):
        """ Flip the ``enabled`` flag on a device token.

        Mirrors the sso_create_device_token cross-site pattern:

          * Originator (foreign user): validate that the token belongs
            to a role this portal offers the user, then forward to the
            user's home site for the write.
          * Home (peer-forwarded): validate the same thing again. It
            resolves to the same answer on both ends -- the user's
            cascade is read here either way, and the portal's trust
            list travels as portal_site -- so there is nothing to take
            on the peer's word.
          * Local user: resolve + validate on this site.

        Enable/disable propagates via the normal cluster sync, so no
        separate mirror step is required beyond the home-site mutation. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})

        token = user.token(token_name)
        if not token or token.owner_uuid != user.uuid:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})
        if token.token_type not in DEVICE_TOKEN_TYPES:
            return self.build_response(False,
                            {'message':'Not a device token.', 'status':False})

        roles = self._resolve_device_token_roles(user, command_args)
        if not any(token.uuid in role.tokens for role in roles):
            return self.build_response(False,
                            {'message':'Not a device token.', 'status':False})

        # Refuse to disable the token the caller is currently signed in with.
        # See del_passkey for the rationale — the JWT would still carry the
        # token's UUID and the next request would fail verify_sso_jwt.
        if not enable and _is_current_token(token):
            return self.build_response(False, {
                'message': 'Cannot disable the device token you are currently '
                           'signed in with. Sign in with another factor first.',
                'status': False})

        # Originator with foreign user: forward to home for the actual
        # mutation now that role membership has been validated locally.
        if user.site != config.site:
            remote_command = "enable_device_token" if enable else "disable_device_token"
            return self.ssod_redirect_command(command=remote_command,
                                            user=user,
                                            command_args=command_args,
                                            mgmt=True)

        callback = self.get_callback()
        callback.raise_exception = True
        try:
            if enable:
                token.enable(force=True, verify_acls=False, callback=callback)
            else:
                token.disable(force=True, verify_acls=False, callback=callback)
            token._write(callback=callback)
        except Exception as e:
            action = "enable" if enable else "disable"
            log_msg = _("Failed to {action} device token '{token}' for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(action=action, token=token_name,
                                    user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':f'Failed to update device token: {e}',
                     'status':False})
        log_msg = _("Device token '{token}' {state} for user '{user_name}'.",
                    log=True)[1]
        log_msg = log_msg.format(token=token_name,
                                state=("enabled" if enable else "disabled"),
                                user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True,
                {'status': True, 'enabled': bool(token.enabled)})

    def enable_passkey(self, username, sso_jwt, command_args):
        return self._set_passkey_enabled(username, sso_jwt,
                                        command_args, enable=True)

    def disable_passkey(self, username, sso_jwt, command_args):
        return self._set_passkey_enabled(username, sso_jwt,
                                        command_args, enable=False)

    def _set_passkey_enabled(self, username, sso_jwt, command_args, enable):
        """ Flip the ``enabled`` flag on a passkey token.

        Mirrors the list_passkeys / passkey_register_begin cross-site
        pattern:

          * Originator (foreign user): resolve ``sso_allow_passkeys``
            locally (honours ``sso_allow_passkeys_trusts``), then forward
            to the user's home site with the ``_passkeys_allowed`` marker.
          * Home (peer-forwarded): accept the originator's decision only
            when the peer's site is listed in the local
            ``sso_allow_passkeys_trusts`` (reciprocal).
          * Local user: resolve locally. """
        try:
            token_name = command_args['token_name']
        except Exception:
            return self.build_response(False, "SSOD_INCOMPLETE_COMMAND")
        try:
            user = self.verify_sso_jwt(username, sso_jwt)
        except Exception as e:
            log_msg = _("SSO JWT verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                            {'message':'JWT_INVALID', 'status':False})

        peer_allowed = command_args.get('_passkeys_allowed')

        if self._from_other_site_node():
            # Home, peer-forwarded. Accept the originator's decision only
            # when reciprocally trusted.
            if not self._site_trusts_site_for_passkeys(self.peer.site):
                self._log_passkey_denied("set_passkey_enabled",
                                    "peer site not in sso_allow_passkeys_trusts",
                                    user)
                return self.build_response(False, {
                    'message': 'Passkey modification not available: peer site '
                               'is not listed in sso_allow_passkeys_trusts.',
                    'status': False})
            if not bool(peer_allowed):
                self._log_passkey_denied("set_passkey_enabled",
                                    "originator said not allowed", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})
        else:
            # Originator (foreign user) or local user: check local policy.
            if not self._resolve_passkeys_allowed(user):
                self._log_passkey_denied("set_passkey_enabled",
                                    "sso_allow_passkeys", user)
                return self.build_response(False,
                        {'message':'Passkeys are not enabled.', 'status':False})

        token = self._get_user_passkey(user, token_name, command_args)
        if not token or token.owner_uuid != user.uuid:
            return self.build_response(False,
                            {'message':'UNKNOWN_TOKEN', 'status':False})

        # Refuse to disable the passkey the caller is currently signed in with.
        if not enable and _is_current_token(token):
            return self.build_response(False, {
                'message': 'Cannot disable the passkey you are currently '
                           'signed in with. Sign in with another factor first.',
                'status': False})

        # Originator with foreign user: forward to home for the mutation.
        if user.site != config.site:
            forward_args = dict(command_args)
            forward_args['_passkeys_allowed'] = True
            remote_command = "enable_passkey" if enable else "disable_passkey"
            return self.ssod_redirect_command(command=remote_command,
                                            user=user,
                                            command_args=forward_args,
                                            mgmt=True)

        callback = self.get_callback()
        callback.raise_exception = True
        try:
            if enable:
                token.enable(force=True, verify_acls=False, callback=callback)
            else:
                token.disable(force=True, verify_acls=False, callback=callback)
            token._write(callback=callback)
        except Exception as e:
            action = "enable" if enable else "disable"
            log_msg = _("Failed to {action} passkey '{token}' for user '{user_name}': {e}", log=True)[1]
            log_msg = log_msg.format(action=action, token=token_name,
                                    user_name=user.name, e=e)
            self.logger.warning(log_msg)
            return self.build_response(False,
                    {'message':f'Failed to update passkey: {e}', 'status':False})
        log_msg = _("Passkey '{token}' {state} for user '{user_name}'.",
                    log=True)[1]
        log_msg = log_msg.format(token=token_name,
                                state=("enabled" if enable else "disabled"),
                                user_name=user.name)
        self.logger.info(log_msg)
        return self.build_response(True,
                {'status': True, 'enabled': bool(token.enabled)})

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
          1. Parent SSO session's ``reauth_time`` -- set by the
             step-up auth flow (OIDC ``prompt=login`` / ``max_age``).
             Takes precedence over creation_time when present so RPs
             requesting fresh auth get the post-step-up timestamp.
          2. Parent SSO session's ``creation_time`` -- the actual
             user login moment (best truth when no step-up happened).
          3. OIDCSession's own ``creation_time`` -- the OIDC flow
             happened then, so user auth must be at-or-before this.
             Acceptable lower bound; still a real freshness indicator.
          4. ``None`` -- truly unknown, nothing to claim.

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
                parent = parents[0]
                rt = getattr(parent, 'reauth_time', None)
                if rt:
                    return int(rt)
                ct = getattr(parent, 'creation_time', None)
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
            msg = _("Site '{site}' has no oidc_pairwise_secret. Run 'otpme-site change_oidc_pairwise_secret' or re-run enable_oidc.")
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
            # ``picture`` per OIDC Core 1.0 §5.4 (part of profile scope).
            # We point at the public /oidc/avatar/<uuid>.jpg endpoint
            # (served by oidc_avatar) instead of inlining the photo as
            # a data: URI. Inline data: URIs blow past gunicorn's
            # request-line limit when the ID Token is round-tripped
            # via ``/end_session?id_token_hint=...`` and bloat
            # cookies. The endpoint is public, with the user UUID as
            # the obscurity guard.
            site_obj = None
            if read_photo(user.uuid):
                site_obj = backend.get_object(object_type="site",
                                              uuid=config.site_uuid)
                if site_obj is not None and getattr(site_obj, 'sso_fqdn', None):
                    claims['picture'] = (
                        f"https://{site_obj.sso_fqdn}"
                        f"/oidc/avatar/{user.uuid}.jpg"
                    )
            # Remaining profile claims per OIDC Core 1.0 §5.4. Emit
            # whatever the user has populated; missing claims are
            # omitted (per spec). Only those we can populate from
            # OTPme/LDAP attributes are advertised in
            # ``claims_supported``; gender/birthdate/zoneinfo/profile
            # are deliberately absent.
            middle = _first('initials')  # LDAP "initials" carries middle name(s)
            if middle:
                claims['middle_name'] = middle
            nickname = _first('displayName')
            if nickname and nickname != cn:
                claims['nickname'] = nickname
            website = _first('labeledURI') or _first('wWWHomePage')
            if website:
                claims['website'] = website
            # Locale only honored when the user explicitly set it
            # (otherwise it's the en default and not user intent).
            if getattr(user, 'language_set', False):
                lang = getattr(user, 'language', None)
                if lang:
                    claims['locale'] = lang
            # ``updated_at`` per OIDC Core §5.1: seconds since epoch
            # when the user's profile was last modified.
            try:
                lm = getattr(user, 'last_modified', None)
                if lm:
                    claims['updated_at'] = int(lm)
            except Exception:
                pass
            # Not emitted (OTPme has no native mapping):
            #   profile (URL to a human-readable profile page),
            #   gender, birthdate, zoneinfo.
            # If a deployment uses custom attributes for any of these,
            # a future config-param mapping could surface them.
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
            # ``email_verified`` is not emitted -- OTPme doesn't track
            # verification state. RPs that care should treat the
            # absence as "unknown" rather than "false".
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
        responsible for (sub, auth_time, amr, acr). Infrastructure
        claims (iss/aud/iat/exp/jti/sid/nonce) and at_hash live on
        OIDCSession.build_id_token.

        Per OIDC Core 1.0 §5.4, scope-requested user claims (profile,
        email, phone, address) are returned ONLY from /userinfo in
        the Authorization Code Flow -- they do NOT belong in the ID
        Token. Including them would leak PII into a token that's
        often forwarded as proof-of-auth to other parties (Logout,
        federations), and is flagged by the OIDC conformance suite
        (EnsureIdTokenDoesNotContainEmailForScopeEmail).

        Spec: OIDC Core 1.0 §2 "ID Token" (claim set: iss, sub, aud,
          exp, iat, auth_time, nonce, acr, amr, azp)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        Spec: OIDC Core 1.0 §5.4 "Requesting Claims using Scope Values"
          (Code Flow: scope claims are returned only from UserInfo)
          https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
        """
        claims = {
            "sub": self._compute_oidc_sub(user, client, site),
        }

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

        # Some RPs never call /userinfo and read the ID Token alone
        # (Nextcloud user_oidc does). For those the client can have the
        # user claims put in here as well, see oidc_id_token_user_claims.
        # They never replace one of the claims above.
        if self._id_token_user_claims(client):
            user_claims = self._get_user_claims(user, oidc_session.scope,
                                                client=client)
            for k, v in (user_claims or {}).items():
                if k in claims:
                    continue
                claims[k] = v

        return claims

    def _id_token_user_claims(self, client):
        """ Resolve oidc_id_token_user_claims via the Site/Unit/Client
        config-param hierarchy. Off when unset or unreadable: the spec
        conform answer is the default. """
        try:
            return bool(client.get_config_parameter("oidc_id_token_user_claims"))
        except Exception:
            return False

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
            # Active index missed -- check the burn index. A hit
            # there means the code was already used successfully and
            # someone is replaying it. RFC 6749 §4.1.2 says we MUST
            # deny AND SHOULD revoke the tokens issued under that
            # code, so we delete the entire OIDCSession.
            #   https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
            burned = backend.search(object_type="session",
                                    attribute="burned_authcode_hash",
                                    value=code_hash,
                                    return_type="instance")
            if burned:
                replayed_session = burned[0]
                # Cross-client guard: only act if the calling client
                # actually owns the session; otherwise a malicious
                # client could weaponize this to nuke another
                # client's session via a captured code.
                if replayed_session.client == client.uuid:
                    sid = replayed_session.session_id
                    try:
                        replayed_session.delete(force=True,
                                                 verify_acls=False)
                    except Exception as e:
                        log_msg = _("Failed to invalidate OIDC session '{sid}' on code replay: {err}", log=True)[1]
                        log_msg = log_msg.format(sid=sid, err=e)
                        self.logger.warning(log_msg)
                    emit_audit("OIDC", 'authcode_replay_detected',
                                    level='warning',
                                    client=client_id,
                                    session=sid,
                                    ip=client_ip)
                else:
                    emit_audit("OIDC", 'authcode_replay_cross_client',
                                    level='warning',
                                    client=client_id,
                                    session=replayed_session.session_id,
                                    ip=client_ip)
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
                        log_msg = _("Failed to invalidate replayed OIDC session '{sid}': {err}", log=True)[1]
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
            log_msg = _("Failed to issue tokens / build ID Token (refresh): {err}", log=True)[1]
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
        # introspected either by the client it was issued to, or by
        # a peer client in the same accessgroup. The same-AG path
        # covers the resource-server pattern (IMAP/POP/SMTP servers
        # validating tokens issued to mail clients) without forcing
        # callers to share a client_id.
        if oidc_session.client != client.uuid:
            same_ag = (client.access_group_uuid
                       and oidc_session.access_group_uuid
                       and client.access_group_uuid == oidc_session.access_group_uuid)
            if not same_ag:
                emit_audit("OIDC", 'introspect_cross_client',
                                level='warning',
                                client=client_id,
                                session=oidc_session.session_id,
                                token_kind=token_kind,
                                ip=client_ip)
                return self.build_response(True, {'active': False})
            emit_audit("OIDC", 'introspect_same_ag',
                            client=client_id,
                            session=oidc_session.session_id,
                            token_kind=token_kind,
                            access_group=client.access_group,
                            ip=client_ip)

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
        hintless_username = command_args.get("username")

        log_msg = _("OIDC end_session from {ip} for client '{cid}'.", log=True)[1]
        log_msg = log_msg.format(ip=client_ip or "?", cid=client_id or "?")
        self.logger.info(log_msg)

        # Hintless path: per OIDC RP-Initiated Logout 1.0 §2,
        # id_token_hint is RECOMMENDED, not REQUIRED. If the web layer
        # identified the user via the browser session, fall back to
        # SSO-scope logout (RP-scope needs the hint's sid).
        sid = None
        hint_aud = None
        if not id_token_hint:
            if not hintless_username:
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
            emit_audit("OIDC", 'end_session_no_hint',
                            client=client_id or '?',
                            username=hintless_username,
                            ip=client_ip)
        else:
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

        if client_id and hint_aud and client_id != hint_aud:
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

        # Hintless + no client_id query param: we can't validate the
        # post_logout_redirect_uri without a client. Defer to /logout
        # (SSO-scope) and let the web layer show the generic
        # logged-out page.
        if client_id is None:
            emit_audit("OIDC", 'end_session_sso_deferred_no_client',
                            username=hintless_username,
                            ip=client_ip)
            return self.build_response(True, {
                'scope': 'sso',
                'action': 'redirect_logout',
            })

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
        # RP-scope needs the hint's sid to identify the specific
        # OIDCSession to terminate. Without a hint, force SSO-scope.
        if sid is None and scope_mode == "rp":
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
            return self.build_response(False, 'SSOD_INCOMPLETE_COMMAND')
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
        # OIDC Core §3.1.2.1: ``max_age=N`` requires the End-User to
        # have been authenticated within the last N seconds; otherwise
        # the OP MUST actively re-authenticate. We signal the web
        # layer via REAUTH_REQUIRED so it can route through /reauth
        # (same mechanism as prompt=login).
        max_age_raw = command_args.get("max_age")
        max_age = None
        if max_age_raw not in (None, ""):
            try:
                max_age = int(max_age_raw)
                if max_age < 0:
                    raise ValueError("negative")
            except (TypeError, ValueError):
                return self.build_response(False, {
                    'error':             'invalid_request',
                    'error_description': f"max_age not a non-negative integer: {max_age_raw}",
                    'can_redirect':      True,
                })
        if max_age is not None:
            auth_time = (getattr(session, 'reauth_time', None)
                         or getattr(session, 'creation_time', None))
            now = time.time()
            if auth_time is None or (now - int(auth_time)) > max_age:
                log_msg = _("max_age={ma}s exceeded for session '{sid}' (age={age}s); requesting reauth.",
                            log=True)[1]
                log_msg = log_msg.format(
                            ma=max_age,
                            sid=session.session_id,
                            age=(int(now - int(auth_time))
                                 if auth_time else 'unknown'))
                self.logger.info(log_msg)
                return self.build_response(False, {
                    'message': 'REAUTH_REQUIRED',
                    'status':  False,
                })
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
        # OIDC Core §6.1 / RFC 9101 (JAR): we don't implement the
        # ``request`` / ``request_uri`` parameters. Per OIDC Core
        # §3.1.2.6 reject with the dedicated error codes (not
        # ``invalid_request``) so RPs can fall back cleanly. Discovery
        # also advertises both as unsupported.
        if command_args.get("request"):
            return _err('request_not_supported',
                        "request object parameter not supported",
                        can_redirect=True)
        if command_args.get("request_uri"):
            return _err('request_uri_not_supported',
                        "request_uri parameter not supported",
                        can_redirect=True)
        #if response_type != "code":
        #    return _err('unsupported_response_type',
        #                f"response_type '{response_type}' not supported",
        #                can_redirect=True)
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
            require_consent = client.get_config_parameter("oidc_require_consent")
        except Exception:
            require_consent = False
        force_consent = "consent" in prompt_values
        if force_consent or require_consent:
            # Consent state is authoritative on the user's home site.
            # For a foreign user we read it via a targeted RPC -- the
            # OP stays local because the OIDC client and access group
            # are registered here, only the per-(user,client) consent
            # record lives on home.
            if user.site != config.site:
                ok, remote_resp = self._remote_ssod_call(
                        user=user,
                        command="oidc_get_consent_for_client",
                        extra_args={
                            'username':    username,
                            'sso_jwt':     sso_jwt,
                            'client_uuid': client.uuid,
                        })
                if not ok:
                    msg = (remote_resp.get('message')
                           if isinstance(remote_resp, dict) else None) \
                          or 'unknown'
                    return _err('server_error',
                                f"failed to read consent from home site: {msg}",
                                can_redirect=True)
                stored = (remote_resp.get('consent')
                          if isinstance(remote_resp, dict) else None) or {}
            else:
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
                    log_msg = _("Failed to compute claims preview for consent screen: {err}", log=True)[1]
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
                if user.site != config.site:
                    ok, remote_resp = self._remote_ssod_call(
                            user=user,
                            command="oidc_set_consent_for_client",
                            extra_args={
                                'username':    username,
                                'sso_jwt':     sso_jwt,
                                'client_uuid': client.uuid,
                                'scopes':      sorted(requested_scopes),
                            },
                            mgmt=True)
                    if not ok:
                        # Persistence failed on home -- log and continue.
                        # Authorize keeps going (the user did click Allow)
                        # but they'll be re-prompted on the next request.
                        msg = (remote_resp.get('message')
                               if isinstance(remote_resp, dict) else None) \
                              or 'unknown'
                        log_msg = _("Failed to persist OIDC consent on home site for user '{user}' / client '{cid}': {err}", log=True)[1]
                        log_msg = log_msg.format(user=user.name,
                                                  cid=client_id, err=msg)
                        self.logger.warning(log_msg)
                else:
                    user.set_oidc_consent(client.uuid, requested_scopes)
                    try:
                        user._write(callback=self.get_callback())
                    except Exception as e:
                        log_msg = _("Failed to persist OIDC consent for user '{user}' / client '{cid}': {err}", log=True)[1]
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
        try:
            sotp_data = self.gen_sotp(user, ag_uuid, session.pass_hash)
        except UnknownAccessgroup:
            emit_audit("SSO", "oidc_authorize_validate_failed",
                       level='warning',
                       user=user.name,
                       ag=client_ag,
                       reason='no_ag_permissions',
                       ip=client_ip)
            return _err('server_error', f"unknown access_group '{client_ag}'",
                        can_redirect=False)
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
                # Infrastructure / ID-Token claims.
                "sub", "iss", "aud", "iat", "exp", "jti", "sid",
                "auth_time", "nonce", "acr", "amr", "azp",
                # ``profile`` scope claims we MAY emit. Not all
                # listed claims are guaranteed -- emission depends on
                # whether the underlying user attribute is populated.
                "name", "given_name", "family_name", "middle_name",
                "nickname", "preferred_username", "picture", "website",
                "locale", "updated_at",
                # ``email`` scope.
                "email",
                # ``phone`` scope.
                "phone_number",
                # ``address`` scope (composite claim).
                "address",
                # Non-standard but widely supported by NextCloud,
                # Grafana, Authentik, ...
                "groups",
            ],
            # OIDC Core §6.1 / RFC 9101 (JAR) "request" / "request_uri"
            # parameters are not implemented. Advertise both flags as
            # false (rather than relying on the default) so RPs don't
            # try to use them and the conformance suite is satisfied.
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "require_request_uri_registration": False,
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

    def oidc_avatar(self, command_args):
        """ Serve a user's avatar (jpegPhoto) as base64 JPEG.

        Public, unauthenticated endpoint -- the user UUID in the URL
        is the obscurity guard (UUIDs aren't enumerable and the
        ``picture`` claim is only minted into tokens that already
        identify the user). Used by RPs (e.g. Nextcloud user_oidc)
        that follow ``claims.picture`` as a downloadable URL instead
        of consuming a data: URI inline.

        Returns ``{'photo': '<base64 jpeg>'}`` on success, 404-ish
        error otherwise. The web layer decodes and serves with
        Content-Type: image/jpeg.
        """
        user_uuid = command_args.get("user_uuid")
        if not user_uuid:
            return self.build_response(False, {
                'error': 'not_found',
            })
        # Straight from the photo object, without loading the user: the
        # UUID is all read_photo() needs, and it refuses anything else.
        photo = read_photo(user_uuid)
        if not photo:
            return self.build_response(False, {
                'error': 'not_found',
            })
        return self.build_response(True, {'photo': photo})

    def oidc_prompt_none_no_session(self, command_args):
        """ Validate that ``redirect_uri`` is registered for
        ``client_id`` so the web layer can safely redirect a
        ``prompt=none`` request back with ``error=login_required``
        when the user has no active SSO session.

        Spec: OIDC Core 1.0 §3.1.2.6 "Authentication Error Response"
          (login_required: ``prompt=none`` but the End-User is not
          authenticated and an authentication is required)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthError
        """
        client_id = command_args.get('client_id')
        redirect_uri = command_args.get('redirect_uri')
        if not client_id or not redirect_uri:
            return self.build_response(True, {'valid': False})
        client = backend.get_object(object_type="client",
                                    name=client_id,
                                    realm=config.realm,
                                    site=config.site)
        if client is None or not getattr(client, 'oidc_auth', False):
            return self.build_response(True, {'valid': False})
        allowed = getattr(client, 'oidc_redirect_uris', []) or []
        if redirect_uri not in allowed:
            return self.build_response(True, {'valid': False})
        return self.build_response(True, {'valid': True})

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
        # Per request: the SSO session the browser names, taken over by
        # verify_sso_jwt() once it is checked. Reset first, or a request
        # without one would be logged with the previous one's session.
        config.auth_session = None
        config.auth_session_id = None
        self._request_session_uuid = None
        if isinstance(command_args, dict):
            self._request_session_uuid = command_args.get('session_uuid')
        # Many commands write objects (e.g. adding a token). So we have to
        # prevent a master failover and a service shutdown (e.g. node
        # disable) while we handle the command. On an already running
        # failover/shutdown we must not add a blocker. The command is
        # refused below (cluster status check) and a blocker would prevent
        # a second failover/shutdown request.
        blocker_name = f"SSO: {command}"
        failover_blocker_id = None
        if not config.master_failover:
            failover_blocker_id = multiprocessing.add_master_failover_blocker(blocker_name)
        shutdown_blocker_id = None
        if not config.service_shutdown:
            shutdown_blocker_id = multiprocessing.add_service_shutdown_blocker(blocker_name)
        try:
            return self._process_command(command, command_args, **kwargs)
        finally:
            if failover_blocker_id is not None:
                multiprocessing.del_master_failover_blocker(failover_blocker_id)
            if shutdown_blocker_id is not None:
                multiprocessing.del_service_shutdown_blocker(shutdown_blocker_id)

    def _process_command(self, command, command_args, **kwargs):
        """ Handle SSO commands received from client. """
        # All valid commands.
        valid_commands = [
                            "get_apps",
                            "get_sotp",
                            "deploy_begin",
                            "deploy_verify",
                            "get_allowed_deploy_token_types",
                            "get_login_token_options",
                            "change_password",
                            "change_pin",
                            "change_language",
                            "resolve_user_language",
                            "fido2_register_begin",
                            "fido2_register_complete",
                            "list_fido2_tokens",
                            "fido2_add_begin",
                            "fido2_add_complete",
                            "del_fido2_token",
                            "enable_fido2_token",
                            "disable_fido2_token",
                            "list_passkeys",
                            "passkey_register_begin",
                            "passkey_register_complete",
                            "del_passkey",
                            "tiqr_enroll_begin",
                            "tiqr_enroll_metadata",
                            "tiqr_enroll_finish",
                            "list_tiqr_tokens",
                            "del_tiqr_token",
                            "enable_tiqr_token",
                            "disable_tiqr_token",
                            "totp_enroll_begin",
                            "totp_enroll_verify",
                            "list_totp_tokens",
                            "del_totp_token",
                            "enable_totp_token",
                            "disable_totp_token",
                            "change_totp_pin",
                            "promote_token",
                            "list_device_tokens",
                            "add_device_token",
                            "del_device_token",
                            "enable_device_token",
                            "disable_device_token",
                            "enable_passkey",
                            "disable_passkey",
                            "sso_create_device_token",
                            "sso_delete_device_token",
                            "sso_get_device_token_role_uuids",
                            "get_admin_access_state",
                            "set_admin_access_state",
                            "get_recovery_mail",
                            "set_recovery_mail",
                            "get_step_up_state",
                            "request_sso_token_recovery",
                            "get_sso_token_recovery_info",
                            "recovery_deploy_begin",
                            "recovery_deploy_verify",
                            "recovery_fido2_register_begin",
                            "recovery_fido2_register_complete",
                            "oidc_token",
                            "oidc_userinfo",
                            "oidc_introspect",
                            "oidc_revoke",
                            "oidc_end_session",
                            "oidc_discovery",
                            "oidc_jwks",
                            "oidc_avatar",
                            "oidc_prompt_none_no_session",
                            "oidc_authorize_validate",
                            "list_oidc_consents",
                            "revoke_oidc_consent",
                            "oidc_get_consent_for_client",
                            "oidc_set_consent_for_client",
                            "list_sessions",
                            "delete_session",
                        ]

        # The phone talks to us without a session: the signed grant it
        # presents is the authorisation. Same bypass of the
        # username/sso_jwt envelope as the OIDC commands below.
        tiqr_device_commands = ("tiqr_enroll_metadata", "tiqr_enroll_finish")

        # OIDC commands are server-to-server (or browser-to-server
        # for end_session); the user-facing username/sso_jwt
        # envelope is bypassed for them.
        oidc_commands = ("oidc_token", "oidc_userinfo",
                         "oidc_introspect", "oidc_revoke",
                         "oidc_end_session",
                         "oidc_discovery", "oidc_jwks",
                         "oidc_avatar",
                         "oidc_prompt_none_no_session")

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

        if command in tiqr_device_commands:
            log_msg = _("Processing tiqr device command {command}.", log=True)[1]
            log_msg = log_msg.format(command=command)
            self.logger.info(log_msg)
            if command == "tiqr_enroll_metadata":
                return self.tiqr_enroll_metadata(command_args)
            if command == "tiqr_enroll_finish":
                return self.tiqr_enroll_finish(command_args)

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
            if command == "oidc_avatar":
                return self.oidc_avatar(command_args)
            if command == "oidc_prompt_none_no_session":
                return self.oidc_prompt_none_no_session(command_args)

        # SSO-token recovery commands are unauth by design ("forgot my
        # token" flow): the caller cannot present an SSO JWT because
        # the whole point is that they have no valid credential.
        # Bypass the username/sso_jwt envelope check below; the
        # handlers do their own input validation and enum-safe
        # response shaping.
        recovery_commands = ("request_sso_token_recovery",
                             "get_sso_token_recovery_info",
                             "recovery_deploy_begin",
                             "recovery_deploy_verify",
                             "recovery_fido2_register_begin",
                             "recovery_fido2_register_complete")
        if command in recovery_commands:
            # Reconfigure the per-connection logger (child fork inherits
            # a pre-connect logger that swallows records). set_proctitle
            # is what does that in the authed paths; recovery skips the
            # sso_jwt/username envelope, so we call it here explicitly
            # with the requested-username (or the command name if the
            # client sent no username) so DEBUG/INFO from the recovery
            # handler is actually written.
            recovery_username = command_args.get('username', '')
            self.set_proctitle(recovery_username or command)
            log_msg = _("Processing recovery command {command}.", log=True)[1]
            log_msg = log_msg.format(command=command)
            self.logger.info(log_msg)
            if command == "request_sso_token_recovery":
                return self.request_sso_token_recovery(recovery_username,
                                                       None, command_args)
            if command == "get_sso_token_recovery_info":
                return self.get_sso_token_recovery_info(recovery_username,
                                                       None, command_args)
            if command == "recovery_deploy_begin":
                return self.recovery_deploy_begin(recovery_username,
                                                  None, command_args)
            if command == "recovery_deploy_verify":
                return self.recovery_deploy_verify(recovery_username,
                                                   None, command_args)
            if command == "recovery_fido2_register_begin":
                return self.recovery_fido2_register_begin(recovery_username,
                                                          None, command_args)
            if command == "recovery_fido2_register_complete":
                return self.recovery_fido2_register_complete(recovery_username,
                                                             None, command_args)

        # Try to get username.
        try:
            username = command_args['username']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)

        # Set proctitle to contain username.
        self.set_proctitle(username)

        try:
            sso_jwt = command_args['sso_jwt']
        except Exception:
            status = False
            message = "SSOD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)

        # session_uuid is only meaningful when the request originates
        # from the SSO portal (web frontend / CLI). Cross-site ssod-to-
        # ssod redirects strip it -- the originating ssod has already
        # verified the session, and the foreign backend wouldn't see it.
        session_uuid = command_args.get('session_uuid')
        if session_uuid:
            session = backend.get_object(uuid=session_uuid)
            if not session:
                return self.build_response(False, {
                    'message': 'UNKNOWN_SESSION', 'status': False,
                })

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

        if command == "get_allowed_deploy_token_types":
            log_msg = _("Processing command get_allowed_deploy_token_types.", log=True)[1]
            self.logger.info(log_msg)
            return self.get_allowed_deploy_token_types(username, sso_jwt, command_args)

        if command == "get_login_token_options":
            log_msg = _("Processing command get_login_token_options.", log=True)[1]
            self.logger.debug(log_msg)
            return self.get_login_token_options(username, sso_jwt, command_args)

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

        if command == "resolve_user_language":
            log_msg = _("Processing command resolve_user_language.", log=True)[1]
            self.logger.info(log_msg)
            return self.resolve_user_language(username, sso_jwt, command_args)

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

        if command == "enable_device_token":
            log_msg = _("Processing command enable_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.enable_device_token(username, sso_jwt, command_args)

        if command == "disable_device_token":
            log_msg = _("Processing command disable_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.disable_device_token(username, sso_jwt, command_args)

        if command == "sso_create_device_token":
            log_msg = _("Processing command sso_create_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.sso_create_device_token(username, sso_jwt, command_args)

        if command == "sso_delete_device_token":
            log_msg = _("Processing command sso_delete_device_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.sso_delete_device_token(username, sso_jwt, command_args)

        if command == "sso_get_device_token_role_uuids":
            log_msg = _("Processing command sso_get_device_token_role_uuids.", log=True)[1]
            self.logger.info(log_msg)
            return self.sso_get_device_token_role_uuids(username, sso_jwt, command_args)

        if command == "get_admin_access_state":
            log_msg = _("Processing command get_admin_access_state.", log=True)[1]
            self.logger.info(log_msg)
            return self.get_admin_access_state(username, sso_jwt, command_args)

        if command == "set_admin_access_state":
            log_msg = _("Processing command set_admin_access_state.", log=True)[1]
            self.logger.info(log_msg)
            return self.set_admin_access_state(username, sso_jwt, command_args)

        if command == "get_recovery_mail":
            log_msg = _("Processing command get_recovery_mail.", log=True)[1]
            self.logger.info(log_msg)
            return self.get_recovery_mail(username, sso_jwt, command_args)

        if command == "get_step_up_state":
            log_msg = _("Processing command get_step_up_state.", log=True)[1]
            self.logger.info(log_msg)
            return self.get_step_up_state(username, sso_jwt, command_args)

        if command == "set_recovery_mail":
            log_msg = _("Processing command set_recovery_mail.", log=True)[1]
            self.logger.info(log_msg)
            return self.set_recovery_mail(username, sso_jwt, command_args)

        if command == "list_passkeys":
            log_msg = _("Processing command list_passkeys.", log=True)[1]
            self.logger.info(log_msg)
            return self.list_passkeys(username, sso_jwt, command_args)

        if command == "list_fido2_tokens":
            log_msg = _("Processing command list_fido2_tokens.", log=True)[1]
            self.logger.debug(log_msg)
            return self.list_fido2_tokens(username, sso_jwt, command_args)

        if command == "fido2_add_begin":
            log_msg = _("Processing command fido2_add_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.fido2_add_begin(username, sso_jwt, command_args)

        if command == "fido2_add_complete":
            log_msg = _("Processing command fido2_add_complete.", log=True)[1]
            self.logger.info(log_msg)
            return self.fido2_add_complete(username, sso_jwt, command_args)

        if command == "del_fido2_token":
            log_msg = _("Processing command del_fido2_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.del_fido2_token(username, sso_jwt, command_args)

        if command == "enable_fido2_token":
            log_msg = _("Processing command enable_fido2_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.enable_fido2_token(username, sso_jwt, command_args)

        if command == "disable_fido2_token":
            log_msg = _("Processing command disable_fido2_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.disable_fido2_token(username, sso_jwt, command_args)

        if command == "tiqr_enroll_begin":
            log_msg = _("Processing command tiqr_enroll_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.tiqr_enroll_begin(username, sso_jwt, command_args)

        if command == "list_tiqr_tokens":
            log_msg = _("Processing command list_tiqr_tokens.", log=True)[1]
            self.logger.debug(log_msg)
            return self.list_tiqr_tokens(username, sso_jwt, command_args)

        if command == "del_tiqr_token":
            log_msg = _("Processing command del_tiqr_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.del_tiqr_token(username, sso_jwt, command_args)

        if command == "enable_tiqr_token":
            log_msg = _("Processing command enable_tiqr_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.enable_tiqr_token(username, sso_jwt, command_args)

        if command == "disable_tiqr_token":
            log_msg = _("Processing command disable_tiqr_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.disable_tiqr_token(username, sso_jwt, command_args)

        if command == "totp_enroll_begin":
            log_msg = _("Processing command totp_enroll_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.totp_enroll_begin(username, sso_jwt, command_args)

        if command == "totp_enroll_verify":
            log_msg = _("Processing command totp_enroll_verify.", log=True)[1]
            self.logger.info(log_msg)
            return self.totp_enroll_verify(username, sso_jwt, command_args)

        if command == "list_totp_tokens":
            log_msg = _("Processing command list_totp_tokens.", log=True)[1]
            self.logger.debug(log_msg)
            return self.list_totp_tokens(username, sso_jwt, command_args)

        if command == "del_totp_token":
            log_msg = _("Processing command del_totp_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.del_totp_token(username, sso_jwt, command_args)

        if command == "enable_totp_token":
            log_msg = _("Processing command enable_totp_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.enable_totp_token(username, sso_jwt, command_args)

        if command == "disable_totp_token":
            log_msg = _("Processing command disable_totp_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.disable_totp_token(username, sso_jwt, command_args)

        if command == "change_totp_pin":
            log_msg = _("Processing command change_totp_pin.", log=True)[1]
            self.logger.info(log_msg)
            return self.change_totp_pin(username, sso_jwt, command_args)

        if command == "promote_token":
            log_msg = _("Processing command promote_token.", log=True)[1]
            self.logger.info(log_msg)
            return self.promote_token(username, sso_jwt, command_args)

        if command == "passkey_register_begin":
            log_msg = _("Processing command passkey_register_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.passkey_register_begin(username, sso_jwt, command_args)

        if command == "passkey_register_complete":
            log_msg = _("Processing command passkey_register_complete.", log=True)[1]
            self.logger.info(log_msg)
            return self.passkey_register_complete(username, sso_jwt, command_args)

        if command == "del_passkey":
            log_msg = _("Processing command del_passkey.", log=True)[1]
            self.logger.info(log_msg)
            return self.del_passkey(username, sso_jwt, command_args)

        if command == "enable_passkey":
            log_msg = _("Processing command enable_passkey.", log=True)[1]
            self.logger.info(log_msg)
            return self.enable_passkey(username, sso_jwt, command_args)

        if command == "disable_passkey":
            log_msg = _("Processing command disable_passkey.", log=True)[1]
            self.logger.info(log_msg)
            return self.disable_passkey(username, sso_jwt, command_args)

        if command == "oidc_authorize_validate":
            log_msg = _("Processing command oidc_authorize_validate.", log=True)[1]
            self.logger.info(log_msg)
            return self.oidc_authorize_validate(username, sso_jwt, command_args)

        if command == "list_sessions":
            log_msg = _("Processing command list_sessions.", log=True)[1]
            self.logger.info(log_msg)
            return self.list_sessions(username, sso_jwt, command_args)

        if command == "delete_session":
            log_msg = _("Processing command delete_session.", log=True)[1]
            self.logger.info(log_msg)
            return self.delete_session(username, sso_jwt, command_args)

        if command == "list_oidc_consents":
            log_msg = _("Processing command list_oidc_consents.", log=True)[1]
            self.logger.info(log_msg)
            return self.list_oidc_consents(username, sso_jwt, command_args)

        if command == "revoke_oidc_consent":
            log_msg = _("Processing command revoke_oidc_consent.", log=True)[1]
            self.logger.info(log_msg)
            return self.revoke_oidc_consent(username, sso_jwt, command_args)

        if command == "oidc_get_consent_for_client":
            log_msg = _("Processing command oidc_get_consent_for_client.", log=True)[1]
            self.logger.info(log_msg)
            return self.oidc_get_consent_for_client(username, sso_jwt, command_args)

        if command == "oidc_set_consent_for_client":
            log_msg = _("Processing command oidc_set_consent_for_client.", log=True)[1]
            self.logger.info(log_msg)
            return self.oidc_set_consent_for_client(username, sso_jwt, command_args)

        return self.build_response(status, message)

    def _close(self):
        pass
