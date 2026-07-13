# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import hmac
import json
import time
import base64
import hashlib
import datetime
import setproctitle
from fido2.cose import ES256
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
from otpme.lib import jwt
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import multiprocessing
from otpme.lib.audit import emit_audit
from otpme.lib import connections
from otpme.lib.humanize import units
from otpme.lib.encoding.base import decode

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
    """ Serialize an fido2-server auth/registration state dict to a
    plain-JSON-safe form: bytes values are b64-encoded and tagged
    with a sibling ``_b_<key>=True`` marker so the round-trip can
    restore them. Used before stashing the state in the
    Redis-backed shared dict (``multiprocessing.fido2_auth_states``)
    that bridges the begin/complete HTTP roundtrip. """
    serialized = {}
    for k, v in state.items():
        if isinstance(v, bytes):
            serialized[k] = base64.b64encode(v).decode('ascii')
            serialized['_b_' + k] = True
        else:
            serialized[k] = v
    return serialized

def _deserialize_fido2_state(data):
    """ Inverse of ``_serialize_fido2_state``: rebuild the original
    state dict (bytes restored where the ``_b_<key>=True`` marker is
    present) before handing it to fido2-server's authenticate_complete /
    register_complete. """
    state = {}
    for k, v in data.items():
        if k.startswith('_b_'):
            continue
        if data.get('_b_' + k):
            state[k] = base64.b64decode(v)
        else:
            state[k] = v
    return state


def _sso_allow_passkeys_for_user(user):
    """ Home-side resolution of the ``sso_allow_passkeys`` cascade
    (user → unit → site) for the WebAuthn login path. Passkey login
    is allowed only when the cascade resolves to an explicit True;
    an unset cascade blocks. The registered default is intentionally
    NOT consulted -- if nobody set the flag, no passkey login.
    Applied to drop passkey tokens from the assertion allow-list at
    ``fido2_auth_begin`` so the browser can't sign with a passkey and
    the whole attempt falls through the generic "Login failed" path.
    Fido2 (u2f-style) tokens are unaffected. """
    try:
        return bool(user.get_config_parameter("sso_allow_passkeys"))
    except Exception:
        return False


# Per-process cache for the decoy HMAC seed -- derived from the site's
# private key once, so we don't pay export_private_key() on every
# fido2_auth_begin. Reset to None on fork; the child re-derives lazily.
_DECOY_SEED_CACHE = None
# P-256 (secp256r1) curve order. Standard NIST constant, immutable.
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _decoy_seed():
    """ Return per-site HMAC seed for /fido2/auth/begin decoy
    credentials. Derived from the site's private RSA key
    (``OTPmeRSAKey``) via DER export + SHA256. The private key is
    sync'd to authd nodes but never leaked to clients, so an attacker
    cannot compute the same decoys to distinguish them from real
    credentials -- which is the entire point of the mechanism.

    Raises OTPmeException if the site key cannot be read. No public-info
    fallback by design: a fallback based on the site UUID (or any
    other client-visible material) would let the attacker generate the
    same decoys and recognise them in responses, defeating enumeration
    resistance. """
    global _DECOY_SEED_CACHE
    if _DECOY_SEED_CACHE is not None:
        return _DECOY_SEED_CACHE
    site = backend.get_object(object_type="site", uuid=config.site_uuid)
    if site is None:
        msg = _("FIDO2 decoy seed: site object not found.")
        raise OTPmeException(msg)
    key_obj = getattr(site, '_key', None)
    if key_obj is None:
        msg = _("FIDO2 decoy seed: site private key missing.")
        raise OTPmeException(msg)
    der = key_obj.export_private_key(encoding="DER")
    _DECOY_SEED_CACHE = hashlib.sha256(
            b"otpme-fido2-decoy-v1:" + der).digest()
    return _DECOY_SEED_CACHE


def _derive_decoy_pubkey(seed, username, idx):
    """ Deterministic throwaway P-256 public key derived from
    ``(seed, username, idx)``. Same input → same key, so an attacker
    can't spot decoys by querying twice and comparing. Uses only
    documented APIs of cryptography / python-fido2; no reliance on
    python-fido2's internal COSE dict layout. """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    msg = f"fido2-decoy:{username}:{idx}".encode('utf-8')
    seed_bytes = hmac.new(seed, msg, hashlib.sha512).digest()
    # Map HMAC bytes into [1, n-1]: valid ECDSA private-key range.
    # See the math note in the commit message; we don't need
    # cryptographic strength on the scalar itself (the pubkey is just
    # a placeholder so AttestedCredentialData parses) but mapping
    # cleanly into the legal range keeps any present-or-future
    # validation in python-fido2 happy.
    scalar = (int.from_bytes(seed_bytes, 'big') % (_P256_ORDER - 1)) + 1
    priv = ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())
    return priv.public_key()


def _decoy_fido2_credentials(username, count=1):
    """ Build deterministic decoy FIDO2 credentials for /fido2/auth/begin
    so the response shape doesn't leak whether the user exists or has
    a FIDO2 token. credential_ids and the underlying public key are
    HMAC-derived from a per-site secret seed:

      * same username + same site -> same fake credential_ids (random
        variation would itself signal "user unknown"),
      * an attacker can't generate matching decoys without the secret.

    The pubkey is a valid on-curve P-256 point but with the private
    half discarded; verify naturally fails at complete-time. """
    seed = _decoy_seed()
    credentials = []
    credential_token_map = {}
    for idx in range(count):
        cred_id = hmac.new(seed,
                           f"fido2-decoy:{username}:{idx}:id".encode('utf-8'),
                           hashlib.sha256).digest()
        pub_ec = _derive_decoy_pubkey(seed, username, idx)
        pub_key = ES256.from_cryptography_key(pub_ec)
        acd = AttestedCredentialData.create(b"\0" * 16, cred_id, pub_key)
        credentials.append(acd)
        cred_id_b64 = base64.urlsafe_b64encode(cred_id).rstrip(b'=').decode()
        # Synthetic token_name keeps the complete-path's
        # matched_token_name lookup from 400-ing differently for decoy
        # vs real -- signature verify fails either way.
        credential_token_map[cred_id_b64] = f"decoy-{idx}"
    return credentials, credential_token_map


def _pad_min_duration(start, target=0.15):
    """ Sleep so the surrounding function takes at least ``target``
    seconds from ``start`` (monotonic). Equalises real vs decoy auth
    paths so an attacker can't tell apart "user unknown" / "no FIDO2"
    from "user has FIDO2" via timing. 150ms covers backend.get_object,
    token lookups and Fido2Server.authenticate_begin on a busy node. """
    elapsed = time.monotonic() - start
    if elapsed < target:
        time.sleep(target - elapsed)

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
        # Redirect user to home site.
        self.redirect_user = True
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
            except IndexError as err:
                emit_audit("AuthZ", "denied",
                           level='warning',
                           actor=token.rel_path,
                           user=username,
                           method='gen_jwt',
                           reason='invalid_access_group_name',
                           ag=access_group)
                msg = _("Invalid accessgroup name: {access_group}")
                msg = msg.format(access_group=access_group)
                raise AccessDenied(msg) from err
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=ag_name,
                                    realm=config.realm,
                                    site=ag_site)
            if not result:
                emit_audit("AuthZ", "denied",
                           level='warning',
                           actor=token.rel_path,
                           user=username,
                           method='gen_jwt',
                           reason='unknown_access_group',
                           ag=access_group)
                msg = _("Unknown accessgroup: {access_group}")
                msg = msg.format(access_group=access_group)
                raise AccessDenied(msg)
            ag_uuid = result[0]
            if ag_uuid not in token_accessgroups:
                emit_audit("AuthZ", "denied",
                           level='warning',
                           actor=token.rel_path,
                           user=username,
                           method='gen_jwt',
                           reason='token_not_in_access_group',
                           ag=access_group)
                msg = _("Token not in accessgroup: {token_path}: {access_group}")
                msg = msg.format(token_path=token.rel_path, access_group=access_group)
                raise AccessDenied(msg)

        # Load JWT signing key.
        user_site = backend.get_object(uuid=token.site_uuid)
        sign_key = user_site._key
        if not sign_key:
            emit_audit("AuthZ", "denied",
                       level='warning',
                       actor=token.rel_path,
                       user=username,
                       method='gen_jwt',
                       reason='site_signing_key_missing',
                       site=getattr(user_site, 'name', None))
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
        except Exception as err:
            msg = _("Invalid auth JWT validity.")
            raise ValueError(msg) from err

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

        expire_human = datetime.datetime.fromtimestamp(
                            jwt_data['exp']).strftime("%Y-%m-%d %H:%M:%S")
        log_msg = _("Sigend JWT: user={username} token={token_name} access_group={access_group}, reason={reason}, expire={expire}", log=True)[1]
        log_msg = log_msg.format(username=username, token_name=token.name, access_group=access_group, reason=reason, expire=expire_human)
        self.logger.info(log_msg)
        return _jwt

    def get_jwt(self, command_args):
        try:
            jwt_reason = command_args['jwt_reason']
        except Exception:
            status = False
            message = "AUTHD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)

        try:
            jwt_challenge = command_args['jwt_challenge']
        except Exception:
            status = False
            message = "AUTHD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)

        try:
            jwt_access_group = command_args['jwt_access_group']
        except Exception:
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

    def get_apps(self, token):
        from otpme.lib.protocols.server.sso1 import get_apps
        return get_apps(token)

    def build_log_msg(self, command_error):
            log_msg = _("{command_error}: user={log_username} access_group={log_access_group} client={log_client} client_ip={log_client_ip} auth_mode={log_auth_mode} auth_type={log_auth_type}", log=True)[1]
            log_msg = log_msg.format(command_error=command_error, log_username=self.log_username, log_access_group=self.log_access_group, log_client=self.log_client, log_client_ip=self.log_client_ip, log_auth_mode=self.log_auth_mode, log_auth_type=self.log_auth_type)
            return log_msg

    def authd_redirect_command(self, command, user, command_args, node=None):
        try:
            authd_conn = connections.get("authd",
                                        node=node,
                                        realm=config.realm,
                                        site=user.site,
                                        auto_preauth=True,
                                        auto_auth=False)
        except Exception as e:
            log_msg = _("Redirect connection failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return False, {'message':'REDIRECT_CONN_FAILED', 'status':False}
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
            return False, {'message':'REDIRECT_CONN_FAILED', 'status':False}
        finally:
            authd_conn.close()
        return status, response

    def redirect_fido2_complete(self, user, smartcard_data, sso_challenge,
        client, client_ip, fido2_state_id, node):
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
                        'sso_ag'            : sso_jwt_ag,
                        'sso_challenge'     : sso_challenge,
                        'smartcard_data'    : smartcard_data,
                        'jwt_reason'        : jwt_reason,
                        'jwt_access_group'  : sso_jwt_ag,
                        'jwt_challenge'     : redirect_challenge,
                        'fido2_state_id'    : fido2_state_id,
                    }
        status, \
        response = self.authd_redirect_command(command="token_verify_fido2",
                                        user=user,
                                        command_args=verify_args,
                                        node=node)
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
            auth_token = auth_response.pop('token')
        except KeyError:
            pass
        # Get user apps.
        app_data = self.get_apps(auth_token)
        auth_response['app_data'] = app_data
        # Get SSO jwt from remote auth response.
        auth_response['sso_jwt'] = response['sso_jwt']
        return self.build_response(status, auth_response)

    def _pop_fido2_state_or_error(self, fido2_state_id):
        """ Pop the FIDO2 auth state container for ``fido2_state_id``
        from the shared store and return ``(state_dict, None)`` on
        hit, or ``(None, error_response)`` on miss. Single-use: the
        entry is removed by the lookup itself, so replay of the same
        (cookie, assertion) pair within the TTL window can't find a
        state to verify against.

        On miss, callers can simply ``return error_response``.
        """
        try:
            state_data = multiprocessing.fido2_auth_states.delete(
                                                    fido2_state_id)
        except KeyError:
            log_msg = _("Fido2 auth state missing.", log=True)[1]
            self.logger.warning(log_msg)
            auth_response = {'message': 'Login failed.', 'status': False}
            return None, self.build_response(False, auth_response)
        return state_data, None

    def fido2_auth_begin(self, username, command_args):
        # Record start so we can pad to a uniform minimum duration
        # regardless of code path (decoy / real / cross-site). Without
        # this an attacker can distinguish "user unknown" from "user
        # exists w/ FIDO2" by response time alone.
        begin_start = time.monotonic()
        try:
            rp_id = command_args['rp_id']
        except Exception:
            status = False
            message = "AUTHD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            sso_ag_uuid = command_args['sso_ag_uuid']
        except Exception:
            sso_ag = backend.get_object(object_type="accessgroup",
                                        name=config.sso_access_group,
                                        realm=config.realm,
                                        site=config.site)
            sso_ag_uuid = sso_ag.uuid
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        # Cross-site redirect: only possible when the user is known
        # locally. Pad on this path too so the cross-site latency
        # doesn't itself become a "user exists remotely" oracle (we
        # can't shorten the network roundtrip but we can guarantee a
        # floor that masks fast-path local responses).
        if user is not None and user.site != config.site:
            command_args['sso_ag_uuid'] = sso_ag_uuid
            try:
                status, \
                message = self.authd_redirect_command(command="fido2_auth_begin",
                                                user=user,
                                                command_args=command_args)
                try:
                    fido2_state_id = message['fido2_state_id']
                except (TypeError, KeyError):
                    pass
                else:
                    try:
                        fido2_auth_node = message.pop('fido2_auth_node')
                    except KeyError:
                        pass
                    else:
                        multiprocessing.fido2_auth_states.add(key=fido2_state_id,
                                                            value={'node':fido2_auth_node},
                                                            expire=60)
                        my_host = self._get_host()
                        message['fido2_auth_node'] = my_host.fqdn
                return self.build_response(status, message)
            finally:
                _pad_min_duration(begin_start)
        # Local path: gather real FIDO2/passkey credentials for the
        # user. Empty list (or unknown user) falls through to the
        # decoy path so the response is shape-indistinguishable from
        # the success case.
        credentials = []
        credential_token_map = {}
        if user is not None:
            sso_ag = backend.get_object(object_type="accessgroup",
                                        uuid=sso_ag_uuid)
            user_tokens = user.get_tokens(access_group=sso_ag,
                                        return_type="instance")
            # Drop passkey tokens from the assertion allow-list when
            # the ``sso_allow_passkeys`` cascade doesn't resolve to
            # True. Browser then has nothing to sign with (for
            # passkey), so the whole login attempt fails at the
            # signature stage indistinguishable from an unknown user.
            passkeys_allowed = _sso_allow_passkeys_for_user(user)
            for token in user_tokens:
                if token.token_type == "passkey" and not passkeys_allowed:
                    continue
                if token.token_type in ("fido2", "passkey") and token.credential_data:
                    cred_data = decode(token.credential_data, "hex")
                    acd = AttestedCredentialData(cred_data)
                    credentials.append(acd)
                    cred_id_b64 = base64.urlsafe_b64encode(acd.credential_id).rstrip(b'=').decode()
                    credential_token_map[cred_id_b64] = token.name
        if not credentials:
            # User unknown OR exists but has no FIDO2 / passkey
            # credentials. Generate deterministic decoys so the
            # response shape stays identical to the "real" path; the
            # complete-step then naturally fails at signature verify
            # (real path: wrong key) or at token lookup (decoy path:
            # no token by that name). Both surface as a generic
            # "Login failed" -- indistinguishable to the caller.
            log_msg = _("FIDO2 auth_begin: returning decoys for {username}",
                        log=True)[1]
            log_msg = log_msg.format(username=username)
            self.logger.info(log_msg)
            credentials, credential_token_map = _decoy_fido2_credentials(
                                                            username)
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        request_options, auth_state = fido2_server.authenticate_begin(
            credentials,
            user_verification="preferred",
        )
        fido2_auth_state = _serialize_fido2_state(auth_state)
        my_host = self._get_host()
        fido2_auth_node = my_host.fqdn
        fido2_state_id = stuff.gen_secret(len=32)
        # Keep the credential->token_name map server-side: the web
        # layer's flask_session is a signed-but-unencrypted cookie, so
        # putting the map there would leak the synthetic "decoy-N"
        # token names back to the client and undo the enumeration
        # resistance. The map is popped at fido2_auth_complete to
        # resolve matched_token_name.
        multiprocessing.fido2_auth_states.add(key=fido2_state_id,
                                            value={'state':fido2_auth_state,
                                                    'node':fido2_auth_node,
                                                    'credential_token_map':credential_token_map},
                                            expire=60)
        fido2_auth_data = {
                    'request_options'           : dict(request_options),
                    'fido2_state_id'            : fido2_state_id,
                    'fido2_auth_node'           : fido2_auth_node,
                }
        _pad_min_duration(begin_start)
        return self.build_response(True, fido2_auth_data)

    def fido2_auth_complete(self, username, client, client_ip, sso_challenge, command_args):
        try:
            rp_id = command_args['rp_id']
        except Exception:
            status = False
            message = "AUTHD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            fido2_state_id = command_args['fido2_state_id']
        except Exception:
            status = False
            message = "AUTHD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        try:
            auth_response = command_args['auth_response']
        except Exception:
            status = False
            message = "AUTHD_INCOMPLETE_COMMAND"
            return self.build_response(status, message)
        # matched_token_name is no longer accepted from the web layer:
        # the credential->token_name map is held server-side (in the
        # fido2_auth_states shared dict) so the synthetic "decoy-N"
        # names for unknown users never leave the server. Derived from
        # state_data after we pop it below.
        # OIDC ``prompt=login`` / ``max_age`` step-up: web layer sets
        # ``reauth=True`` + the current SSO session_uuid. On success we
        # don't create a new login session -- we just bump
        # ``reauth_time`` on the existing session so subsequent ID
        # Tokens carry a fresh ``auth_time`` while peer RP sessions
        # stay alive.
        reauth = bool(command_args.get('reauth', False))
        reauth_session_uuid = command_args.get('session_uuid')
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
        state_data, err = self._pop_fido2_state_or_error(fido2_state_id)
        if err is not None:
            return err
        # Check for command redirection.
        if user.site != config.site:
            fido2_auth_node = state_data['node']
            # Build smartcard_data for auth_handler.
            smartcard_data = {
                'rp_id'         : rp_id,
                'auth_response' : json.dumps(auth_response),
            }
            return self.redirect_fido2_complete(user=user,
                                        smartcard_data=smartcard_data,
                                        sso_challenge=sso_challenge,
                                        client=client,
                                        client_ip=client_ip,
                                        fido2_state_id=fido2_state_id,
                                        node=fido2_auth_node)
        # Load fido2 auth state and build the smartcard_data envelope
        # consumed by both the step-up reauth path (``token.verify()``)
        # and the regular login path (``user.authenticate()``).
        auth_state = _deserialize_fido2_state(state_data['state'])
        # Look up which token name owns the credential the browser
        # asserted with. The map was cached server-side at begin so
        # decoy token names ("decoy-N") never leak via the web
        # layer's flask_session cookie. A missing entry (assertion
        # for a credential we don't know about) falls through to the
        # normal "token not found" failure below.
        credential_token_map = state_data.get('credential_token_map') or {}
        response_cred_id = auth_response.get('id', '') if isinstance(auth_response, dict) else ''
        matched_token_name = credential_token_map.get(response_cred_id)
        smartcard_data = {
            'rp_id'         : rp_id,
            'auth_state'    : auth_state,
            'auth_response' : json.dumps(auth_response),
        }
        # Step-up reauth: verify FIDO2 directly on the token (which
        # already enforces counter / replay protection) and bump
        # reauth_time on the existing SSO session. No full
        # user.authenticate() call: the user is already logged in,
        # so no new SOTP, no cookies, no session creation.
        if reauth:
            if not reauth_session_uuid:
                log_msg = _("Reauth: session_uuid missing.", log=True)[1]
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            token = None
            for t in backend.search(object_type="token",
                                    attribute="owner_uuid",
                                    value=user.uuid,
                                    return_type="instance"):
                if t.token_type in ("fido2", "passkey") and t.name == matched_token_name:
                    token = t
                    break
            if token is None:
                log_msg = _("Reauth: matched FIDO2 token not found.", log=True)[1]
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            try:
                verify_ok = token.verify(smartcard_data=smartcard_data)
            except Exception as e:
                log_msg = _("Reauth: FIDO2 verify failed: {err}", log=True)[1]
                log_msg = log_msg.format(err=e)
                self.logger.warning(log_msg)
                verify_ok = False
            if not verify_ok:
                emit_audit("Auth", "reauth_failed",
                                level='warning',
                                user=user.name,
                                token=matched_token_name,
                                reason='fido2_verify_failed',
                                ip=client_ip)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            sso_session = backend.get_object(object_type="session",
                                             uuid=reauth_session_uuid)
            if sso_session is None or sso_session.user_uuid != user.uuid:
                emit_audit("Auth", "reauth_failed",
                                level='warning',
                                user=user.name,
                                token=matched_token_name,
                                session=reauth_session_uuid,
                                reason='session_user_mismatch',
                                ip=client_ip)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            try:
                sso_session.update_reauth_time(wait_for_cluster_writes=True)
            except Exception as e:
                log_msg = _("Reauth: failed to persist reauth_time: {err}", log=True)[1]
                log_msg = log_msg.format(err=e)
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            emit_audit("Auth", "reauth_success",
                            user=user.name,
                            token=matched_token_name,
                            session=sso_session.session_id,
                            ip=client_ip)
            return self.build_response(True, {'status': True})
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
            app_data = self.get_apps(auth_token)
            auth_result['app_data'] = app_data
        return self.build_response(True, auth_result)

    def token_verify(self, user, auth_type, command, command_args,
        password=None, mschap_challenge=None, mschap_response=None,
        smartcard_data=None):
        try:
            jwt_reason = command_args['jwt_reason']
        except Exception:
            jwt_reason = None
        try:
            jwt_challenge = command_args['jwt_challenge']
        except Exception:
            jwt_challenge = None
        try:
            jwt_access_group = command_args['jwt_access_group']
        except Exception:
            jwt_access_group = None
        try:
            sso_login = command_args['sso_login']
        except Exception:
            sso_login = False
        try:
            sso_ag = command_args['sso_ag']
        except Exception:
            sso_ag = None
        try:
            sso_challenge = command_args['sso_challenge']
        except Exception:
            sso_challenge = None
        # Get audit logger.
        audit_logger = config.audit_logger
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
            try:
                fido2_state_id = command_args.pop('fido2_state_id')
            except KeyError:
                status = False
                log_msg = _("Fido2 state ID missing.", log=True)[1]
                self.logger.warning(log_msg)
                message = "AUTH_FAILED"
                return self.build_response(status, message)
            state_data, err = self._pop_fido2_state_or_error(fido2_state_id)
            if err is not None:
                return err
            # Load fido2 auth state.
            auth_state = _deserialize_fido2_state(state_data['state'])
            smartcard_data['auth_state'] = auth_state
            token_verify_parms = {
                    'auth_type'     : "smartcard",
                    'smartcard_data': smartcard_data,
                    }
        auth_token = None
        user_tokens = user.get_tokens(return_type="instance")
        # Mirror the fido2_auth_begin gate: on the cross-site verify
        # path (originator redirected here) an assertion signed with a
        # passkey must not be accepted when the user's cascade doesn't
        # resolve to True. Resolve once, outside the loop.
        fido2_passkeys_allowed = None
        if command == "token_verify_fido2":
            fido2_passkeys_allowed = _sso_allow_passkeys_for_user(user)
        for x_token in user_tokens:
            if command == "token_verify":
                if x_token.pass_type != "static":
                    if x_token.pass_type != "otp":
                        continue
            if command == "token_verify_mschap":
                if not x_token.mschap_enabled:
                    continue
            if command == "token_verify_fido2":
                if x_token.token_type not in ("fido2", "passkey"):
                    continue
                if x_token.token_type == "passkey" and not fido2_passkeys_allowed:
                    continue
            try:
                verify_status = x_token.verify(**token_verify_parms)
            except Exception as e:
                log_msg = _("Verification of token '{token_name}' returned error: {error}", log=True)[1]
                log_msg = log_msg.format(token_name=x_token.name, error=e)
                self.logger.critical(log_msg)
                continue

            # MSCHAP tokens return a (status, nt_key, nt_hash) tuple; all
            # other verify() dispatchers return a scalar. Unwrap the tuple
            # before the status check so mschap auth is not always rejected.
            if command == "token_verify_mschap":
                if not isinstance(verify_status, tuple) or verify_status[0] is not True:
                    continue
            elif verify_status is not True:
                continue

            auth_token = x_token
            break

        # Try temp password.
        if not auth_token and password:
            for x_token in user_tokens:
                if command == "token_verify_mschap":
                    try:
                        verify_status = x_token.verify(temp=True, **token_verify_parms)
                    except Exception as e:
                        log_msg = _("Verification of token (temp) '{token_name}' returned error: {error}", log=True)[1]
                        log_msg = log_msg.format(token_name=x_token.name, error=e)
                        self.logger.critical(log_msg)
                        continue
                else:
                    token_verify_parms = {
                            'auth_type'         : "clear-text",
                            'password'          : password,
                            }
                    try:
                        verify_status = x_token.verify_temp_password(**token_verify_parms)
                    except Exception as e:
                        log_msg = _("Verification of token (temp) '{token_name}' returned error: {error}", log=True)[1]
                        log_msg = log_msg.format(token_name=x_token.name, error=e)
                        self.logger.critical(log_msg)
                        continue

                # Same tuple-vs-scalar shape as the primary verify loop.
                if command == "token_verify_mschap":
                    if not isinstance(verify_status, tuple) or verify_status[0] is not True:
                        continue
                elif verify_status is not True:
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
            if sso_login and sso_ag:
                # Gen jwt for SSO auth.
                try:
                    sso_jwt = self.gen_jwt(username=user.name,
                                        token=auth_token,
                                        reason="SSO_AUTH",
                                        challenge=sso_challenge,
                                        access_group=sso_ag,
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
            sso_ag = f"{config.site}/{config.sso_access_group}"
            verify_args['sso_login'] = True
            verify_args['sso_ag'] = sso_ag
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
            message, log_msg = _("Remote authentication failed: {user}: {e}", log=True)
            log_msg = log_msg.format(user=user.name, e=redirect_auth_response)
            message = message.format(user=user.name, e=redirect_auth_response)
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
            app_data = self.get_apps(auth_token)
            auth_response['app_data'] = app_data
            # Get SSO jwt from remote auth response.
            auth_response['sso_jwt'] = redirect_auth_response['sso_jwt']
        return self.build_response(status, auth_response)

    def auth_user(self, user, auth_type, auth_mode,
        password=None, mschap_challenge=None, mschap_response=None,
        access_group=None, sso_challenge=None, session_logout=False,
        host=None, host_type=None, host_ip=None, client=None,
        client_ip=None, oidc_context=None, oidc_scope=None,
        oidc_nonce=None, oidc_redirect_uri=None,
        oidc_skip_backchannel_client=None,
        oidc_code_challenge_method=None,
        oidc_code_challenge=None,
        oidc_skip_backchannel=False):
        # Build auth request.
        kwargs = {
                    'auth_mode'                 : auth_mode,
                    'auth_type'                 : auth_type,
                    'peer'                      : self.peer,
                    'access_group'              : access_group,
                    'challenge'                 : mschap_challenge,
                    'response'                  : mschap_response,
                    'password'                  : password,
                    'session_logout'            : session_logout,
                    'host'                      : host,
                    'host_type'                 : host_type,
                    'host_ip'                   : host_ip,
                    'client'                    : client,
                    'client_ip'                 : client_ip,
                    'oidc_context'              : oidc_context,
                    'oidc_scope'                : oidc_scope,
                    'oidc_nonce'                : oidc_nonce,
                    'oidc_redirect_uri'         : oidc_redirect_uri,
                    'oidc_code_challenge'       : oidc_code_challenge,
                    'oidc_code_challenge_method': oidc_code_challenge_method,
                    'oidc_skip_backchannel_client': oidc_skip_backchannel_client,
                    'oidc_skip_backchannel'     : oidc_skip_backchannel,
                    'ecdh_curve'                : self.ecdh_curve,
                }
        # Do authentication.
        auth_response = user.authenticate(**kwargs)
        # Get auth status and message from response.
        auth_status = auth_response['status']
        if not auth_status:
            status = False
            group_maintenance = auth_response.get('group_maintenance', False)
            if group_maintenance:
                # Propagate the maintenance signal as a structured
                # response so the caller (e.g. /oidc/authorize) can
                # render a maintenance page instead of bouncing the
                # user back to the RP with a generic auth error.
                message = {
                    'message': _("Application in maintenance mode."),
                    'group_maintenance': True,
                }
            else:
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
            app_data = self.get_apps(auth_token)
            auth_response['app_data'] = app_data

        # Build response message.
        message = auth_response
        if auth_status:
            status = True
        else:
            status = status_codes.ERR

        return self.build_response(status, message)

    def _process(self, *args, **kwargs):
        try:
            return self.__process(*args, **kwargs)
        finally:
            # End any implicit read-only transaction so the DB
            # connection doesn't sit in "idle in transaction".
            if config.session is not None:
                try:
                    config.session.commit()
                except Exception:
                    pass

    def __process(self, command, command_args, **kwargs):
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
        except Exception:
            username = None

        try:
            client = command_args['client']
        except Exception:
            client = None

        try:
            client_ip = command_args['client_ip']
        except Exception:
            client_ip = None

        try:
            host = command_args['host']
        except Exception:
            host = None

        try:
            host_type = command_args['host_type']
        except Exception:
            host_type = None

        try:
            host_ip = command_args['host_ip']
        except Exception:
            host_ip = None

        try:
            password = command_args['password']
        except Exception:
            password = None

        try:
            mschap_challenge = command_args['mschap_challenge']
        except Exception:
            mschap_challenge = None

        try:
            mschap_response = command_args['mschap_response']
        except Exception:
            mschap_response = None

        try:
            smartcard_data = command_args['smartcard_data']
        except Exception:
            smartcard_data = None

        try:
            access_group = command_args['access_group']
        except Exception:
            access_group = None

        try:
            sso_logout = command_args['sso_logout']
        except Exception:
            sso_logout = False

        try:
            sso_challenge = command_args['sso_challenge']
        except Exception:
            sso_challenge = None

        try:
            oidc_login = command_args['oidc_login']
        except Exception:
            oidc_login = False

        try:
            oidc_context = command_args['oidc_context']
        except Exception:
            oidc_context = None

        try:
            oidc_scope = command_args['oidc_scope']
        except Exception:
            oidc_scope = None

        try:
            oidc_nonce = command_args['oidc_nonce']
        except Exception:
            oidc_nonce = None

        try:
            oidc_redirect_uri = command_args['oidc_redirect_uri']
        except Exception:
            oidc_redirect_uri = None

        try:
            oidc_code_challenge = command_args['oidc_code_challenge']
        except Exception:
            oidc_code_challenge = None

        try:
            oidc_code_challenge_method = command_args['oidc_code_challenge_method']
        except Exception:
            oidc_code_challenge_method = None

        try:
            oidc_skip_backchannel_client = command_args['oidc_skip_backchannel_client']
        except Exception:
            oidc_skip_backchannel_client = None

        oidc_skip_backchannel = bool(command_args.get('oidc_skip_backchannel', False))

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
        if oidc_login:
            redirect_connection = False
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
                            session_logout=sso_logout,
                            host=host,
                            host_ip=host_ip,
                            host_type=host_type,
                            client=client,
                            client_ip=client_ip,
                            oidc_context=oidc_context,
                            oidc_scope=oidc_scope,
                            oidc_nonce=oidc_nonce,
                            oidc_redirect_uri=oidc_redirect_uri,
                            oidc_code_challenge=oidc_code_challenge,
                            oidc_code_challenge_method=oidc_code_challenge_method,
                            oidc_skip_backchannel_client=oidc_skip_backchannel_client,
                            oidc_skip_backchannel=oidc_skip_backchannel)

    def _close(self):
        pass
