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
from otpme.lib import qrcode
from otpme.lib import connections
from otpme.lib.otp.oath import ocra
from otpme.lib.humanize import units
from otpme.lib.encoding.base import decode

from otpme.lib.protocols import status_codes
from otpme.lib.protocols import tiqr_helpers
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.token.tiqr import tiqr as tiqr_token
from otpme.lib.daemon.clusterd import cluster_sync_state
from otpme.lib.daemon.clusterd import cluster_sync_state_delete

from otpme.lib.exceptions import *

DEPLOY_NAME = "sso-deploy"

# tiqr result codes, as the apps expect them. Version 1 answers in plain
# text, version 2 in JSON; the app picks via the X-TIQR-Protocol-Version
# header. Translating these into what goes over the wire is the web
# layer's job -- authd only says which case it is.
#
# The protocol also carries an "attemptsLeft" alongside INVALID_RESPONSE,
# which we never send. It would have to count wrong responses on an
# unauthenticated endpoint, and anyone who knows a username can post
# those -- locking any account at will. Guessing is bounded instead by
# the rate limit on /tiqr/auth and by the challenge expiry, and the
# apps treat a missing attemptsLeft as "no count given".
TIQR_AUTH_OK = "OK"
TIQR_AUTH_INVALID_RESPONSE = "INVALID_RESPONSE"
TIQR_AUTH_INVALID_CHALLENGE = "INVALID_CHALLENGE"
TIQR_AUTH_INVALID_USERID = "INVALID_USERID"
TIQR_AUTH_ACCOUNT_BLOCKED = "ACCOUNT_BLOCKED"

# How much longer than the challenge an answered login is kept. Nothing
# can be collected with it any more once the challenge has expired --
# tiqr_auth_status() checks the expiry it carries -- but a browser that
# polls a moment too late gets told the challenge expired instead of
# being left waiting for something that is gone.
TIQR_RESULT_TTL_GRACE = 60

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-auth-1.0"

def register():
    config.register_otpme_protocol("authd", PROTOCOL_VERSION, server=True)

def _sso_allowed_here(parameter):
    """ Does the site running this portal allow <parameter> at all?

    The three ``_sso_allow_*_for_user`` resolvers below walk the user's
    parents, and those end at the user's *home* site -- so setting
    sso_allow_fido2 to False on the site the portal runs on has no
    effect on a user from somewhere else. It reads as "not for our
    users", never as "not here", and an administrator who turns it off
    on their portal's site means the second one.

    So both have to agree: this answers for the portal, the per-user
    resolver answers for the account, and a login needs neither to
    object. The combination can only ever forbid more, never allow
    more.

    Site scope only, no user or unit walk -- those hang below one site
    and would be the account's answer again, which is the other
    resolver's job. Fail-open like the FIDO2 and tiqr resolvers: only
    an explicit False blocks, so a parameter added underneath a running
    installation does not switch anything off.
    """
    my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
    if my_site is None:
        return True
    try:
        value = my_site.get_config_parameter(parameter)
    except Exception:
        return True
    if value is None:
        return True
    return bool(value)


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


def _sso_allow_tiqr_for_user(user):
    """ Home-side resolution of the ``sso_allow_tiqr`` cascade
    (user → unit → site) for the tiqr login path.

    Fail-open for the same reason as the FIDO2 one: an explicit False
    blocks, an unset cascade does not. Applied where the user's tiqr
    tokens are gathered, so a blocked user simply has none -- the QR
    still goes out, and the attempt ends the way it does for anyone
    without a phone. """
    try:
        value = user.get_config_parameter("sso_allow_tiqr")
    except Exception:
        return True
    if value is None:
        return True
    return bool(value)


def _sso_allow_fido2_for_user(user):
    """ Home-side resolution of the ``sso_allow_fido2`` cascade
    (user → unit → site) for the WebAuthn login path. Covers signing in
    with a security key and managing them in the portal, the same span
    ``sso_allow_passkeys`` covers for passkeys.

    Resolves fail-open, which is the difference to the passkey gate:
    FIDO2 login has always worked here, and a parameter added underneath
    a running installation must not switch it off. It takes an explicit
    False to block. """
    try:
        value = user.get_config_parameter("sso_allow_fido2")
    except Exception:
        return True
    if value is None:
        return True
    return bool(value)


# Per-process cache for the decoy HMAC seed -- derived from the site's
# private key once, so we don't pay export_private_key() on every
# fido2_auth_begin. Reset to None on fork; the child re-derives lazily.
_DECOY_SEED_CACHE = None
# P-256 (secp256r1) curve order. Standard NIST constant, immutable.
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# Fallbacks for the two decoy shape parameters, used when the site
# object cannot be read. 64 bytes is what a YubiKey hands out, and two
# is a plausible number of keys for somebody who has more than one.
DEFAULT_DECOY_CRED_ID_LEN = 64
DEFAULT_DECOY_MAX_CREDS = 2


# This method was written by claude code.
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


# This method was written by claude code.
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


# This method was written by claude code.
def _decoy_bytes(seed, label, length):
    """ ``length`` bytes derived from ``(seed, label)``.

    HMAC-SHA256 in counter mode, because one digest is 32 bytes and a
    credential id is usually longer than that -- a YubiKey hands out
    64. The same construction HKDF-Expand uses, minus the parts that
    only matter for key material; this output is a public identifier.

    The length goes into the HMAC input, not just into the truncation.
    Otherwise a shorter output would be a prefix of a longer one, and
    somebody who probed the same name before and after the site
    parameter changed could tell a decoy by that relationship alone.
    """
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac.new(seed,
                        f"{label}:{length}:{counter}".encode('utf-8'),
                        hashlib.sha256).digest()
        counter += 1
    return out[:length]


# This method was written by claude code.
def _decoy_cred_id_len():
    """ How long a decoy credential id has to be.

    Not a detail: the id and the number of ids are the only things a
    credential descriptor puts on the wire (fido2.server.to_descriptor
    builds it from the credential id alone -- no AAGUID, no public key,
    no transports). A decoy of a length no authenticator in this realm
    produces is recognisable from a single request, whatever else it
    gets right. Which length that is only the operator knows, hence the
    site parameter rather than whatever SHA-256 happens to produce. """
    my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
    if my_site is None:
        return DEFAULT_DECOY_CRED_ID_LEN
    cred_id_len = my_site.get_config_parameter("fido2_decoy_cred_id_len")
    return cred_id_len or DEFAULT_DECOY_CRED_ID_LEN


# This method was written by claude code.
def _decoy_count(seed, username):
    """ How many decoys this username gets.

    Always one would say "this account has exactly one key, or does not
    exist" -- and every user with a second key would stand out by list
    length alone, which is the enumeration this whole mechanism is
    against.

    Derived from the seed, so asking twice gives the same answer: a
    count that changed between two requests would be the giveaway by
    itself. Bounded by a site parameter, because how many keys people
    here actually carry is the operator's knowledge and not ours. """
    max_creds = DEFAULT_DECOY_MAX_CREDS
    my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
    if my_site is not None:
        max_creds = (my_site.get_config_parameter("fido2_decoy_max_creds")
                    or DEFAULT_DECOY_MAX_CREDS)
    if max_creds <= 1:
        return 1
    digest = hmac.new(seed,
                    f"fido2-decoy-count:{username}".encode('utf-8'),
                    hashlib.sha256).digest()
    # Modulo maps the digest into 1..max_creds. The bias that comes
    # with it is 2^-256 against a single digit divisor, and the value
    # is a count rather than key material.
    return 1 + (int.from_bytes(digest, 'big') % max_creds)


# This method was written by claude code.
def _decoy_fido2_credentials(username, count=None):
    """ Build deterministic decoy FIDO2 credentials for /fido2/auth/begin
    so the response shape doesn't leak whether the user exists or has
    a FIDO2 token. credential_ids and the underlying public key are
    HMAC-derived from a per-site secret seed:

      * same username + same site -> same fake credential_ids (random
        variation would itself signal "user unknown"),
      * an attacker can't generate matching decoys without the secret.

    Length and number come from the site config rather than from what
    SHA-256 happens to produce -- see _decoy_cred_id_len() and
    _decoy_count() for why exactly those two are what matters.

    The pubkey is a valid on-curve P-256 point but with the private
    half discarded; verify naturally fails at complete-time. """
    seed = _decoy_seed()
    cred_id_len = _decoy_cred_id_len()
    if count is None:
        count = _decoy_count(seed, username)
    credentials = []
    credential_token_map = {}
    for idx in range(count):
        cred_id = _decoy_bytes(seed,
                            f"fido2-decoy:{username}:{idx}:id",
                            cred_id_len)
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

def _tiqr_result_state_id(poll_id):
    """ The key an answered tiqr login is filed under.

    Prefixed with the shared dict's name because that is how the state
    sync finds the dict again on the other nodes, and the poll id goes
    in hashed: the id itself is what the browser presents to collect
    the result, while the key travels through the cluster journal and
    the logs. """
    return f"tiqr_auth_results:{tiqr_helpers.hash_poll_id(poll_id)}"


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
        # Autodetect in auth handler if SOTP should be checked.
        self.allow_sotp_auth = None
        # Redirect user to home site.
        self.redirect_user = True
        # Instructs parent class to require a client certificate.
        self.require_client_cert = True
        # Auth request are allowed to any node.
        self.require_master_node = False
        # We need a clean cluster status.
        self.require_cluster_status = True
        # Authd can continue to process request on master failover.
        self.process_on_master_failover = True
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
        if config.proc_mode == "multiprocessing":
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

    def gen_jwt(self, username, token, reason, challenge, access_group=None, sso=False, src_token=None):
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
        if src_token:
            jwt_data['src_token'] = src_token.uuid

        _jwt = jwt.encode(payload=jwt_data, key=sign_key, algorithm='RS256')

        expire_human = datetime.datetime.fromtimestamp(
                            jwt_data['exp']).strftime("%Y-%m-%d %H:%M:%S")
        if src_token:
            log_msg = _("Sigend JWT: user={username} src_token={src_token} token={token_name} access_group={access_group}, reason={reason}, expire={expire}", log=True)[1]
            log_msg = log_msg.format(username=username, src_token=src_token.rel_path, token_name=token.name, access_group=access_group, reason=reason, expire=expire_human)
        else:
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

    def authd_redirect_command(self, command, user, command_args, node=None, site=None):
        if site is None:
            site = user.site
        try:
            authd_conn = connections.get("authd",
                                        node=node,
                                        realm=config.realm,
                                        site=site,
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
        client, client_ip, fido2_state_id):
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
                        # What this portal allows. token_verify runs on
                        # the user's home site and would otherwise only
                        # see the account's own cascade -- the same gap
                        # fido2_auth_begin forwards these for.
                        '_fido2_allowed_here'    : _sso_allowed_here("sso_allow_fido2"),
                        '_passkeys_allowed_here' : _sso_allowed_here("sso_allow_passkeys"),
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

        Single-use across the cluster, not just here: the state was
        synced to every node at begin time, and without telling them it
        is spent, the same assertion sent to another node would find a
        copy still sitting there and be accepted a second time.

        On miss, callers can simply ``return error_response``.
        """
        try:
            state_data = multiprocessing.fido2_auth_states.delete(fido2_state_id)
        except KeyError:
            log_msg = _("Fido2 auth state missing.", log=True)[1]
            self.logger.warning(log_msg)
            auth_response = {'message': 'Login failed.', 'status': False}
            return None, self.build_response(False, auth_response)
        cluster_sync_state_delete(fido2_state_id)
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
        # What the portal's own site allows. The per-user resolvers
        # further down answer for the account and their cascade ends at
        # the account's home site -- so without this, a site that
        # switched FIDO2 off could still be signed in to by anybody
        # from elsewhere.
        #
        # Forwarded across the redirect the same way sso_ag_uuid is:
        # the home site runs this function too, and asking its own
        # config there would give the home site's answer a second time
        # instead of the portal's. Absent means nobody forwarded one,
        # so we are the portal.
        # Only for an account of another site. For one of our own the
        # cascade already ends at this very site, and asking it again
        # on top would let the site value win over a user or unit
        # override -- which is what those levels are registered for.
        foreign_user = user is not None and user.site != config.site
        peer_fido2_allowed = command_args.get('_fido2_allowed_here')
        if peer_fido2_allowed is not None:
            fido2_allowed_here = bool(peer_fido2_allowed)
        elif foreign_user:
            fido2_allowed_here = _sso_allowed_here("sso_allow_fido2")
        else:
            fido2_allowed_here = True
        peer_passkeys_allowed = command_args.get('_passkeys_allowed_here')
        if peer_passkeys_allowed is not None:
            passkeys_allowed_here = bool(peer_passkeys_allowed)
        elif foreign_user:
            passkeys_allowed_here = _sso_allowed_here("sso_allow_passkeys")
        else:
            passkeys_allowed_here = True
        # Cross-site redirect: only possible when the user is known
        # locally. Pad on this path too so the cross-site latency
        # doesn't itself become a "user exists remotely" oracle (we
        # can't shorten the network roundtrip but we can guarantee a
        # floor that masks fast-path local responses).
        if user is not None and user.site != config.site:
            command_args['_fido2_allowed_here'] = fido2_allowed_here
            command_args['_passkeys_allowed_here'] = passkeys_allowed_here
            command_args['sso_ag_uuid'] = sso_ag_uuid
            try:
                status, \
                message = self.authd_redirect_command(command="fido2_auth_begin",
                                                user=user,
                                                command_args=command_args)
                # Nothing kept here: the state belongs to the site
                # that made it, and that is where the assertion is
                # verified. We only pass the id along.
                return self.build_response(status, message)
            finally:
                _pad_min_duration(begin_start)
        # Local path: gather real FIDO2/passkey credentials for the
        # user. Empty list (or unknown user) falls through to the
        # decoy path so the response is shape-indistinguishable from
        # the success case.
        credentials = []
        credential_token_map = {}
        # Why a token did not make it into the allow-list. Ends up in
        # the decoy log line below, which otherwise says that we found
        # nothing without ever saying what we looked at.
        skipped = []
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
            # Both sides have to agree: the account's own cascade, and
            # the portal the user is standing in front of.
            passkeys_allowed = (passkeys_allowed_here
                                and _sso_allow_passkeys_for_user(user))
            fido2_allowed = (fido2_allowed_here
                            and _sso_allow_fido2_for_user(user))
            for token in user_tokens:
                # The credential belongs to the destination of a link,
                # the assignment to the link -- so everything the
                # browser is offered is read from the destination,
                # while the name we remember is the link's. That name
                # goes back into user.authenticate() at complete, and
                # only the link knows where the token really lives.
                cred_token = token
                if token.destination_token:
                    cred_token = token.dst_token
                    if not cred_token:
                        # Its site holds it and we do not have it. From
                        # here the token simply is not there, which is
                        # worth saying: the whole login then ends in
                        # decoys with nothing to point at.
                        log_msg = _("FIDO2 auth_begin: destination token of '{token_path}' not available here: {dst_uuid}", log=True)[1]
                        log_msg = log_msg.format(token_path=token.rel_path,
                                                dst_uuid=token.destination_token)
                        self.logger.warning(log_msg)
                        continue
                if cred_token.token_type == "passkey" and not passkeys_allowed:
                    skipped.append(f"{token.rel_path}:passkeys_not_allowed")
                    continue
                if cred_token.token_type == "fido2" and not fido2_allowed:
                    skipped.append(f"{token.rel_path}:fido2_not_allowed")
                    continue
                # Only offer credentials that were registered for this RP: an
                # authenticator's assertion is bound to the rpIdHash it was
                # created with, so a credential from a different rp would never
                # produce a valid signature anyway. Filtering here keeps the
                # allow-list clean (and avoids leaking foreign-rp cred IDs).
                # Legacy tokens without a stored rp (rp is None) are not
                # filtered, preserving pre-existing deployments.
                if cred_token.token_type not in ("fido2", "passkey"):
                    skipped.append(f"{token.rel_path}:type={cred_token.token_type}")
                    continue
                if cred_token.rp and cred_token.rp != rp_id:
                    skipped.append(f"{token.rel_path}:rp={cred_token.rp}")
                    continue
                if not cred_token.credential_data:
                    skipped.append(f"{token.rel_path}:no_credential_data")
                    continue
                cred_data = decode(cred_token.credential_data, "hex")
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
            log_msg = _("FIDO2 auth_begin: returning decoys for {username} (rp_id={rp_id}, skipped: {skipped})", log=True)[1]
            log_msg = log_msg.format(username=username, rp_id=rp_id,
                                    skipped=", ".join(skipped) or "-")
            self.logger.info(log_msg)
            credentials, credential_token_map = _decoy_fido2_credentials(
                                                            username)
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        request_options, auth_state = fido2_server.authenticate_begin(
            credentials,
            user_verification="preferred",
        )
        fido2_state_id = f"fido2_auth_states:{stuff.gen_secret(len=32)}"
        # Keep the credential->token_name map server-side: the web
        # layer's flask_session is a signed-but-unencrypted cookie, so
        # putting the map there would leak the synthetic "decoy-N"
        # token names back to the client and undo the enumeration
        # resistance. The map is popped at fido2_auth_complete to
        # resolve matched_token_name.
        expiry = 60
        multiprocessing.fido2_auth_states.add(key=fido2_state_id,
                                            value={'state':auth_state,
                                                    'credential_token_map':credential_token_map},
                                            expire=expiry)
        # Sync fido state.
        cluster_sync_state(state_id=fido2_state_id, expiry=expiry)
        # Build reply.
        fido2_auth_data = {
                    'request_options'           : dict(request_options),
                    'fido2_state_id'            : fido2_state_id,
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
        log_msg = _("fido2_auth_complete: reauth={r} session_uuid_set={s}", log=True)[1]
        log_msg = log_msg.format(r=reauth, s=bool(reauth_session_uuid))
        self.logger.info(log_msg)
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
        # Whether the caller (another authd) is asking us to verify only
        # and hand back a proof-of-verify JWT, leaving session state on
        # them. Set by portal's cross-site reauth path (see below); we
        # do NOT create a session or bump reauth_time here.
        reauth_forward = bool(command_args.get('reauth_forward'))
        # Cross-site reauth: portal forwards a lightweight "verify only,
        # return a signed JWT" request to home so home never sees the
        # SSO session (it lives on portal). Full-auth redirect stays as
        # the default for a plain login.
        #
        # No state is read here: for a user of another site there is
        # none. fido2_auth_begin was answered by their home site and
        # kept the state there, which is also where the assertion gets
        # verified. We only carry the id across.
        if user.site != config.site:
            if reauth:
                # Ask home to verify and JWT-sign the result -- portal
                # validates the JWT below and bumps reauth_time on the
                # local session (never crosses).
                jwt_reason = "DST_TOKEN_VERIFY"
                jwt_challenge = stuff.gen_secret(32)
                forward_args = {
                        'username'          : user.name,
                        'client'            : client,
                        'client_ip'         : client_ip,
                        'rp_id'             : rp_id,
                        'fido2_state_id'    : fido2_state_id,
                        'auth_response'     : auth_response,
                        'reauth_forward'    : True,
                        'jwt_reason'        : jwt_reason,
                        'jwt_challenge'     : jwt_challenge,
                    }
                status, response = self.authd_redirect_command(
                                                command="fido2_auth_complete",
                                                user=user,
                                                command_args=forward_args)
                if not status or not isinstance(response, dict):
                    log_msg = _("Cross-site fido2 reauth: redirected verify failed for user '{u}'.", log=True)[1]
                    log_msg = log_msg.format(u=user.name)
                    self.logger.warning(log_msg)
                    return self.build_response(False, {
                        'message': 'Login failed.', 'status': False,
                    })
                token_uuid = response.get('token_uuid')
                dst_token = backend.get_object(uuid=token_uuid) if token_uuid else None
                if dst_token is None:
                    log_msg = _("Cross-site fido2 reauth: unknown token uuid in home response.", log=True)[1]
                    self.logger.warning(log_msg)
                    return self.build_response(False, {
                        'message': 'Login failed.', 'status': False,
                    })
                if not self.verify_redirect_jwt(response, dst_token, dst_token,
                                                jwt_challenge, jwt_reason):
                    return self.build_response(False, {
                        'message': 'Login failed.', 'status': False,
                    })
                if not reauth_session_uuid:
                    log_msg = _("Reauth: session_uuid missing.", log=True)[1]
                    self.logger.warning(log_msg)
                    return self.build_response(False, {
                        'message': 'Login failed.', 'status': False,
                    })
                sso_session = backend.get_object(object_type="session",
                                                 uuid=reauth_session_uuid)
                if sso_session is None or sso_session.user_uuid != user.uuid:
                    emit_audit("Auth", "reauth_failed",
                                    level='warning',
                                    user=user.name,
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
                                token=dst_token.name,
                                session=sso_session.session_id,
                                ip=client_ip)
                return self.build_response(True, {
                    'message': 'ok', 'status': True,
                })
            # Regular cross-site full auth: unchanged.
            smartcard_data = {
                'rp_id'         : rp_id,
                'auth_response' : json.dumps(auth_response),
            }
            return self.redirect_fido2_complete(user=user,
                                        smartcard_data=smartcard_data,
                                        sso_challenge=sso_challenge,
                                        client=client,
                                        client_ip=client_ip,
                                        fido2_state_id=fido2_state_id)
        # Our own user, so the state is ours: made by fido2_auth_begin
        # on some node of this site and synced to the rest, which is
        # why it can be read here and not only where it was made.
        state_data, err = self._pop_fido2_state_or_error(fido2_state_id)
        if err is not None:
            return err
        # Load fido2 auth state and build the smartcard_data envelope
        # consumed by both the step-up reauth path (``token.verify()``)
        # and the regular login path (``user.authenticate()``).
        auth_state = state_data['state']
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
        # The token that owns the asserted credential. Both paths below
        # need it: the reauth one verifies against it directly, the
        # login one hands it to user.authenticate(). It stays None for a
        # credential we have no name for, which then fails the regular
        # way.
        token = None
        verify_token = None
        for t in backend.search(object_type="token",
                                attribute="owner_uuid",
                                value=user.uuid,
                                return_type="instance"):
            if t.name != matched_token_name:
                continue
            # The name we put into the map at begin is the link's, while
            # the credential the browser signed with belongs to its
            # destination. <token> is what the request was made with,
            # <verify_token> is what holds the credential.
            x_verify_token = t
            if t.destination_token:
                x_verify_token = t.dst_token
                if not x_verify_token:
                    continue
            if x_verify_token.token_type not in ("fido2", "passkey"):
                continue
            # Asked again here, not only at begin: the allow-list has
            # already left the browser by then, and a cascade can be
            # turned off between the two requests.
            # Both sides, as at begin. On a reauth forward we are the
            # account's home site and the portal's verdict travels in
            # the command. Nothing forwarded means we are the portal
            # ourselves, and then the account's cascade already ends
            # here -- asking our site again on top would let it win
            # over a user or unit override that is meant to win.
            peer_passkeys = command_args.get('_passkeys_allowed_here')
            peer_fido2 = command_args.get('_fido2_allowed_here')
            if x_verify_token.token_type == "passkey" \
            and (peer_passkeys is False
                or not _sso_allow_passkeys_for_user(user)):
                continue
            if x_verify_token.token_type == "fido2" \
            and (peer_fido2 is False
                or not _sso_allow_fido2_for_user(user)):
                continue
            token = t
            verify_token = x_verify_token
            break

        # Cross-site reauth forward from a peer authd (the SSO session
        # is on the caller, not here): verify the fido2 assertion, sign
        # a JWT proving it, and return. The caller validates the JWT
        # and bumps its own session's reauth_time -- we do not touch
        # session state locally.
        if reauth_forward:
            if token is None:
                log_msg = _("Reauth-forward: matched FIDO2 token not found.", log=True)[1]
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            try:
                verify_ok = verify_token.verify(smartcard_data=smartcard_data)
            except Exception as e:
                log_msg = _("Reauth-forward: FIDO2 verify failed: {err}", log=True)[1]
                log_msg = log_msg.format(err=e)
                self.logger.warning(log_msg)
                verify_ok = False
            if not verify_ok:
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            jwt_reason = command_args.get('jwt_reason')
            jwt_challenge = command_args.get('jwt_challenge')
            try:
                # src_token=verify_token (not the local link token) so
                # the JWT's src_token/login_token both point to the
                # dst_token -- portal validates via verify_redirect_jwt
                # with dst_token=src_token=verify_token, no need to
                # transmit the local link's uuid across sites.
                proof_jwt = self.gen_jwt(username=verify_token.owner,
                                        token=verify_token,
                                        src_token=verify_token,
                                        reason=jwt_reason,
                                        access_group=None,
                                        challenge=jwt_challenge)
            except Exception as e:
                log_msg = _("Reauth-forward: gen_jwt failed: {err}", log=True)[1]
                log_msg = log_msg.format(err=e)
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            return self.build_response(True, {
                'status':     True,
                'jwt':        proof_jwt,
                'token_uuid': verify_token.uuid,
            })

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
            if token is None:
                log_msg = _("Reauth: matched FIDO2 token not found.", log=True)[1]
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            if verify_token.site != config.site:
                # A link to another site: the credential is verified
                # where it lives, or the replay counter would be raised
                # here while the owning site keeps accepting the same
                # assertion.
                verify_ok = self.reauth_redirect(user=user,
                                            token=token,
                                            verify_token=verify_token,
                                            smartcard_data=smartcard_data,
                                            client=client,
                                            client_ip=client_ip)
            else:
                try:
                    verify_ok = verify_token.verify(smartcard_data=smartcard_data)
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
                user_token=token,
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

    def _tiqr_sso_accessgroup(self):
        """ The access group a tiqr login lands in.

        The browser half of the flow talks to authd as the SSO client,
        so this is the group the token has to be valid for and the
        group a block would be counted in. """
        return backend.get_object(object_type="accessgroup",
                                name=config.sso_access_group,
                                realm=config.realm,
                                site=config.site)

    def _tiqr_block_duration(self):
        """ How long a block lasts, in minutes, as the apps show it.

        OTPme lifts a block after max_fail_reset seconds without a
        further attempt. Zero means it stands until an admin lifts it,
        and a missing duration is exactly how the apps read that. """
        sso_ag = self._tiqr_sso_accessgroup()
        if sso_ag is None:
            return None
        max_fail_reset = sso_ag.max_fail_reset
        if not max_fail_reset:
            return None
        # Round up: telling the user 0 minutes would be worse than
        # telling them 1.
        return -(-int(max_fail_reset) // 60)

    def _get_tiqr_tokens(self, user):
        """ Enabled, enrolled tiqr tokens of a user.

        The single choke point of the tiqr login: begin, response and
        the typed-OTP fallback all come through here, so the cascade is
        asked once, here.

        For an account of another site, two answers are needed. The
        cascade belongs to the account and ends at its home site;
        whether tiqr may be used at all is the portal's own to say, and
        this runs on the portal -- unlike the FIDO2 begin, which
        redirects and has to forward its verdict. Either one refusing
        is enough.

        For an account of our own site the cascade already ends here,
        user and unit overrides included, so the site value is not
        asked a second time. """
        if user.site != config.site \
        and not _sso_allowed_here("sso_allow_tiqr"):
            return []
        if not _sso_allow_tiqr_for_user(user):
            return []
        tiqr_tokens = []
        sso_ag = self._tiqr_sso_accessgroup()
        user_tokens = user.get_tokens(access_group=sso_ag,
                                    return_type="instance")
        for token in user_tokens:
            verify_token = token
            if token.destination_token:
                verify_token = token.dst_token
                if not verify_token:
                    continue
            if verify_token.token_type != "tiqr":
                continue
            if not verify_token.enabled:
                continue
            if not verify_token.deployed:
                continue
            tiqr_tokens.append((token, verify_token))
        return tiqr_tokens

    def _tiqr_challenge_len(self, verify_token):
        """ How long a challenge this token's OCRA suite asks for. """
        suite_config = ocra.get_suite(verify_token.ocra_suite)
        return suite_config.data_input.Q[1]

    def _tiqr_max_age(self):
        """ How long a tiqr challenge stays answerable. """
        my_site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)
        return my_site.get_config_parameter("tiqr_challenge_expiry")

    def tiqr_auth_begin(self, username, command_args):
        """ Hand the browser a challenge. Writes nothing.

        Session key, challenge and poll id all come out of the site
        secret and one fresh random session key, so no record has to
        exist before the phone has proven it holds a token. See
        protocols/tiqr_helpers.py for why that matters.

        An unknown user, or one without a usable tiqr token, gets the
        same shaped answer as anybody else -- otherwise the response
        says which accounts have tiqr. """
        begin_start = time.monotonic()
        try:
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            user = backend.get_object(object_type="user",
                                    name=username,
                                    realm=config.realm,
                                    run_policies=True,
                                    _no_func_cache=True)
            # The identifier, not the display name: it goes into the
            # URL where the app reads it as a host and canonicalises it.
            # Has to match what the enrollment metadata declared, which
            # is why both come from the same helper.
            display_name = my_site.get_config_parameter("tiqr_service_display_name")
            # Everything below has to come out the same shape whether
            # the user is unknown, known without tiqr, or known with
            # tiqr. The URL naming an identity only in the last case
            # would say who uses tiqr -- the very thing fido2 spends
            # its decoy credentials on hiding.
            identity_id = username
            site_suite = my_site.get_config_parameter("tiqr_ocra_suite")
            challenge_len = ocra.get_suite(site_suite).data_input.Q[1]
            if user is not None:
                tiqr_tokens = self._get_tiqr_tokens(user)
                if tiqr_tokens:
                    verify_token = tiqr_tokens[0][1]
                    identity_id = verify_token.identity_id or user.name
                    challenge_len = self._tiqr_challenge_len(verify_token)
            # A user we cannot name still gets a session key: the QR
            # scans, the app just never finds a matching identity.
            user_uuid = getattr(user, 'uuid', None) or ""

            tiqr_secret = tiqr_token.get_site_secret()
            session_key = tiqr_helpers.gen_session_key(time.time())
            challenge = tiqr_helpers.derive_challenge(tiqr_secret,
                                                    session_key,
                                                    user_uuid,
                                                    challenge_len)
            poll_id = tiqr_helpers.derive_poll_id(tiqr_secret, session_key)

            service_identifier = tiqr_helpers.canonical_service_identifier(
                                                    display_name, config.realm)
            return_url = command_args.get('return_url')
            auth_scheme = my_site.get_config_parameter("tiqr_auth_scheme")
            auth_url = tiqr_helpers.build_auth_url(auth_scheme,
                                                service_identifier,
                                                session_key,
                                                challenge,
                                                identity_id=identity_id,
                                                return_url=return_url)
            # The same URL twice: as a QR for a second device, and as a
            # link the app opens directly when the browser is on the
            # phone itself.
            try:
                qrcode_data = qrcode.gen_qrcode(auth_url, fmt="svg")
                if isinstance(qrcode_data, bytes):
                    qrcode_data = qrcode_data.decode('utf-8')
                qrcode_img = ("data:image/svg+xml;base64,"
                            + base64.b64encode(qrcode_data.encode()).decode())
            except Exception as e:
                log_msg = _("tiqr: QR code generation failed: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                return self.build_response(False, "AUTHD_FAILED")
            message = {
                        'poll_id'       : poll_id,
                        'session_key'   : session_key,
                        'auth_url'      : auth_url,
                        'qrcode_img'    : qrcode_img,
                    }
            return self.build_response(True, message)
        finally:
            _pad_min_duration(begin_start)

    def tiqr_auth_response(self, command_args, client, client_ip):
        """ Take the phone's answer.

        Unauthenticated by nature -- what authenticates it is the OCRA
        response itself, and nothing is written until that verifies, so
        a caller without a token secret leaves no trace. """
        session_key = command_args.get('session_key')
        response = command_args.get('response')
        identity_id = command_args.get('identity_id')
        if not session_key or not response:
            return self.build_response(False, TIQR_AUTH_INVALID_CHALLENGE)
        if not identity_id:
            return self.build_response(False, TIQR_AUTH_INVALID_USERID)

        now = time.time()
        max_age = self._tiqr_max_age()
        try:
            expired = tiqr_helpers.session_key_expired(session_key, max_age, now)
        except ValueError:
            expired = True
        if expired:
            return self.build_response(False, TIQR_AUTH_INVALID_CHALLENGE)

        user = backend.get_object(object_type="user",
                                name=identity_id,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if user is None:
            return self.build_response(False, TIQR_AUTH_INVALID_USERID)
        tiqr_secret = tiqr_token.get_site_secret()
        # Whichever of the user's phones answered. Trying them all is
        # what makes several enrolled devices work.
        matched_token = None
        matched_verify_token = None
        tiqr_tokens = self._get_tiqr_tokens(user)
        for token, verify_token in tiqr_tokens:
            challenge_len = self._tiqr_challenge_len(verify_token)
            challenge = tiqr_helpers.derive_challenge(tiqr_secret,
                                                    session_key,
                                                    user.uuid,
                                                    challenge_len)
            token_auth_data = {
                                'challenge'     : challenge,
                                'response'      : response,
                                'session_key'   : session_key,
                            }
            if not self._tiqr_verify_response(user, token, verify_token,
                                            token_auth_data,
                                            client, client_ip):
                continue
            matched_token = token
            matched_verify_token = verify_token
            break

        if matched_verify_token is None:
            log_msg = _("tiqr: no token matched the response: {user}", log=True)[1]
            log_msg = log_msg.format(user=user.name)
            self.logger.warning(log_msg)
            return self.build_response(False, TIQR_AUTH_INVALID_RESPONSE)

        # A blocked user gets no session out of this answer, so say so
        # rather than let the app report a success that dies silently on
        # the browser's next poll. The block itself is the shared one --
        # counted by user.authenticate() on every login path, lifted by
        # 'otpme-user unblock' or by max_fail_reset.
        #
        # Asked only now that the response verified. Earlier it would
        # tell anyone who knows a username whether that account is
        # blocked.
        if user.is_blocked(config.sso_access_group,
                            realm=config.realm,
                            site=config.site):
            log_msg = _("tiqr: user '{user}' is blocked.", log=True)[1]
            log_msg = log_msg.format(user=user.name)
            self.logger.warning(log_msg)
            blocked = {'result': TIQR_AUTH_ACCOUNT_BLOCKED}
            duration = self._tiqr_block_duration()
            if duration is not None:
                blocked['duration'] = duration
            return self.build_response(False, blocked)

        # Somebody holds a token secret, so writing is safe from here.
        poll_id = tiqr_helpers.derive_poll_id(tiqr_secret, session_key)
        expiry = tiqr_helpers.get_session_key_time(session_key) + max_age
        state_id = _tiqr_result_state_id(poll_id)
        if state_id in multiprocessing.tiqr_auth_results:
            # Same challenge answered twice inside its window. The first
            # answer stands.
            log_msg = _("tiqr: duplicate response for one challenge.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(True, TIQR_AUTH_OK)
        # The entry outlives the challenge by a minute so that a poll
        # arriving just after the window still gets "expired" rather
        # than "keep waiting" -- collecting it is refused on the stored
        # expiry below, not on the entry still being there.
        ttl = int(expiry - now) + TIQR_RESULT_TTL_GRACE
        multiprocessing.tiqr_auth_results.add(key=state_id,
                            value={
                                'user_uuid'     : user.uuid,
                                'token_uuid'    : matched_token.uuid,
                                'session_key'   : session_key,
                                'response'      : response,
                                'expiry'        : expiry,
                                },
                            expire=ttl)
        # Waits for the other nodes: the browser polls wherever the load
        # balancer sends it, and it may get there before we answer the
        # phone.
        cluster_sync_state(state_id=state_id, expiry=ttl)
        log_msg = _("tiqr: response accepted for token {token}", log=True)[1]
        log_msg = log_msg.format(token=matched_verify_token.rel_path)
        self.logger.info(log_msg)
        return self.build_response(True, TIQR_AUTH_OK)

    def _burn_tiqr_result(self, poll_id):
        """ Consume the result for a poll id, if there is one.

        Called on both collection paths so an answered challenge can be
        turned into a session exactly once. Without it the manual OTP
        entry and the still running poll could each produce a session
        from the same answer.

        And cluster wide, for the same reason the WebAuthn states are
        dropped that way: the answer was handed to every node, so one
        that never hears it is spent would hand out a second session
        for it. """
        state_id = _tiqr_result_state_id(poll_id)
        try:
            multiprocessing.tiqr_auth_results.delete(state_id)
        except KeyError:
            return
        except Exception as e:
            log_msg = _("tiqr: failed to drop auth result: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return
        cluster_sync_state_delete(state_id)

    def _tiqr_login(self, user, token, token_auth_data, client, client_ip,
        sso_challenge):
        """ Run the answered challenge through the normal auth path.

        Everything that hangs off a login -- access groups, policies,
        session creation, audit, failed-login counting -- happens here,
        exactly where it happens for every other token type. """
        try:
            auth_status = user.authenticate(
                    auth_type="tiqr",
                    auth_mode="tiqr",
                    client=client,
                    client_ip=client_ip,
                    realm_login=False,
                    realm_logout=False,
                    token_auth_data=token_auth_data,
                    user_token=token,
                )
        except Exception as e:
            log_msg = _("tiqr authentication failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.critical(log_msg)
            return False, {'message':'Login failed.', 'status':False}
        if not auth_status['status']:
            return False, {'message':'Login failed.', 'status':False}
        try:
            auth_token = auth_status.pop('token')
        except KeyError:
            auth_token = None
        # Gen JWT for SSO auth.
        if auth_token and client == config.sso_client_name:
            jwt_ag = f"{config.site}/{config.sso_access_group}"
            try:
                sso_jwt = self.gen_jwt(username=user.name,
                                    token=auth_token,
                                    reason="SSO_AUTH",
                                    challenge=sso_challenge,
                                    access_group=jwt_ag,
                                    sso=True)
            except AccessDenied as e:
                message = _("Unable to gen SSO JWT: {e}")
                message = message.format(e=e)
                return False, message
            auth_status['sso_jwt'] = sso_jwt
            auth_status['app_data'] = self.get_apps(auth_token)
        return True, auth_status

    def _tiqr_verify_response(self, user, token, verify_token,
        token_auth_data, client, client_ip):
        """ Does this OCRA response belong to this token?

        The arithmetic only. Replay protection is the caller's job --
        see tiqr.verify_ocra() for why a six digit response cannot be a
        used-OTP key.

        A token of another site is verified where it lives. Its secret
        is not ours to hold, so asking the owning site is the only way
        to find out, and it is also the site whose word counts. """
        if token.site == config.site:
            return verify_token.verify_ocra(token_auth_data['challenge'],
                                            token_auth_data['session_key'],
                                            token_auth_data['response'])
        verify_args = {
                        'username'          : user.name,
                        # Nothing to prove to anybody: the answer is
                        # consumed right here, by us.
                        'gen_jwt'           : False,
                        'token_uuid'        : token.uuid,
                        'token_auth_data'   : token_auth_data,
                        'client'            : client,
                        'client_ip'         : client_ip,
                    }
        status, \
        verify_response = self.authd_redirect_command(command="token_verify_tiqr",
                                            user=user,
                                            command_args=verify_args,
                                            site=token.site)
        return bool(status)

    def _tiqr_login_remote(self, user, token, token_auth_data, client,
        client_ip, sso_challenge):
        """ The same login as _tiqr_login for a token of another site.

        Split in two: the site owning the token verifies it and signs
        that it did, and the session is created here, where the browser
        is. The SSO JWT has to come from there as well -- the portal
        verifies it against the token site's key, and only that site
        holds the private half.

        Returns the same (status, response) pair as _tiqr_login. """
        failed = {'message':'Login failed.', 'status':False}
        my_site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)
        jwt_reason = "AUTH"
        sso_jwt_ag = f"{config.site}/{config.sso_access_group}"
        # What we hand the other site to sign back to us, so its answer
        # can only be an answer to this request.
        jwt_data = {
                    'user'          : user.name,
                    'realm'         : config.realm,
                    'site'          : config.site,
                    'reason'        : jwt_reason,
                    'access_group'  : sso_jwt_ag,
                    'challenge'     : stuff.gen_secret(len=32),
                    'exp'           : time.time() + 60,
                }
        redirect_challenge = jwt.encode(payload=jwt_data,
                                        key=my_site._key,
                                        algorithm='RS256')
        verify_args = {
                        'username'          : user.name,
                        'token_uuid'        : token.uuid,
                        'client'            : client,
                        'client_ip'         : client_ip,
                        'sso_login'         : True,
                        'sso_ag'            : sso_jwt_ag,
                        'sso_challenge'     : sso_challenge,
                        'token_auth_data'   : token_auth_data,
                        'jwt_reason'        : jwt_reason,
                        'jwt_access_group'  : sso_jwt_ag,
                        'jwt_challenge'     : redirect_challenge,
                    }
        # Verify token on home site.
        status, \
        response = self.authd_redirect_command(command="token_verify_tiqr",
                                            user=user,
                                            command_args=verify_args,
                                            site=token.site)
        if not status or not isinstance(response, dict):
            log_msg = _("tiqr: redirected verify failed for token '{token}'.", log=True)[1]
            log_msg = log_msg.format(token=token.rel_path)
            self.logger.warning(log_msg)
            return False, failed
        redirect_response = response.get('jwt')
        sso_jwt = response.get('sso_jwt')
        if not redirect_response or not sso_jwt:
            log_msg = _("tiqr: redirected verify answered without a JWT: {token}", log=True)[1]
            log_msg = log_msg.format(token=token.rel_path)
            self.logger.warning(log_msg)
            return False, failed
        # Try local JWT auth.
        try:
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
        except Exception as e:
            log_msg = _("tiqr JWT authentication failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.critical(log_msg)
            return False, failed
        if not auth_response['status']:
            return False, failed
        # Add missing data.
        auth_token = auth_response.pop('token')
        auth_response['sso_jwt'] = sso_jwt
        auth_response['app_data'] = self.get_apps(auth_token)
        return True, auth_response

    def _tiqr_reauth(self, user, token, verify_token, token_auth_data,
        reauth_session_uuid, client, client_ip):
        """ Step-up re-authentication with a tiqr token.

        The user is logged in already, so this is not a login: the
        response is verified and reauth_time is bumped on the SSO
        session that exists. No user.authenticate(), no second session,
        no new cookie -- the same shape the FIDO2 step-up in
        fido2_auth_complete() has.

        Returns a finished response, both call sites hand it straight
        back. """
        failed = {'message':'Login failed.', 'status':False}
        if not reauth_session_uuid:
            log_msg = _("Reauth: session_uuid missing.", log=True)[1]
            self.logger.warning(log_msg)
            return self.build_response(False, failed)
        try:
            verify_ok = self._tiqr_verify_response(user, token, verify_token,
                                                token_auth_data,
                                                client, client_ip)
        except Exception as e:
            log_msg = _("Reauth: tiqr verify failed: {err}", log=True)[1]
            log_msg = log_msg.format(err=e)
            self.logger.warning(log_msg)
            verify_ok = False
        if not verify_ok:
            emit_audit("Auth", "reauth_failed",
                            level='warning',
                            user=user.name,
                            token=token.name,
                            reason='tiqr_verify_failed',
                            ip=client_ip)
            return self.build_response(False, failed)
        sso_session = backend.get_object(object_type="session",
                                        uuid=reauth_session_uuid)
        if sso_session is None or sso_session.user_uuid != user.uuid:
            emit_audit("Auth", "reauth_failed",
                            level='warning',
                            user=user.name,
                            token=token.name,
                            session=reauth_session_uuid,
                            reason='session_user_mismatch',
                            ip=client_ip)
            return self.build_response(False, failed)
        try:
            sso_session.update_reauth_time(wait_for_cluster_writes=True)
        except Exception as e:
            log_msg = _("Reauth: failed to persist reauth_time: {err}", log=True)[1]
            log_msg = log_msg.format(err=e)
            self.logger.warning(log_msg)
            return self.build_response(False, failed)
        emit_audit("Auth", "reauth_success",
                        user=user.name,
                        token=token.name,
                        session=sso_session.session_id,
                        ip=client_ip)
        return self.build_response(True, {'status':True})

    def tiqr_auth_status(self, client, client_ip, sso_challenge, command_args):
        """ The browser collecting its result.

        The login runs here rather than on the phone's request, so the
        session records the browser's address and not the phone's, and
        a token disabled in the meantime still stops the login.

        Short poll: this answers right away, it never holds the request
        open. A long poll would tie up a gunicorn worker per waiting
        browser. """
        poll_id = command_args.get('poll_id')
        # Step-up reauth marker set by the portal's /reauth page. The
        # session uuid comes from the SSO cookie and is cross-checked
        # against the user below.
        reauth = bool(command_args.get('reauth', False))
        reauth_session_uuid = command_args.get('session_uuid')
        pending = {'status':False, 'tiqr_status':'pending'}
        expired = {'status':False, 'tiqr_status':'challenge-expired'}
        if not poll_id:
            return self.build_response(True, pending)
        try:
            auth_result = multiprocessing.tiqr_auth_results.get(
                                        _tiqr_result_state_id(poll_id))
        except KeyError:
            return self.build_response(True, pending)
        if auth_result['expiry'] and time.time() > auth_result['expiry']:
            return self.build_response(True, expired)

        token = backend.get_object(uuid=auth_result['token_uuid'])
        user = backend.get_object(uuid=auth_result['user_uuid'],
                                run_policies=True,
                                _no_func_cache=True)
        if token is None or user is None:
            return self.build_response(True, expired)
        # Asked again here, not only where the answer was accepted: a
        # result already waiting when either side is turned off must
        # not still be collectable for the minutes it lives. Same two
        # answers as _get_tiqr_tokens(), and the portal's only for an
        # account of another site.
        if user.site != config.site \
        and not _sso_allowed_here("sso_allow_tiqr"):
            return self.build_response(True, expired)
        if not _sso_allow_tiqr_for_user(user):
            return self.build_response(True, expired)

        verify_token = token
        if token.destination_token:
            verify_token = token.dst_token
        if verify_token is None:
            return self.build_response(True, expired)

        challenge_len = self._tiqr_challenge_len(verify_token)
        challenge = tiqr_helpers.derive_challenge(tiqr_token.get_site_secret(),
                                                auth_result['session_key'],
                                                user.uuid,
                                                challenge_len)
        token_auth_data = {
                        'challenge'     : challenge,
                        'session_key'   : auth_result['session_key'],
                        'response'      : auth_result['response'],
                    }

        # One collection per answered challenge, success or not. A phone
        # request replayed inside the window would otherwise be
        # collectable a second time.
        try:
            # Step-up: no login, no session, just a fresh reauth_time on
            # the session the user already has.
            if reauth:
                return self._tiqr_reauth(user, token, verify_token,
                                        token_auth_data,
                                        reauth_session_uuid,
                                        client, client_ip)
            if token.site == config.site:
                auth_status, auth_response = self._tiqr_login(user, token,
                                                            token_auth_data,
                                                            client, client_ip,
                                                            sso_challenge)
            else:
                auth_status, auth_response = self._tiqr_login_remote(user, token,
                                                            token_auth_data,
                                                            client, client_ip,
                                                            sso_challenge)
        finally:
            self._burn_tiqr_result(poll_id)
        if not auth_status:
            return self.build_response(False, auth_response)
        auth_response['tiqr_status'] = "ok"
        return self.build_response(True, auth_response)

    def tiqr_auth_otp(self, client, client_ip, sso_challenge, command_args):
        """ The fallback where the user types the response.

        The tiqr apps show the six digits when they cannot reach us. The
        browser still holds the session key, so this needs no result
        object of its own. """
        session_key = command_args.get('session_key')
        response = command_args.get('response')
        username = command_args.get('username')
        # Same step-up marker the poll path takes, for the user who
        # types the code instead of letting the phone answer.
        reauth = bool(command_args.get('reauth', False))
        reauth_session_uuid = command_args.get('session_uuid')
        failed = {'message':'Login failed.', 'status':False}
        if not session_key or not response or not username:
            return self.build_response(False, failed)

        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm,
                                run_policies=True,
                                _no_func_cache=True)
        if user is None:
            return self.build_response(False, failed)
        # The challenge is ours -- it was derived from this site's tiqr
        # secret in tiqr_auth_begin -- so the session belongs here, and
        # only the verification of the response travels to the site
        # owning the token. Redirecting the whole command instead would
        # create the session, the SSO JWT and the audit trail on the
        # user's home site, where the browser never was.
        now = time.time()
        max_age = self._tiqr_max_age()
        try:
            expired = tiqr_helpers.session_key_expired(session_key, max_age, now)
        except ValueError:
            expired = True
        if expired:
            return self.build_response(False, failed)

        tiqr_secret = tiqr_token.get_site_secret()
        for token, verify_token in self._get_tiqr_tokens(user):
            challenge_len = self._tiqr_challenge_len(verify_token)
            challenge = tiqr_helpers.derive_challenge(tiqr_secret,
                                                    session_key,
                                                    user.uuid,
                                                    challenge_len)
            token_auth_data = {
                            'challenge'     : challenge,
                            'session_key'   : session_key,
                            'response'      : response,
                        }
            if not self._tiqr_verify_response(user, token, verify_token,
                                            token_auth_data,
                                            client, client_ip):
                continue
            # The phone may have got through after all, in which case a
            # result is waiting and the still running poll would make a
            # second session out of the same answer. Take it first.
            poll_id = tiqr_helpers.derive_poll_id(tiqr_secret, session_key)
            self._burn_tiqr_result(poll_id)
            if reauth:
                return self._tiqr_reauth(user, token, verify_token,
                                        token_auth_data,
                                        reauth_session_uuid,
                                        client, client_ip)
            if token.site == config.site:
                status, auth_status = self._tiqr_login(user, token,
                                                    token_auth_data,
                                                    client, client_ip,
                                                    sso_challenge)
            else:
                status, auth_status = self._tiqr_login_remote(user, token,
                                                    token_auth_data,
                                                    client, client_ip,
                                                    sso_challenge)
            if not status:
                return self.build_response(False, auth_status)
            return self.build_response(True, auth_status)
        return self.build_response(False, failed)

    def reauth_redirect(self, user, token, verify_token, smartcard_data,
        client, client_ip):
        """ Have the site owning a linked token verify the assertion.

        The step-up reauth verifies the credential itself instead of
        going through user.authenticate(), so it also has to make the
        redirect itself when the destination of a link lives elsewhere.
        """
        jwt_reason = "DST_TOKEN_VERIFY"
        jwt_challenge = stuff.gen_secret(32)
        verify_args = {
                    'username'          : user.name,
                    'token_uuid'        : token.uuid,
                    'jwt_reason'        : jwt_reason,
                    'jwt_challenge'     : jwt_challenge,
                    'smartcard_data'    : smartcard_data,
                    'client'            : client,
                    'client_ip'         : client_ip,
                    }
        status, \
        response = self.authd_redirect_command(command="token_verify_smartcard",
                                            user=user,
                                            command_args=verify_args,
                                            site=verify_token.site)
        if not status:
            log_msg = _("Reauth: redirected verify failed: {token}", log=True)[1]
            log_msg = log_msg.format(token=verify_token.rel_path)
            self.logger.warning(log_msg)
            return False
        return self.verify_redirect_jwt(response, verify_token, token,
                                    jwt_challenge, jwt_reason)

    def reauth_redirect_password(self, user, token, verify_token,
        password, client, client_ip):
        """ Cross-site password/OTP reauth: same shape as ``reauth_redirect``
        but sends ``token_verify`` (clear-text) to the token's home site
        instead of ``token_verify_smartcard``. Used from the ``verify``
        reauth branch when the SSO session's auth token (or its dst
        token) lives elsewhere. """
        jwt_reason = "DST_TOKEN_VERIFY"
        jwt_challenge = stuff.gen_secret(32)
        verify_args = {
                    'username'          : user.name,
                    'token_uuid'        : token.uuid,
                    'jwt_reason'        : jwt_reason,
                    'jwt_challenge'     : jwt_challenge,
                    'password'          : password,
                    'client'            : client,
                    'client_ip'         : client_ip,
                    }
        status, \
        response = self.authd_redirect_command(command="token_verify",
                                            user=user,
                                            command_args=verify_args,
                                            site=verify_token.site)
        if not status:
            log_msg = _("Reauth: redirected password verify failed: {token}", log=True)[1]
            log_msg = log_msg.format(token=verify_token.rel_path)
            self.logger.warning(log_msg)
            return False
        return self.verify_redirect_jwt(response, verify_token, token,
                                    jwt_challenge, jwt_reason)

    def verify_redirect_jwt(self, response, dst_token, src_token,
        jwt_challenge, jwt_reason):
        """ Verify the JWT of the site we redirected a verify to.

        We are about to tell whoever asked us that this token verified,
        and we sign that statement ourselves -- but we did not verify
        anything, another site did. Its JWT is what we have to go on,
        so check it before passing its word off as our own.
        """
        if not isinstance(response, dict):
            log_msg = _("Redirected verify answered without data: {token}", log=True)[1]
            log_msg = log_msg.format(token=dst_token.rel_path)
            self.logger.warning(log_msg)
            return False

        dst_jwt = response.get('jwt')
        if not dst_jwt:
            log_msg = _("Redirected verify answered without a JWT: {token}", log=True)[1]
            log_msg = log_msg.format(token=dst_token.rel_path)
            self.logger.warning(log_msg)
            return False

        dst_site = backend.get_object(object_type="site",
                                    uuid=dst_token.site_uuid)
        if not dst_site:
            log_msg = _("Unknown site of destination token: {token}", log=True)[1]
            log_msg = log_msg.format(token=dst_token.rel_path)
            self.logger.warning(log_msg)
            return False

        try:
            jwt_data = jwt.decode(jwt=dst_jwt,
                                key=dst_site._cert_public_key,
                                algorithm='RS256')
        except Exception as e:
            log_msg = _("JWT of redirected verify failed verification: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return False

        # The challenge and the reason we passed on tie the answer to
        # this request, the two tokens tie it to what we asked about.
        checks = [
                ('challenge', jwt_challenge),
                ('reason', jwt_reason),
                ('login_token', dst_token.uuid),
                ('src_token', src_token.uuid),
                ]
        for x_field, x_wanted in checks:
            if jwt_data.get(x_field) == x_wanted:
                continue
            log_msg = _("JWT of redirected verify has wrong {field}: {token}", log=True)[1]
            log_msg = log_msg.format(field=x_field, token=dst_token.rel_path)
            self.logger.warning(log_msg)
            return False

        return True

    def token_verify(self, user, auth_type, command, command_args,
        password=None, mschap_challenge=None, mschap_response=None,
        smartcard_data=None, token_auth_data=None):
        try:
            token_uuid = command_args['token_uuid']
        except Exception:
            token_uuid = None
        try:
            gen_jwt = command_args['gen_jwt']
        except Exception:
            gen_jwt = True
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
        try:
            dot1x_auth = command_args['dot1x_auth']
        except Exception:
            dot1x_auth = False

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
        if command == "token_verify_tiqr":
            token_verify_parms = {
                    'auth_type'         : "tiqr",
                    'token_auth_data'   : token_auth_data,
                    }
        if command == "token_verify_smartcard":
            token_verify_parms = {
                    'auth_type'         : "smartcard",
                    'smartcard_data'    : smartcard_data,
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
            auth_state = state_data['state']
            smartcard_data['auth_state'] = auth_state
            token_verify_parms = {
                    'auth_type'     : "smartcard",
                    'smartcard_data': smartcard_data,
                    }
        verify_token = None
        if token_uuid:
            verify_token = backend.get_object(object_type="token",
                                            uuid=token_uuid)
            if not verify_token:
                status = False
                log_msg = _("Unknown token: {token}.", log=True)[1]
                log_msg = log_msg.format(token=token_uuid)
                self.logger.warning(log_msg)
                message = "AUTH_FAILED"
                return self.build_response(status, message)
            # The caller names the user and the token independently of
            # each other, and nothing tied the two together so far.
            # Every check made above was made for <user>, so a token of
            # someone else would decide this request by a credential
            # the named user never owned.
            if verify_token.uuid not in user.tokens:
                emit_audit("AuthZ", "denied",
                           level='warning',
                           actor=verify_token.rel_path,
                           user=user.name,
                           method='verify_token',
                           reason='token_owner_mismatch')
                status = False
                log_msg = _("Token '{token}' is not a token of user: {user}", log=True)[1]
                log_msg = log_msg.format(token=verify_token.rel_path, user=user.name)
                self.logger.warning(log_msg)
                message = "AUTH_FAILED"
                return self.build_response(status, message)
            user_tokens = [verify_token]
        else:
            user_tokens = user.get_tokens(return_type="instance")
        # Mirror the fido2_auth_begin gate: on the cross-site verify
        # path (originator redirected here) an assertion signed with a
        # passkey must not be accepted when the user's cascade doesn't
        # resolve to True. Resolve once, outside the loop.
        #
        # Both sides again. We are the account's home site here, so our
        # own config would answer for the account a second time -- what
        # the portal allows travels in the command, set by
        # redirect_fido2_complete(). Absent means nobody forwarded one
        # and there is nothing to add.
        fido2_passkeys_allowed = None
        fido2_keys_allowed = None
        if command == "token_verify_fido2":
            peer_fido2 = command_args.get('_fido2_allowed_here')
            peer_passkeys = command_args.get('_passkeys_allowed_here')
            fido2_passkeys_allowed = (peer_passkeys is not False
                                    and _sso_allow_passkeys_for_user(user))
            fido2_keys_allowed = (peer_fido2 is not False
                                and _sso_allow_fido2_for_user(user))
        # Get accessgroup if given.
        if jwt_access_group:
            try:
                ag_site = jwt_access_group.split("/")[0]
                ag_name = jwt_access_group.split("/")[1]
            except IndexError:
                emit_audit("AuthZ", "denied",
                           level='warning',
                           actor=jwt_access_group,
                           user=user.name,
                           method='verify_token',
                           reason='invalid_access_group_name',
                           ag=jwt_access_group)
                status = status_codes.ERR
                message = _("Invalid accessgroup name: {access_group}")
                message = message.format(access_group=jwt_access_group)
                return self.build_response(status, message)
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=ag_name,
                                    realm=config.realm,
                                    site=ag_site,
                                    return_type="instance")
            if not result:
                emit_audit("AuthZ", "denied",
                           level='warning',
                           actor=jwt_access_group,
                           user=user.name,
                           method='verify_token',
                           reason='unknown_access_group',
                           ag=jwt_access_group)
                status = status_codes.ERR
                message = _("Invalid accessgroup name: {access_group}")
                message = message.format(access_group=jwt_access_group)
                return self.build_response(status, message)
            jwt_ag = result[0]
        src_token = None
        dst_token = None
        auth_token = None
        tried_tokens = []
        redirect_response = None
        for x_token in user_tokens:
            # Whose assignment this is asks about the token that was
            # selected, not about the one holding the secret: a link is
            # what gets assigned to an accessgroup, what its destination
            # is assigned to is a matter for the site that owns it.
            # Checked before the link is resolved, so that both cases
            # below are judged by the same token.
            if jwt_access_group:
                if not jwt_ag.is_assigned_token(x_token.uuid):
                    continue
            if x_token.destination_token:
                if not x_token.dst_token:
                    continue
                dst_token = x_token.dst_token
                if dst_token.site == config.site:
                    src_token = x_token
                    x_token = dst_token
                else:
                    verify_args = command_args.copy()
                    # The accessgroup belongs to whoever asked us, and
                    # the token assigned to it is the link we just
                    # checked. The next site holds neither of the two,
                    # so passing it on would only make it judge a token
                    # that was never assigned there.
                    try:
                        verify_args.pop("jwt_access_group")
                    except KeyError:
                        pass
                    verify_args['token_uuid'] = x_token.uuid
                    # Our state id means nothing at the next site, and
                    # popping it above left the command without one
                    # anyway. It does not need one: the state itself
                    # travels in <smartcard_data>, where we just put it,
                    # and that is what token_verify_smartcard reads.
                    x_command = command
                    if command == "token_verify_fido2":
                        x_command = "token_verify_smartcard"
                    status, \
                    response = self.authd_redirect_command(command=x_command,
                                                    user=user,
                                                    command_args=verify_args,
                                                    site=dst_token.site)
                    tried_tokens.append(x_token.oid.read_oid)
                    if not status:
                        continue
                    if not self.verify_redirect_jwt(response, dst_token,
                                                x_token, jwt_challenge,
                                                jwt_reason):
                        continue
                    # Verified by another site, so whatever we hand back
                    # has to come out of its answer -- verify() never
                    # ran here, and <verify_status> holds nothing of
                    # this token.
                    redirect_response = response
                    auth_token = x_token
                    break
            if command == "token_verify":
                if x_token.pass_type != "static":
                    if x_token.pass_type != "otp":
                        continue
            if command == "token_verify_mschap":
                if not x_token.mschap_enabled:
                    continue
            if command == "token_verify_tiqr":
                if x_token.pass_type != "tiqr":
                    continue
            if command == "token_verify_smartcard":
                if x_token.pass_type != "smartcard":
                    continue
            if command == "token_verify_fido2":
                if x_token.token_type not in ("fido2", "passkey"):
                    continue
                if x_token.token_type == "passkey" and not fido2_passkeys_allowed:
                    continue
                if x_token.token_type == "fido2" and not fido2_keys_allowed:
                    continue
            if dot1x_auth:
                if not x_token.support_dot1x:
                    continue
            tried_tokens.append(x_token.oid.read_oid)
            if dot1x_auth:
                try:
                    verify_status = x_token.verify_dot1x(**token_verify_parms)
                except Exception as e:
                    log_msg = _("Verification (dot1x) of token '{token_name}' returned error: {error}", log=True)[1]
                    log_msg = log_msg.format(token_name=x_token.name, error=e)
                    self.logger.critical(log_msg)
                    continue
            else:
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
        if not auth_token \
        and (command == "token_verify_mschap" or command == "token_verify"):
            for x_token in user_tokens:
                _verify_token = x_token
                if x_token.destination_token:
                    if not x_token.dst_token:
                        continue
                    _verify_token = x_token.dst_token
                tried_tokens.append(_verify_token.oid.read_oid)
                if command == "token_verify_mschap":
                    try:
                        verify_status = _verify_token.verify_mschap_static(temp=True, **token_verify_parms)
                    except Exception as e:
                        log_msg = _("Verification of token (temp) '{token_name}' returned error: {error}", log=True)[1]
                        log_msg = log_msg.format(token_name=_verify_token.name, error=e)
                        self.logger.critical(log_msg)
                        continue
                else:
                    token_verify_parms = {
                            'auth_type'         : "clear-text",
                            'password'          : password,
                            }
                    try:
                        verify_status = _verify_token.verify_temp_password(**token_verify_parms)
                    except Exception as e:
                        log_msg = _("Verification of token (temp) '{token_name}' returned error: {error}", log=True)[1]
                        log_msg = log_msg.format(token_name=_verify_token.name, error=e)
                        self.logger.critical(log_msg)
                        continue

                # Same tuple-vs-scalar shape as the primary verify loop.
                if command == "token_verify_mschap":
                    if not isinstance(verify_status, tuple) or verify_status[0] is not True:
                        continue
                elif verify_status is not True:
                    continue

                auth_token = _verify_token
                src_token = x_token
                break

        _jwt = None
        auth_status = False
        if auth_token:
            auth_status = True
            _jwt = None
            if gen_jwt:
                try:
                    _jwt = self.gen_jwt(username=auth_token.owner,
                                        token=auth_token,
                                        src_token=src_token,
                                        reason=jwt_reason,
                                        access_group=jwt_access_group,
                                        challenge=jwt_challenge)
                except AccessDenied as e:
                    status = False
                    message = _("Unable to gen JWT: {e}")
                    message = message.format(e=e)
                    return self.build_response(status, message)
            nt_key = None
            pass_hash = None
            if command == "token_verify_mschap" and redirect_response:
                # The site that verified it already decided what it is
                # willing to give out, so pass its answer along.
                nt_key = redirect_response.get('nt_key')
                pass_hash = redirect_response.get('pass_hash')
            elif command == "token_verify_mschap":
                nt_key = verify_status[1]
                # The third element of the tuple is a one time value for
                # one time tokens -- the clear text OTP, or the hash of
                # the code we pushed. Both are spent with this
                # verification, so they can go back and let the caller
                # build the session hash it needs to let the client
                # present the same OTP again.
                #
                # For a static token it is the NT hash instead, which
                # answers any future challenge on its own. That one
                # stays here: whoever is allowed to hold it syncs the
                # token anyway and has no reason to ask us.
                if auth_token.pass_type in ("otp", "otp_push"):
                    pass_hash = verify_status[2]
            sso_jwt = None
            if sso_login and sso_ag:
                # Gen jwt for SSO auth.
                try:
                    sso_jwt = self.gen_jwt(username=user.name,
                                        token=auth_token,
                                        src_token=src_token,
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
                        'pass_hash'     : pass_hash,
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
            log_msg = _("Token verification failed: {user}: {tried_tokens}", log=True)[1]
            log_msg = log_msg.format(user=user.name, tried_tokens=tried_tokens)
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
        auth_ag = None
        auth_client = None
        if client == config.sso_client_name:
            sso_ag = f"{config.site}/{config.sso_access_group}"
            verify_args['sso_login'] = True
            verify_args['sso_ag'] = sso_ag
            verify_args['sso_challenge'] = sso_challenge
            verify_args['jwt_access_group'] = sso_ag
        else:
            if client:
                auth_client = backend.get_object(object_type="client",
                                                realm=config.realm,
                                                site=config.site,
                                                name=client,
                                                run_policies=True,
                                                _no_func_cache=True)
            elif client_ip:
                result = backend.search(object_type="client",
                                        attribute="address",
                                        value=client_ip,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
                if result:
                    auth_client = result[0]
                    client = auth_client.name

            if not auth_client:
                message, log_msg = _("Unable to determine client: {client}: {client_ip}", log=True)
                log_msg = log_msg.format(client=client, client_ip=client_ip)
                self.logger.critical(log_msg)
                message = message.format(client=client, client_ip=client_ip)
                status = status_codes.ERR
                return self.build_response(status, message)

            if auth_client.access_group:
                auth_ag = backend.get_object(object_type="accessgroup",
                                            realm=config.realm,
                                            site=config.site,
                                            name=auth_client.access_group,
                                            run_policies=True,
                                            _no_func_cache=True)
            if not auth_ag:
                message, log_msg = _("Unable to get accessgroup from client: {client}: {access_group}", log=True)
                log_msg = log_msg.format(client=auth_client.name, access_group=auth_client.access_group)
                self.logger.critical(log_msg)
                message = message.format(client=client, client_ip=client_ip)
                status = status_codes.ERR
                return self.build_response(status, message)
            # Set JWT accessgroup.
            verify_args['jwt_access_group'] = f"{auth_ag.site}/{auth_ag.name}"
            # Set dot1x auth.
            if auth_client.dot1x_auth:
                verify_args['dot1x_auth'] = True
            access_group = auth_client.access_group

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
                                    auth_client=auth_client,
                                    auth_group=auth_ag,
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
                            "token_verify_tiqr",
                            "token_verify_smartcard",
                            "token_verify_fido2",
                            "verify_static",
                            "verify_mschap",
                            "fido2_auth_begin",
                            "fido2_auth_complete",
                            "tiqr_auth_begin",
                            "tiqr_auth_response",
                            "tiqr_auth_status",
                            "tiqr_auth_otp",
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
            token_auth_data = command_args['token_auth_data']
        except Exception:
            token_auth_data = None

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
        if command == "token_verify_tiqr":
            auth_type = "tiqr"
        if command == "token_verify_smartcard":
            auth_type = "smartcard"
        if command == "fido2_auth_begin":
            auth_type = "smartcard"
        if command == "fido2_auth_complete":
            auth_type = "smartcard"
        if command.startswith("tiqr_auth_"):
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

        if command == "tiqr_auth_begin":
            log_msg = _("Processing command tiqr_auth_begin.", log=True)[1]
            self.logger.info(log_msg)
            return self.tiqr_auth_begin(username, command_args)

        # The phone's own request. It carries no username -- the identity
        # it names is the tiqr identity, checked inside.
        if command == "tiqr_auth_response":
            log_msg = _("Processing command tiqr_auth_response.", log=True)[1]
            self.logger.info(log_msg)
            return self.tiqr_auth_response(command_args,
                                        client=client,
                                        client_ip=client_ip)

        if command == "tiqr_auth_status":
            log_msg = _("Processing command tiqr_auth_status.", log=True)[1]
            self.logger.debug(log_msg)
            return self.tiqr_auth_status(client, client_ip, sso_challenge, command_args)

        if command == "tiqr_auth_otp":
            log_msg = _("Processing command tiqr_auth_otp.", log=True)[1]
            self.logger.info(log_msg)
            return self.tiqr_auth_otp(client, client_ip, sso_challenge, command_args)

        # Check for incomplete command.
        incomplete_command = False
        if not username:
            incomplete_command = True
        if not client and not client_ip and not host:
            incomplete_command = True
        if password is None:
            if token_auth_data is None:
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

        # Set proctitle to contain username.
        self.set_proctitle(username)

        # Step-up reauth via the plain "verify" command: the SSO portal
        # bounces the user through /reauth for sensitive actions and
        # submits the standard login form. Instead of creating a new
        # session (cookies, JWT, peer-RP disruption) we verify the
        # credential directly against the token that opened the current
        # SSO session and bump the session's ``reauth_time``. FIDO2
        # reauth already lives in fido2_auth_complete; this branch
        # covers password/OTP tokens so the "Sign In" button in reauth
        # mode of login.html actually works for them.
        reauth = bool(command_args.get('reauth', False))
        reauth_session_uuid = command_args.get('session_uuid')
        if reauth and command == "verify":
            log_msg = _("Reauth branch entered for user '{u}'.", log=True)[1]
            log_msg = log_msg.format(u=user.name)
            self.logger.info(log_msg)
            if not reauth_session_uuid:
                log_msg = _("Reauth: session_uuid missing.", log=True)[1]
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            # The SSO session was created on the site that owns the SSO
            # portal (this node); a foreign-user login stashed a link
            # token here whose ``dst_token`` lives on the user's home
            # site. Look the session up locally, dereference the link,
            # and verify against the destination token -- either directly
            # (same site) or via ``reauth_redirect_password`` (foreign).
            sso_session = backend.get_object(object_type="session",
                                             uuid=reauth_session_uuid)
            if sso_session is None or sso_session.user_uuid != user.uuid:
                emit_audit("Auth", "reauth_failed",
                                level='warning',
                                user=user.name,
                                session=reauth_session_uuid,
                                reason='session_user_mismatch',
                                ip=client_ip)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            token = backend.get_object(uuid=sso_session.auth_token)
            if token is None:
                log_msg = _("Reauth: session token not found.", log=True)[1]
                self.logger.warning(log_msg)
                return self.build_response(False, {
                    'message': 'Login failed.', 'status': False,
                })
            verify_token = token
            if token.destination_token:
                verify_token = token.dst_token
                if verify_token is None:
                    log_msg = _("Reauth: link token has no dst_token: {t}", log=True)[1]
                    log_msg = log_msg.format(t=token.rel_path)
                    self.logger.warning(log_msg)
                    return self.build_response(False, {
                        'message': 'Login failed.', 'status': False,
                    })
            if verify_token.site != config.site:
                # Cross-site: hand the verify to the home authd. Home
                # returns a signed JWT proving it verified the token;
                # we validate the JWT (identity+challenge+reason bound)
                # and only then bump reauth_time on the local session.
                try:
                    verify_ok = self.reauth_redirect_password(user=user,
                                                token=token,
                                                verify_token=verify_token,
                                                password=password,
                                                client=client,
                                                client_ip=client_ip)
                except Exception as e:
                    log_msg = _("Reauth: cross-site password verify failed: {err}", log=True)[1]
                    log_msg = log_msg.format(err=e)
                    self.logger.warning(log_msg)
                    verify_ok = False
            else:
                verify_kwargs = {'auth_type': 'clear-text'}
                if verify_token.pass_type == 'otp':
                    verify_kwargs['otp'] = password
                else:
                    verify_kwargs['password'] = password
                try:
                    verify_ok = verify_token.verify(**verify_kwargs)
                except Exception as e:
                    log_msg = _("Reauth: token verify failed: {err}", log=True)[1]
                    log_msg = log_msg.format(err=e)
                    self.logger.warning(log_msg)
                    verify_ok = False
            if not verify_ok:
                emit_audit("Auth", "reauth_failed",
                                level='warning',
                                user=user.name,
                                token=verify_token.name,
                                reason='token_verify_failed',
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
                            token=verify_token.name,
                            session=sso_session.session_id,
                            ip=client_ip)
            return self.build_response(True, {
                'message': 'ok', 'status': True,
            })

        if command == "token_verify" \
        or command == "token_verify_mschap" \
        or command == "token_verify_smartcard" \
        or command == "token_verify_tiqr" \
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
                                    smartcard_data=smartcard_data,
                                    token_auth_data=token_auth_data)

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
