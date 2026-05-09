# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
OIDCSession -- Session subtype for OIDC OP flows.

Lives as a child of the user's SSO Session. One OIDCSession is created
per RP login and holds the per-flow state (auth code, access token,
refresh token, scopes, redirect_uri, PKCE values, ...). Tokens are
stored only as SHA-256 hashes; the originals live exclusively in the
RP's storage.

Skeleton only at this stage -- field set, indexed lookups, state
machine helpers. Token issuance, rotation and consumption logic plus
the backchannel-logout side-effect on delete are layered on top later.
"""
import os
import time
import hashlib
import secrets

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib.audit import emit_audit
from otpme.lib.classes.session import Session


SESSION_TYPE = "oidc"

STATE_PENDING_CODE_EXCHANGE = "pending_code_exchange"
STATE_ACTIVE = "active"


REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.classes.session']


def register():
    """ Register OIDCSession-specific index attributes.

    These three hashes are how /token, /userinfo and /introspect
    resolve an opaque token back to its session. They live here
    (not in the parent session module) so the base Session stays
    free of OIDC-specific concerns.
    """
    from otpme.lib import config
    config.register_index_attribute('authcode_hash')
    config.register_index_attribute('access_token_hash')
    config.register_index_attribute('refresh_token_hash')


def hash_token(token: str) -> str:
    """ Canonical hash for OIDC token storage and indexed lookup. """
    if isinstance(token, str):
        token = token.encode("utf-8")
    return hashlib.sha256(token).hexdigest()


class OIDCSession(Session):
    """ Session subtype representing one OIDC OP <-> RP flow. """

    def __init__(self, *args, scope="", nonce=None, redirect_uri=None,
        code_challenge=None, code_challenge_method=None, **kwargs):
        # Force the session_type so the index/dispatcher round-trips.
        kwargs.setdefault("session_type", SESSION_TYPE)
        super().__init__(*args, **kwargs)
        # OIDC-specific state. Defaults; real values are set by the
        # OIDC flow (authorize -> token exchange -> refresh).
        # The OIDC client UUID lives on the inherited ``self.client``
        # field (set via the parent's ``client=`` kwarg) -- no
        # separate self.client_uuid to avoid drift.
        self.scope = scope
        self.nonce = nonce
        self.redirect_uri = redirect_uri
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.state = STATE_PENDING_CODE_EXCHANGE
        # Token hashes. None means "not issued / not active".
        self.authcode_hash = None
        self.authcode_expires_at = 0
        self.access_token_hash = None
        self.access_token_expires_at = 0
        self.refresh_token_hash = None
        # RT lifetime is bounded by the parent SSO session's expiry,
        # so we don't track refresh_token_expires_at separately.

    def write_config(self, wait_for_cluster_writes: bool=True):
        """ Persist with cluster sync.

        OIDC sessions must be visible on every node before the RP can
        legitimately call /token or /userinfo behind a load balancer.
        Skipping the wait would create races where a token issued by
        node-A is rejected by node-B because the session hasn't
        propagated yet.
        """
        return super().write_config(wait_for_cluster_writes=wait_for_cluster_writes)

    def _set_extra_object_config(self):
        """ Serialize OIDC-specific fields into object_config. """
        self.object_config['OIDC_SCOPE'] = self.scope
        self.object_config['OIDC_NONCE'] = self.nonce
        self.object_config['OIDC_REDIRECT_URI'] = self.redirect_uri
        self.object_config['OIDC_CODE_CHALLENGE'] = self.code_challenge
        self.object_config['OIDC_CODE_CHALLENGE_METHOD'] = self.code_challenge_method
        self.object_config['OIDC_STATE'] = self.state
        self.object_config['OIDC_AUTHCODE_HASH'] = self.authcode_hash
        self.object_config['OIDC_AUTHCODE_EXPIRES_AT'] = self.authcode_expires_at
        self.object_config['OIDC_ACCESS_TOKEN_HASH'] = self.access_token_hash
        self.object_config['OIDC_ACCESS_TOKEN_EXPIRES_AT'] = self.access_token_expires_at
        self.object_config['OIDC_REFRESH_TOKEN_HASH'] = self.refresh_token_hash

    def _set_extra_variables(self):
        """ Read OIDC-specific fields back from object_config. """
        self.scope = self.get_config_parameter('OIDC_SCOPE') or ""
        self.nonce = self.get_config_parameter('OIDC_NONCE')
        self.redirect_uri = self.get_config_parameter('OIDC_REDIRECT_URI')
        self.code_challenge = self.get_config_parameter('OIDC_CODE_CHALLENGE')
        self.code_challenge_method = self.get_config_parameter('OIDC_CODE_CHALLENGE_METHOD')
        state = self.get_config_parameter('OIDC_STATE')
        if state:
            self.state = state
        self.authcode_hash = self.get_config_parameter('OIDC_AUTHCODE_HASH')
        self.authcode_expires_at = self.get_config_parameter('OIDC_AUTHCODE_EXPIRES_AT') or 0
        self.access_token_hash = self.get_config_parameter('OIDC_ACCESS_TOKEN_HASH')
        self.access_token_expires_at = self.get_config_parameter('OIDC_ACCESS_TOKEN_EXPIRES_AT') or 0
        self.refresh_token_hash = self.get_config_parameter('OIDC_REFRESH_TOKEN_HASH')

    def set_authcode(self, code: str, expires_in: int=300):
        """ Store the SHA-256 of the issued auth code on the session
        and index it for /token lookup. The plaintext code lives only
        in the redirect to the RP.
        """
        if self.authcode_hash:
            # Replace any previous code (e.g. /authorize re-entered).
            self.del_index("authcode_hash", self.authcode_hash)
        h = hash_token(code)
        self.authcode_hash = h
        self.authcode_expires_at = int(time.time()) + expires_in
        self.add_index("authcode_hash", h)

    def consume_authcode(self):
        """ Single-use: drop the auth code hash + index entry and
        transition the session into the active token-bearing state.
        Caller is responsible for issue_tokens() afterwards.
        """
        if self.authcode_hash:
            self.del_index("authcode_hash", self.authcode_hash)
        self.authcode_hash = None
        self.authcode_expires_at = 0
        self.state = STATE_ACTIVE

    def issue_tokens(self, ttl_access: int=3600):
        """ Generate fresh access + refresh tokens, hash them onto the
        session, and update the indexes. Used for both initial code
        exchange and refresh-token rotation. Returns ``(at, rt)`` --
        the only point at which the plaintext values exist.
        """
        new_at = secrets.token_urlsafe(32)
        new_rt = secrets.token_urlsafe(32)
        new_at_hash = hash_token(new_at)
        new_rt_hash = hash_token(new_rt)
        # Drop the previous index entries before overwriting state.
        if self.access_token_hash:
            self.del_index("access_token_hash", self.access_token_hash)
        if self.refresh_token_hash:
            self.del_index("refresh_token_hash", self.refresh_token_hash)
        self.access_token_hash = new_at_hash
        self.access_token_expires_at = int(time.time()) + ttl_access
        self.refresh_token_hash = new_rt_hash
        self.add_index("access_token_hash", new_at_hash)
        self.add_index("refresh_token_hash", new_rt_hash)
        return new_at, new_rt

    def access_token_valid(self) -> bool:
        """ True if an access token is currently issued and not yet
        expired. Does not check revocation; that's handled by the
        session's own delete() / state lifecycle. """
        if not self.access_token_hash:
            return False
        return int(time.time()) < self.access_token_expires_at

    def authcode_valid(self) -> bool:
        """ True if the auth code is currently issued and not yet
        expired. """
        if not self.authcode_hash:
            return False
        if self.state != STATE_PENDING_CODE_EXCHANGE:
            return False
        return int(time.time()) < self.authcode_expires_at

    def delete(self, **kwargs):
        """ Override: fire backchannel logout to the RP before the
        session is actually removed. Failures here NEVER block the
        delete -- the OP must always be able to terminate.
        """
        try:
            self._send_backchannel_logout()
        except Exception:
            # Defensive: even an unexpected error in our notify path
            # must not stop the cleanup.
            pass
        return super().delete(**kwargs)

    def _send_backchannel_logout(self):
        """ POST a signed Logout Token to the RP's
        oidc_backchannel_logout_uri if one is configured. No-op
        when:
            - the session is still pending (nothing handed to RP)
            - the client has been deleted
            - the client has no backchannel_logout_uri set
            - the site has no active signing key
        """
        if self.state != STATE_ACTIVE:
            return
        if not self.client:
            return
        from otpme.lib import backend
        from otpme.lib.classes.session import logger
        client = backend.get_object(object_type="client", uuid=self.client)
        if client is None:
            return
        uri = getattr(client, 'oidc_backchannel_logout_uri', None)
        if not uri:
            return
        try:
            self._post_logout_token(client, uri)
        except Exception as e:
            try:
                log_msg = _("OIDC backchannel logout to {uri} failed: {err}", log=True)[1]
                log_msg = log_msg.format(uri=uri, err=e)
                logger.warning(log_msg)
            except Exception:
                pass
            emit_audit("OIDC", "backchannel_logout_failed",
                       level='warning',
                       client=client.name,
                       session=self.session_id,
                       uri=uri,
                       reason=str(e))
            return
        emit_audit("OIDC", "backchannel_logout_sent",
                   client=client.name,
                   session=self.session_id,
                   uri=uri)

    def _post_logout_token(self, client, uri: str):
        """ Build, sign, and POST the Logout Token. Per OIDC
        Back-Channel Logout 1.0:
            - typ header = "logout+jwt"
            - claims must include iss, aud, iat, jti, events
            - either sub or sid (we use sid; sub requires per-RP
              subject computation that's done at ID-Token-issue time)
        """
        from urllib.request import Request, urlopen
        from joserfc import jwt as joserfc_jwt
        from joserfc.jwk import RSAKey, ECKey, OKPKey
        from otpme.lib import backend
        from otpme.lib.encryption.jwk import find_active_key

        site = backend.get_object(object_type="site", name=self.site)
        if site is None or not getattr(site, 'oidc_keys', None):
            return
        try:
            active = find_active_key(list(site.oidc_keys.values()))
        except LookupError:
            return

        kty = active.get("kty")
        if kty == "RSA":
            signing_key = RSAKey.import_key(active)
        elif kty == "EC":
            signing_key = ECKey.import_key(active)
        elif kty == "OKP":
            signing_key = OKPKey.import_key(active)
        else:
            return

        issuer = f"https://{site.sso_fqdn}/oidc"
        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": client.name,
            "iat": now,
            "jti": secrets.token_urlsafe(16),
            "sid": self.uuid,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            },
        }
        header = {
            "alg": active.get("alg", "RS256"),
            "kid": active.get("kid"),
            "typ": "logout+jwt",
        }
        logout_token = joserfc_jwt.encode(header, claims, signing_key)

        body = f"logout_token={logout_token}".encode()
        req = Request(uri, data=body, method="POST",
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urlopen(req, timeout=10):
            pass
