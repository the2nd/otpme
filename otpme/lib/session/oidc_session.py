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

Specs governing this module:
  OIDC Core 1.0 §3.1 "Authorization Code Flow"
    https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
  OIDC Core 1.0 §2 "ID Token"
    https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  OIDC Core 1.0 §3.1.3.6 "ID Token" (at_hash)
    https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
  OIDC Back-Channel Logout 1.0
    https://openid.net/specs/openid-connect-backchannel-1_0.html
  RFC 6749 §6 "Refreshing an Access Token"
    https://datatracker.ietf.org/doc/html/rfc6749#section-6
  RFC 7519 "JSON Web Token (JWT)"
    https://datatracker.ietf.org/doc/html/rfc7519
  RFC 7636 "Proof Key for Code Exchange (PKCE)"
    https://datatracker.ietf.org/doc/html/rfc7636
  OAuth 2.1 §6.1 "Refresh Token Protection" (RT rotation +
    chain invalidation on replay)
    https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
"""
import os
import time
import secrets
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib.audit import emit_audit
from otpme.lib.classes.session import Session
from otpme.lib.protocols.oidc_helpers import compute_at_hash
from otpme.lib.protocols.oidc_helpers import hash_token as _hash_token


# Backward-compat re-export -- existing call sites import hash_token
# from this module. The implementation lives in oidc_helpers so it's
# unit-testable without the full Session import chain.
def hash_token(token):
    return _hash_token(token)


SESSION_TYPE = "oidc"

STATE_PENDING_CODE_EXCHANGE = "pending_code_exchange"
STATE_ACTIVE = "active"

# Cap concurrent backchannel logout POSTs across the process. Mass
# session-delete (user disable, site failover, expired-session reaper)
# can fire thousands of OIDCSession.delete()s in a tight loop -- each
# one sending an HTTP POST to a separate RP. Without a cap we could
# spawn an unbounded number of sockets / threads against our own OP.
# 32 is a reasonable balance: small enough to keep fd / memory usage
# tame, large enough that a normal logout cascade isn't visibly
# serialized. submit-time waiting is bounded by the per-call HTTP
# timeout (10s), so worst-case a deep mass-logout pipelines at 32 RPs
# at a time.
_BACKCHANNEL_LOGOUT_CONCURRENCY = 32
_backchannel_logout_slots = threading.BoundedSemaphore(
        _BACKCHANNEL_LOGOUT_CONCURRENCY)
# Bound the response body size we'll read from an RP; logout tokens
# are POST-only, the spec mandates the response body is empty/ignored.
# A misbehaving RP that streams data back forever would otherwise pin
# a worker thread.
#
# Spec: OIDC Back-Channel Logout 1.0 §2.8 "Back-Channel Logout
#   Response" (response body is empty / ignored)
#   https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
_BACKCHANNEL_LOGOUT_RESP_LIMIT = 4096


REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.classes.session']


def register():
    """ Register OIDCSession-specific index attributes.

    These hashes are how /token, /userinfo and /introspect resolve an
    opaque token back to its session. They live here (not in the
    parent session module) so the base Session stays free of
    OIDC-specific concerns.

    ``burned_refresh_token_hash`` is multi-valued: every refresh-token
    rotation appends the previous RT hash. A /token call that resolves
    via this index instead of ``refresh_token_hash`` is a replay
    attempt -- the whole token chain is invalidated in that case.

    Spec: OAuth 2.1 §6.1 "Refresh Token Protection"
      (rotate + invalidate chain on replay)
      https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
    """
    config.register_index_attribute('authcode_hash')
    config.register_index_attribute('access_token_hash')
    config.register_index_attribute('refresh_token_hash')
    config.register_index_attribute('burned_refresh_token_hash')


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
        # Hashes of refresh tokens that were rotated out via
        # issue_tokens(). Replay of any of these -- the legitimate
        # holder would only ever present the current RT -- is a
        # token-theft signal and triggers chain-invalidation.
        self.burned_refresh_token_hashes = []

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
        self.object_config['OIDC_BURNED_REFRESH_TOKEN_HASHES'] = list(self.burned_refresh_token_hashes)

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
        self.burned_refresh_token_hashes = list(
                self.get_config_parameter('OIDC_BURNED_REFRESH_TOKEN_HASHES') or [])

    def set_authcode(self, code: str, expires_in: int=300):
        """ Store the SHA-256 of the issued auth code on the session
        and index it for /token lookup. The plaintext code lives only
        in the redirect to the RP.

        Spec: OIDC Core 1.0 §3.1.2.5 "Successful Authentication
          Response" (code in redirect_uri query)
          https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        Spec: RFC 6749 §4.1.2 "Authorization Response" (auth code,
          short-lived; recommended ≤10 minutes)
          https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
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

        Spec: RFC 6749 §4.1.2 "Authorization Response"
          ("The client MUST NOT use the authorization code more than
          once.  If an authorization code is used more than once, the
          authorization server MUST deny the request...")
          https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
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

        On rotation the previous RT hash is moved from the active
        ``refresh_token_hash`` index to the multi-valued
        ``burned_refresh_token_hash`` index, so a later replay of the
        rotated-out RT is detectable rather than collapsing into a
        generic ``invalid_grant``.

        Spec: RFC 6749 §5.1 "Successful Response"
          (access_token + refresh_token + token_type)
          https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
        Spec: RFC 6749 §6 "Refreshing an Access Token"
          https://datatracker.ietf.org/doc/html/rfc6749#section-6
        Spec: OAuth 2.1 §6.1 "Refresh Token Protection"
          (sender-constrain or rotate-and-invalidate-chain on replay)
          https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
        """
        new_at = secrets.token_urlsafe(32)
        new_rt = secrets.token_urlsafe(32)
        new_at_hash = hash_token(new_at)
        new_rt_hash = hash_token(new_rt)
        # AT rotation: the old AT just disappears -- no replay
        # detection on AT (RFC 6749 doesn't expect AT replay to be
        # forensically tracked).
        if self.access_token_hash:
            self.del_index("access_token_hash", self.access_token_hash)
        # RT rotation: move the old hash onto the burn list.
        if self.refresh_token_hash:
            self.del_index("refresh_token_hash", self.refresh_token_hash)
            self.burned_refresh_token_hashes.append(self.refresh_token_hash)
            self.add_index("burned_refresh_token_hash",
                           self.refresh_token_hash)
        self.access_token_hash = new_at_hash
        self.access_token_expires_at = int(time.time()) + ttl_access
        self.refresh_token_hash = new_rt_hash
        self.add_index("access_token_hash", new_at_hash)
        self.add_index("refresh_token_hash", new_rt_hash)
        return new_at, new_rt

    def issue_tokens_with_id_token(self, ttl_access, client, site, claims):
        """ Combined AT/RT rotation + ID-Token mint. The freshly-rotated
        AT plaintext is hashed into the ID Token's ``at_hash`` claim
        before being returned, so callers can't accidentally bind
        the wrong AT.

        ``claims`` carries the OIDC-domain values resolved by the
        protocol handler (sub, user_claims merged in, auth_time, amr,
        acr). The session adds infrastructure claims it owns directly
        (iss, aud, sid, nonce, iat/exp/jti) and the at_hash binding.

        Returns ``(at, rt, id_token, id_token_jti)``. The jti is
        surfaced so the caller can audit-log it for cross-system
        correlation with RP logs.

        Spec: OIDC Core 1.0 §3.1.3.3 "Successful Token Response"
          (id_token co-issued with access_token + refresh_token)
          https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        Spec: OIDC Core 1.0 §3.1.3.6 "ID Token" (at_hash binding)
          https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        """
        at, rt = self.issue_tokens(ttl_access=ttl_access)
        id_token, id_token_jti = self._build_id_token(client=client,
                                                       site=site,
                                                       ttl=ttl_access,
                                                       access_token=at,
                                                       claims=claims)
        return at, rt, id_token, id_token_jti

    def _build_id_token(self, client, site, ttl, access_token, claims):
        """ Build and sign the ID Token JWT.

        ``claims`` is a dict of OIDC-domain values pre-resolved by the
        caller (sub is REQUIRED; auth_time/amr/acr/user-claim names
        are optional). Infrastructure claims (iss, aud, iat, exp, jti,
        sid, nonce) are added here -- they're rooted in session/site
        state, not protocol-handler context. ``at_hash`` is computed
        against ``access_token`` with the digest determined by the
        signing alg.

        Spec: OIDC Core 1.0 §2 "ID Token" (claim semantics:
          iss, sub, aud, exp, iat, auth_time, nonce, acr, amr, azp)
          https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        Spec: OIDC Core 1.0 §3.1.3.6 "ID Token" (at_hash computation)
          https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        Spec: OIDC Front-Channel Logout 1.0 §3 / OIDC Session 1.0 §5
          (sid claim)
          https://openid.net/specs/openid-connect-frontchannel-1_0.html
          https://openid.net/specs/openid-connect-session-1_0.html
        Spec: RFC 7519 §4.1 "Registered Claim Names"
          (iss, sub, aud, exp, nbf, iat, jti)
          https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
        Spec: RFC 7515 §4.1 "Registered Header Parameter Names"
          (alg, kid, typ)
          https://datatracker.ietf.org/doc/html/rfc7515#section-4.1
        Spec: RFC 8725 "JSON Web Token Best Current Practices"
          (typ=JWT; alg pinning)
          https://datatracker.ietf.org/doc/html/rfc8725
        """
        from joserfc import jwt as joserfc_jwt
        from joserfc.jwk import RSAKey, ECKey, OKPKey
        from otpme.lib.encryption.jwk import find_active_key

        # site.get_oidc_keys() returns a plain dict snapshot; reading
        # site.oidc_keys directly hands joserfc IncrementalDict
        # instances which fail its isinstance(value, dict) check.
        oidc_keys = list(site.get_oidc_keys().values())
        active = find_active_key(oidc_keys)
        kty = active.get("kty")
        if kty == "RSA":
            signing_key = RSAKey.import_key(active)
        elif kty == "EC":
            signing_key = ECKey.import_key(active)
        elif kty == "OKP":
            signing_key = OKPKey.import_key(active)
        else:
            from otpme.lib.exceptions import OTPmeException
            raise OTPmeException(f"Unsupported key type: {kty}")

        alg = getattr(client, 'oidc_id_token_signed_response_alg', None) \
              or active.get("alg", "RS256")

        issuer = f"https://{site.sso_fqdn}/oidc"
        now = int(time.time())

        # jti is generated separately so the caller can audit-log it
        # for cross-system correlation: the RP usually logs the jti it
        # processed, the OP logs the jti it issued.
        jti = secrets.token_urlsafe(16)

        full_claims = dict(claims) if claims else {}
        full_claims.update({
            "iss":  issuer,
            "aud":  client.name,
            "iat":  now,
            "exp":  now + ttl,
            "jti":  jti,
            # sid lets /end_session and back-channel logout correlate
            # this token to the OIDCSession that issued it.
            "sid":  self.uuid,
        })
        if self.nonce:
            full_claims["nonce"] = self.nonce

        # at_hash binds this ID Token to the access token issued
        # alongside it. Optional in code-flow per OIDC Core 3.1.3.6;
        # we always emit it -- many RP libraries validate when present
        # and it's defense-in-depth against AT/ID-Token cross-mixing.
        if access_token:
            at_hash = compute_at_hash(access_token, alg)
            if at_hash is not None:
                full_claims["at_hash"] = at_hash

        header = {"alg": alg, "kid": active.get("kid"), "typ": "JWT"}
        return joserfc_jwt.encode(header, full_claims, signing_key), jti

    def access_token_valid(self) -> bool:
        """ True if an access token is currently issued and not yet
        expired. Does not check revocation; that's handled by the
        session's own delete() / state lifecycle.

        Spec: RFC 6749 §1.4 "Access Token" (opaque to the client,
          server-side validity check)
          https://datatracker.ietf.org/doc/html/rfc6749#section-1.4
        """
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

    def delete(self, skip_backchannel: bool = False,
               skip_backchannel_client: str = None, **kwargs):
        """ Override: fire backchannel logout to the RP before the
        session is actually removed. Failures here NEVER block the
        delete -- the OP must always be able to terminate.

        ``skip_backchannel=True`` unconditionally suppresses the
        notify; used by /end_session scope=rp where the calling RP
        directly addresses one OIDCSession.

        ``skip_backchannel_client`` is a client UUID; when it matches
        ``self.client`` the notify is suppressed. Used by the
        SLP-cascade variant of /end_session (scope=sso) where the
        whole SSO tree is being torn down but the initiating RP
        already knows.

        In both cases the RP triggered the logout itself, so a
        back-channel POST would just race with the RP's own cleanup
        and typically produce HTTP 4xx noise.

        Spec: OIDC Back-Channel Logout 1.0 §2 "Back-Channel Logout"
          (OP-initiated POST to RP's backchannel_logout_uri)
          https://openid.net/specs/openid-connect-backchannel-1_0.html#BCLogout
        """
        if skip_backchannel \
                or (skip_backchannel_client
                    and self.client == skip_backchannel_client):
            return super().delete(skip_backchannel_client=skip_backchannel_client,
                                  **kwargs)
        try:
            self._send_backchannel_logout()
        except Exception as e:
            # Defensive: even an unexpected error in our notify path
            # must not stop the cleanup. Log with full traceback so a
            # recurring failure (e.g. a bad RP-config that consistently
            # raises during dispatch) is diagnosable.
            try:
                from otpme.lib.classes.session import logger
                log_msg = _("OIDC backchannel logout dispatch raised "
                            "unexpectedly for session '{sid}': {err}",
                            log=True)[1]
                log_msg = log_msg.format(sid=self.session_id, err=e)
                logger.warning(log_msg, exc_info=True)
            except Exception:
                pass
        return super().delete(skip_backchannel_client=skip_backchannel_client,
                              **kwargs)

    def _send_backchannel_logout(self):
        """ Fire-and-forget POST of a signed Logout Token to the RP's
        oidc_backchannel_logout_uri if one is configured. No-op when:
            - the session is still pending (nothing handed to RP)
            - the client has been deleted
            - the client has no backchannel_logout_uri set
            - the site has no active signing key

        The actual HTTP POST is dispatched to a daemon worker thread
        so that ``OIDCSession.delete()`` -- and by extension the
        whole session-cleanup pipeline -- never blocks waiting for
        an RP. Concurrency is bounded by a process-wide semaphore
        so a mass-logout cascade can't spawn unbounded threads/sockets.

        Spec: OIDC Back-Channel Logout 1.0 §2.5 "Back-Channel Logout
          Request" (POST application/x-www-form-urlencoded with
          ``logout_token=<JWT>``)
          https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest
        """
        if self.state != STATE_ACTIVE:
            return
        if not self.client:
            return
        from otpme.lib import backend
        client = backend.get_object(object_type="client", uuid=self.client)
        if client is None:
            return
        uri = getattr(client, 'oidc_backchannel_logout_uri', None)
        if not uri:
            return

        # Build + sign the token in the caller -- it touches the
        # site's signing key and we want the call to fail visibly if
        # that's wrong, not in a fire-and-forget thread no one reads.
        try:
            logout_token, logout_token_jti = self._build_logout_token(client)
        except Exception as e:
            from otpme.lib.classes.session import logger
            try:
                log_msg = _("OIDC backchannel logout token build failed "
                            "for {uri}: {err}", log=True)[1]
                log_msg = log_msg.format(uri=uri, err=e)
                logger.warning(log_msg, exc_info=True)
            except Exception:
                pass
            emit_audit("OIDC", "backchannel_logout_failed",
                       level='warning',
                       client=client.name,
                       session=self.session_id,
                       uri=uri,
                       reason=f"build_token: {e}")
            return
        if logout_token is None:
            # No active site key, etc. -- _build_logout_token already
            # decided this is a silent no-op (matches pre-fix behavior).
            return

        # Snapshot fields the worker thread needs; the OIDCSession is
        # about to be deleted, so we capture by value.
        client_name = client.name
        session_id = self.session_id
        tls_verify = bool(getattr(client, 'oidc_backchannel_tls_verify', True))
        ca_cert = getattr(client, 'oidc_backchannel_ca_cert', None) or None

        from otpme.lib import multiprocessing as _otpme_mp
        _otpme_mp.start_thread(
                name=f"oidc-backchannel-logout-{session_id}",
                target=_dispatch_backchannel_logout,
                target_args=(uri, logout_token, logout_token_jti,
                             client_name, session_id,
                             tls_verify, ca_cert),
                daemon=True)

    def _build_logout_token(self, client):
        """ Build + sign a Logout Token for the given client. Returns
        ``(signed_jwt, jti)`` on success, or ``(None, None)`` if the
        site has no usable active signing key (silent no-op preserved
        from the pre-async implementation).

        Per the Back-Channel Logout spec:
            - typ header = "logout+jwt"
            - claims must include iss, aud, iat, jti, events
            - either sub or sid (we use sid; sub requires per-RP
              subject computation that's done at ID-Token-issue time)

        Spec: OIDC Back-Channel Logout 1.0 §2.4 "Logout Token"
          (claim + header requirements; events claim with the
          ``http://schemas.openid.net/event/backchannel-logout`` key)
          https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
        Spec: RFC 8417 "Security Event Token (SET)"
          (events claim base format)
          https://datatracker.ietf.org/doc/html/rfc8417
        """
        from joserfc import jwt as joserfc_jwt
        from joserfc.jwk import RSAKey, ECKey, OKPKey
        from otpme.lib import backend
        from otpme.lib.encryption.jwk import find_active_key

        site = backend.get_object(object_type="site", name=self.site, realm=config.realm)
        if site is None or not getattr(site, 'oidc_keys', None):
            return None, None
        try:
            active = find_active_key(list(site.get_oidc_keys().values()))
        except LookupError:
            return None, None

        kty = active.get("kty")
        if kty == "RSA":
            signing_key = RSAKey.import_key(active)
        elif kty == "EC":
            signing_key = ECKey.import_key(active)
        elif kty == "OKP":
            signing_key = OKPKey.import_key(active)
        else:
            return None, None

        issuer = f"https://{site.sso_fqdn}/oidc"
        now = int(time.time())
        # jti returned alongside the signed token so the dispatch
        # path can audit-log it for cross-system correlation with the
        # RP's "logout-token consumed" entry.
        jti = secrets.token_urlsafe(16)
        claims = {
            "iss": issuer,
            "aud": client.name,
            "iat": now,
            "jti": jti,
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
        return joserfc_jwt.encode(header, claims, signing_key), jti


def _dispatch_backchannel_logout(uri, logout_token, logout_token_jti,
                                  client_name, session_id,
                                  tls_verify=True, ca_cert=None):
    """ Worker run on a daemon thread: POSTs the prebuilt logout
    token and audit-logs the outcome. Bounded by the module-level
    semaphore so a mass-delete burst can't blow the fd table.

    ``logout_token_jti`` is included in every audit emission for
    cross-system correlation -- the RP usually logs the jti it
    consumed, so an OP-side ``backchannel_logout_sent
    logout_token_jti=...`` line ties our send to the RP's receive.

    ``tls_verify``/``ca_cert`` control TLS validation against the RP.
    ``tls_verify=False`` produces an unverified context (lab/dev RPs
    with self-signed certs). A PEM ``ca_cert`` pins the trust root
    for this RP, replacing the system trust store.

    Spec: OIDC Back-Channel Logout 1.0 §2.5 "Back-Channel Logout
      Request" (HTTP POST, application/x-www-form-urlencoded,
      single ``logout_token`` parameter)
      https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest
    Spec: OIDC Back-Channel Logout 1.0 §2.8 "Back-Channel Logout
      Response" (response body empty / ignored)
      https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
    """
    import ssl
    from urllib.request import Request, urlopen
    from otpme.lib.classes.session import logger

    if not tls_verify:
        ssl_ctx = ssl._create_unverified_context()
    elif ca_cert:
        ssl_ctx = ssl.create_default_context(cadata=ca_cert)
    else:
        ssl_ctx = ssl.create_default_context()

    acquired = _backchannel_logout_slots.acquire(timeout=30)
    if not acquired:
        # Semaphore saturated for >30s -- treat as failure rather
        # than queueing further. The session has already been
        # deleted; the RP just doesn't get notified this round.
        emit_audit("OIDC", "backchannel_logout_failed",
                   level='warning',
                   client=client_name,
                   session=session_id,
                   uri=uri,
                   logout_token_jti=logout_token_jti,
                   reason="dispatch slot timeout")
        return
    try:
        body = f"logout_token={logout_token}".encode()
        req = Request(uri, data=body, method="POST",
                      headers={"Content-Type":
                               "application/x-www-form-urlencoded"})
        try:
            with urlopen(req, timeout=10, context=ssl_ctx) as resp:
                # Drain a bounded amount; spec response body is
                # empty/ignored. Without a cap a misbehaving RP could
                # stream forever and pin this worker.
                resp.read(_BACKCHANNEL_LOGOUT_RESP_LIMIT)
        except Exception as e:
            try:
                log_msg = _("OIDC backchannel logout to {uri} failed: {err}",
                            log=True)[1]
                log_msg = log_msg.format(uri=uri, err=e)
                logger.warning(log_msg, exc_info=True)
            except Exception:
                pass
            emit_audit("OIDC", "backchannel_logout_failed",
                       level='warning',
                       client=client_name,
                       session=session_id,
                       uri=uri,
                       logout_token_jti=logout_token_jti,
                       reason=str(e))
            return
        emit_audit("OIDC", "backchannel_logout_sent",
                   client=client_name,
                   session=session_id,
                   uri=uri,
                   logout_token_jti=logout_token_jti)
    finally:
        _backchannel_logout_slots.release()
