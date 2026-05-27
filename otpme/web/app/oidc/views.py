# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
HTTP routes for the OIDC OP.

Thin adapter only: each route parses the HTTP request, packages the
relevant fields into a ``command_args`` dict, calls the matching
ssod command via the existing OTPme protocol client, and translates
the response into an OIDC-spec-compliant HTTP reply.

All OIDC logic (grant validation, PKCE, token issuance/rotation,
introspection, revocation, end-session, ID token signing) lives in
otpme.lib.protocols.server.sso1; views.py never touches the backend
directly. This is required because the web layer can run on hosts
that don't host any OTPme objects.

Endpoints + governing specs:
    /.well-known/openid-configuration -- OIDC Discovery 1.0
        https://openid.net/specs/openid-connect-discovery-1_0.html
        (cf. RFC 8414 "OAuth 2.0 Authorization Server Metadata"
         https://datatracker.ietf.org/doc/html/rfc8414)
    /jwks            -- RFC 7517 "JSON Web Key (JWK)"
        https://datatracker.ietf.org/doc/html/rfc7517
    /authorize       -- OIDC Core 1.0 §3.1 "Authorization Code Flow"
        https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
        (cf. RFC 6749 §4.1 "Authorization Code Grant"
         https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)
    /token           -- OIDC Core 1.0 §3.1.3 "Token Endpoint" +
                        RFC 6749 §3.2 "Token Endpoint"
        https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
        https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
    /userinfo        -- OIDC Core 1.0 §5.3 "UserInfo Endpoint"
        https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    /introspect      -- RFC 7662 "OAuth 2.0 Token Introspection"
        https://datatracker.ietf.org/doc/html/rfc7662
    /revoke          -- RFC 7009 "OAuth 2.0 Token Revocation"
        https://datatracker.ietf.org/doc/html/rfc7009
    /end_session     -- OIDC RP-Initiated Logout 1.0
        https://openid.net/specs/openid-connect-rpinitiated-1_0.html
"""
from flask import jsonify, request, make_response, redirect, session as flask_session, url_for, render_template
from flask_babel import gettext, lazy_gettext

from otpme.lib import config
from otpme.lib import connections

from otpme.web.app.oidc import oidc_bp
from otpme.web.app.views import get_ssod_conn
from otpme.web.app.views import _do_sso_logout
from otpme.web.app.views import get_authd_conn
from otpme.web.app.views import check_forwarded_for

logger = config.logger


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# OIDC tooling (test sites, SPA RPs in production) fetches Discovery,
# JWKS, /token and /userinfo from browser JavaScript on a different
# origin. Without CORS the browser blocks the response.
#
# All these endpoints are designed to be public OR auth via Bearer/
# Basic (not cookies), so a wildcard origin is safe -- credentials
# are never sent automatically by the browser. We never combine
# ``Access-Control-Allow-Origin: *`` with ``Allow-Credentials: true``.
#
# The browser-driven endpoints /authorize and /end_session do NOT
# need CORS because they use top-level navigation, not fetch.
#
# Spec: WHATWG Fetch (CORS protocol; supersedes the historical
#   CORS W3C Recommendation referenced by older RFCs)
#   https://fetch.spec.whatwg.org/#http-cors-protocol

_CORS_ROUTES = (
    'oidc.discovery',
    'oidc.jwks',
    'oidc.token',
    'oidc.userinfo',
    'oidc.introspect',
    'oidc.revoke',
)


@oidc_bp.before_request
def _oidc_cors_preflight():
    """ Reply to CORS preflight (OPTIONS) on the public/RP-callable
    OIDC endpoints. The actual route handlers don't need to know
    about OPTIONS. """
    if request.method != "OPTIONS":
        return None
    if request.endpoint not in _CORS_ROUTES:
        return None
    resp = make_response("", 204)
    resp.headers['Access-Control-Allow-Origin']  = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    resp.headers['Access-Control-Max-Age']       = '600'
    return resp


@oidc_bp.after_request
def _oidc_cors_response(response):
    """ Tag actual responses on the same routes with the CORS
    allow-origin so the browser doesn't drop the body. """
    if request.endpoint in _CORS_ROUTES:
        response.headers.setdefault('Access-Control-Allow-Origin', '*')
    return response


def _no_store(response):
    """ Mark a response as non-cacheable for token-bearing endpoints
    (/token, /userinfo, /introspect, /revoke).

    Spec: RFC 6749 §5.1 "Successful Response"
      (Cache-Control: no-store, Pragma: no-cache MUST be set)
      https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    Spec: OIDC Core 1.0 §3.1.3.3 "Successful Token Response"
      https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    """
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


def _extract_client_credentials():
    """ Parse client_id + client_secret from the request.

    The OP MUST support ``client_secret_basic`` (HTTP Basic) and
    SHOULD support ``client_secret_post`` (form body). Returns
    ``(client_id, client_secret)`` -- either may be ``None``.

    A client MUST NOT use both methods in the same request; if it
    does, the spec says the OP MUST reject. We surface that to the
    caller via a third return slot ``error_msg``.

    Spec: RFC 6749 §2.3.1 "Client Password" (Basic + form-post)
      https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    Spec: OIDC Core 1.0 §9 "Client Authentication"
      (defines ``client_secret_basic`` / ``client_secret_post`` /
      ``none`` token_endpoint_auth_method names)
      https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    """
    import base64
    from urllib.parse import unquote

    basic_id = None
    basic_secret = None
    auth = request.headers.get('Authorization', '')
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "basic":
            try:
                decoded = base64.b64decode(parts[1]).decode('utf-8')
                cid, sep, csec = decoded.partition(':')
                if sep:
                    # client_id and client_secret in Basic must be
                    # form-urlencoded per RFC 6749 §2.3.1.
                    #   https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
                    basic_id = unquote(cid)
                    basic_secret = unquote(csec)
            except Exception:
                return None, None, "malformed Authorization header"

    body_id = request.form.get('client_id') or None
    body_secret = request.form.get('client_secret') or None

    if basic_id and body_id and basic_id != body_id:
        return None, None, "client_id mismatch between header and body"
    if basic_secret and body_secret:
        return None, None, "client_secret sent twice"

    client_id = basic_id or body_id
    client_secret = basic_secret or body_secret
    return client_id, client_secret, None


def _oidc_error(error, description=None, http_status=400, www_auth=None):
    """ Build an OAuth/OIDC error response body.

    Spec: RFC 6749 §5.2 "Error Response" (token endpoint errors)
      https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    Spec: RFC 6750 §3 "The WWW-Authenticate Response Header Field"
      (Bearer realm, error="invalid_token" etc.)
      https://datatracker.ietf.org/doc/html/rfc6750#section-3
    """
    payload = {'error': error}
    if description:
        payload['error_description'] = description
    resp = make_response(jsonify(payload), http_status)
    if www_auth:
        resp.headers['WWW-Authenticate'] = www_auth
    return _no_store(resp)


def _extract_bearer_token():
    """ Extract a Bearer access token from the request.

    Sources, in order of preference:
      1. ``Authorization: Bearer <token>`` header  (recommended)
      2. ``access_token=<token>`` form parameter   (POST only)

    The URL-query form (``?access_token=...``) is intentionally
    NOT supported -- it leaks tokens to logs, Referer headers, and
    browser history.

    Spec: RFC 6750 §2.1 "Authorization Request Header Field"
      https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    Spec: RFC 6750 §2.2 "Form-Encoded Body Parameter"
      (POST + application/x-www-form-urlencoded only)
      https://datatracker.ietf.org/doc/html/rfc6750#section-2.2
    Spec: RFC 6750 §2.3 "URI Query Parameter"
      (NOT IMPLEMENTED -- known to leak via logs/Referer)
      https://datatracker.ietf.org/doc/html/rfc6750#section-2.3
    """
    auth = request.headers.get('Authorization', '')
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    # Form body (POST). RFC 6750 §2.2: allowed only for
    # application/x-www-form-urlencoded requests.
    if request.method == "POST" and request.form:
        body_token = request.form.get('access_token')
        if body_token:
            return body_token.strip()
    return None


def _get_oidc_ssod_conn():
    """ Open a server-to-server connection to ssod for OIDC commands.

    Mirrors otpme.web.app.views.get_ssod_conn but without user
    context: OIDC commands authenticate the RP via client_id +
    client_secret in command_args (or via the signed id_token_hint
    for /end_session), not via the user's SSO JWT.
    """
    if config.host_data['type'] == "node":
        return connections.get("ssod",
                               realm=config.realm,
                               site=config.site,
                               auto_auth=False,
                               socket_uri=config.ssod_socket_path,
                               local_socket=True,
                               use_ssl=False,
                               handle_host_auth=False,
                               handle_user_auth=False,
                               encrypt_session=False)
    return connections.get("ssod",
                           realm=config.realm,
                           site=config.site,
                           follow_redirect=False,
                           request_token=False,
                           auto_preauth=False,
                           auto_auth=False,
                           encrypt_session=False)


def _send_oidc_command(command, command_args):
    """ Send an OIDC command to ssod.

    Returns ``(status, payload)`` where status is True/False from
    ssod's build_response and payload is the dict ssod returned.
    On transport failure returns ``(None, error_dict)`` so the
    caller can surface a generic 500.
    """
    args = dict(command_args)
    args.setdefault('client_ip', check_forwarded_for()[0])

    ssod_conn = None
    try:
        ssod_conn = _get_oidc_ssod_conn()
        status, _status_code, response, _binary = ssod_conn.send(
                            command=command, command_args=args)
        return status, response
    except Exception as e:
        log_msg = _("OIDC ssod command '{command}' failed: {err}", log=True)[1]
        log_msg = log_msg.format(command=command, err=e)
        logger.critical(log_msg)
        return None, {
            "error": "server_error",
            "error_description": "internal error",
        }
    finally:
        if ssod_conn is not None:
            try:
                ssod_conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Discovery: /.well-known/openid-configuration
# ---------------------------------------------------------------------------


@oidc_bp.route('/.well-known/openid-configuration', methods=['GET', 'OPTIONS'])
def discovery():
    """ Discovery metadata. ssod builds the doc from the site's
    runtime config (issuer, signing-alg list, supported scopes, ...);
    web layer just relays.

    Spec: OIDC Discovery 1.0 §4 "Obtaining OpenID Provider
      Configuration Information" (well-known URL + JSON document)
      https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    Spec: RFC 8414 "OAuth 2.0 Authorization Server Metadata"
      (sibling spec, aligned field set)
      https://datatracker.ietf.org/doc/html/rfc8414
    """
    status, response = _send_oidc_command('oidc_discovery', {})
    if status is None:
        return jsonify(response), 500
    if not status:
        return jsonify(response), 500
    return jsonify(response), 200


# ---------------------------------------------------------------------------
# JWKS: /jwks
# ---------------------------------------------------------------------------


@oidc_bp.route('/avatar/<path:user_uuid>', methods=['GET'])
def avatar(user_uuid):
    """ Public avatar endpoint -- serves user.photo as image/jpeg.

    Used by RPs that follow the ``picture`` claim as a downloadable
    URL (e.g. Nextcloud user_oidc) rather than consuming a data: URI
    inline. The user UUID is the obscurity guard; UUIDs aren't
    enumerable and the URL is only minted into tokens that already
    identify the holder.

    Accepts the UUID with or without ``.jpg`` suffix (helps caches /
    browsers infer the file type).
    """
    import base64
    if user_uuid.endswith('.jpg'):
        user_uuid = user_uuid[:-4]
    status, response = _send_oidc_command('oidc_avatar',
                                          {'user_uuid': user_uuid})
    if status is None or not status:
        return make_response('', 404)
    photo_b64 = (response or {}).get('photo')
    if not photo_b64:
        return make_response('', 404)
    try:
        photo_bytes = base64.b64decode(photo_b64)
    except Exception:
        return make_response('', 404)
    resp = make_response(photo_bytes, 200)
    resp.headers['Content-Type'] = 'image/jpeg'
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@oidc_bp.route('/jwks', methods=['GET', 'OPTIONS'])
def jwks():
    """ Public signing keys (active + retired). ssod strips private
    parameters via joserfc per-kty allowlist; only public material
    leaves the OP.

    Spec: RFC 7517 §5 "JWK Set Format"
      https://datatracker.ietf.org/doc/html/rfc7517#section-5
    Spec: OIDC Core 1.0 §10.1 "Signing" (key rotation; OP keeps
      retired keys published so RPs can verify in-flight tokens)
      https://openid.net/specs/openid-connect-core-1_0.html#SigEnc
    """
    status, response = _send_oidc_command('oidc_jwks', {})
    if status is None:
        return jsonify(response), 500
    if not status:
        return jsonify(response), 500
    return jsonify(response), 200


# ---------------------------------------------------------------------------
# Token: /token
# ---------------------------------------------------------------------------


@oidc_bp.route('/token', methods=['POST', 'OPTIONS'])
def token():
    """ /token endpoint.

    Dispatches by ``grant_type`` (server-side in ssod). Currently
    handles ``authorization_code`` and ``refresh_token``.

    Client auth: ``client_secret_basic`` (Authorization: Basic) or
    ``client_secret_post`` (form body). Public clients with
    ``token_endpoint_auth_method=none`` may omit the secret as long
    as PKCE is in play.

    Responses are mandated to be ``Cache-Control: no-store``.

    Spec: RFC 6749 §3.2 "Token Endpoint" (HTTP semantics)
      https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
    Spec: RFC 6749 §4.1.3 "Access Token Request"
      https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    Spec: RFC 6749 §6 "Refreshing an Access Token"
      https://datatracker.ietf.org/doc/html/rfc6749#section-6
    Spec: RFC 6749 §5.2 "Error Response"
      (invalid_client => 401; other errors => 400)
      https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    Spec: OIDC Core 1.0 §3.1.3 "Token Endpoint" (adds id_token to
      the response, plus at_hash / nonce binding)
      https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
    Spec: RFC 7636 "PKCE" (code_verifier; required by default per
      OAuth 2.1 §7.5)
      https://datatracker.ietf.org/doc/html/rfc7636
    """
    client_id, client_secret, cred_err = _extract_client_credentials()
    if cred_err:
        return _oidc_error('invalid_client',
                           "client authentication failed",
                           http_status=401,
                           www_auth='Basic realm="oidc"')

    args = {
        'grant_type':    request.form.get('grant_type'),
        'client_id':     client_id,
        'client_secret': client_secret,
        # authorization_code path
        'code':          request.form.get('code'),
        'redirect_uri':  request.form.get('redirect_uri'),
        'code_verifier': request.form.get('code_verifier'),
        # refresh_token path
        'refresh_token': request.form.get('refresh_token'),
    }

    status, response = _send_oidc_command('oidc_token', args)
    if status is None:
        return _oidc_error('server_error',
                           response.get('error_description'),
                           http_status=500)

    if not status:
        # ssod returned an OIDC error dict with 'error' + 'error_description'.
        err = (response or {}).get('error', 'invalid_request')
        desc = (response or {}).get('error_description')
        # RFC 6749 §5.2: invalid_client => 401, others => 400.
        #   https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        http_status = 401 if err == 'invalid_client' else 400
        www_auth = 'Basic realm="oidc"' if err == 'invalid_client' else None
        return _oidc_error(err, desc, http_status=http_status,
                           www_auth=www_auth)

    return _no_store(make_response(jsonify(response), 200))


# ---------------------------------------------------------------------------
# UserInfo: /userinfo
# ---------------------------------------------------------------------------


@oidc_bp.route('/userinfo', methods=['GET', 'POST', 'OPTIONS'])
def userinfo():
    """ /userinfo endpoint.

    Auth: ``Authorization: Bearer <access_token>``. The token is
    self-identifying; no client credentials. Returns user claims
    filtered by the granted scope of the originating session.

    On authentication failure: HTTP 401 with
    ``WWW-Authenticate: Bearer error="invalid_token"``.

    Spec: OIDC Core 1.0 §5.3 "UserInfo Endpoint"
      https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    Spec: OIDC Core 1.0 §5.3.2 "Successful UserInfo Response"
      (``sub`` claim REQUIRED in response)
      https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
    Spec: OIDC Core 1.0 §5.3.3 "UserInfo Error Response"
      https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
    Spec: RFC 6750 §3 "WWW-Authenticate Response Header Field"
      (Bearer realm, error="invalid_token")
      https://datatracker.ietf.org/doc/html/rfc6750#section-3
    Spec: OIDC Core 1.0 §5.4 "Requesting Claims using Scope Values"
      (profile/email/address/phone scope -> claim mappings)
      https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
    """
    bearer_www_auth = ('Bearer realm="oidc", '
                       'error="invalid_token", '
                       'error_description="invalid or expired token"')

    access_token = _extract_bearer_token()
    if not access_token:
        return _oidc_error('invalid_token',
                           "access_token missing",
                           http_status=401,
                           www_auth=bearer_www_auth)

    args = {'access_token': access_token}
    status, response = _send_oidc_command('oidc_userinfo', args)
    if status is None:
        return _oidc_error('server_error',
                           response.get('error_description'),
                           http_status=500)

    if not status:
        err = (response or {}).get('error', 'invalid_token')
        desc = (response or {}).get('error_description')
        if err == 'invalid_token':
            return _oidc_error(err, desc, http_status=401,
                               www_auth=bearer_www_auth)
        # Server-side issues at /userinfo (rare) -> 500.
        return _oidc_error(err, desc, http_status=500)

    # Success: claim dict (already includes 'sub' from ssod).
    return _no_store(make_response(jsonify(response), 200))


# ---------------------------------------------------------------------------
# Introspection: /introspect
# ---------------------------------------------------------------------------


@oidc_bp.route('/introspect', methods=['POST', 'OPTIONS'])
def introspect():
    """ /introspect endpoint.

    Server-to-server: RP authenticates via ``client_id`` +
    ``client_secret`` (Basic header or form body).

    Request body: ``token`` (REQUIRED), ``token_type_hint``
    (OPTIONAL: ``access_token``/``refresh_token``).

    Response: HTTP 200 with ``{"active": true, ...}`` for currently-
    valid tokens, ``{"active": false}`` for anything else. The
    "anything else" branch covers unknown, expired, revoked, AND
    tokens belonging to a different client -- no information leak
    about token existence.

    Real HTTP errors (4xx) only on client-auth failure or missing
    ``token`` parameter.

    Spec: RFC 7662 §2 "Introspection Endpoint" (request schema)
      https://datatracker.ietf.org/doc/html/rfc7662#section-2
    Spec: RFC 7662 §2.2 "Introspection Response"
      (active true/false; both are HTTP 200)
      https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
    """
    client_id, client_secret, cred_err = _extract_client_credentials()
    if cred_err:
        return _oidc_error('invalid_client',
                           "client authentication failed",
                           http_status=401,
                           www_auth='Basic realm="oidc"')

    args = {
        'client_id':        client_id,
        'client_secret':    client_secret,
        'token':            request.form.get('token'),
        'token_type_hint':  request.form.get('token_type_hint'),
    }

    status, response = _send_oidc_command('oidc_introspect', args)
    if status is None:
        return _oidc_error('server_error',
                           response.get('error_description'),
                           http_status=500)

    if not status:
        err = (response or {}).get('error', 'invalid_request')
        desc = (response or {}).get('error_description')
        http_status = 401 if err == 'invalid_client' else 400
        www_auth = 'Basic realm="oidc"' if err == 'invalid_client' else None
        return _oidc_error(err, desc, http_status=http_status,
                           www_auth=www_auth)

    # RFC 7662 §2.2: success = HTTP 200 regardless of active true/false.
    #   https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
    return _no_store(make_response(jsonify(response), 200))


# ---------------------------------------------------------------------------
# Revocation: /revoke
# ---------------------------------------------------------------------------


@oidc_bp.route('/revoke', methods=['POST', 'OPTIONS'])
def revoke():
    """ /revoke endpoint.

    Server-to-server: RP authenticates via ``client_id`` +
    ``client_secret``.

    Request body: ``token`` (REQUIRED), ``token_type_hint``
    (OPTIONAL).

    Response: HTTP 200 with empty body for ANY valid request --
    whether the token existed, was already revoked, or belongs to a
    different client. This prevents token-existence probing. Real
    HTTP errors only on client-auth failure or missing ``token``
    parameter.

    Spec: RFC 7009 §2 "Token Revocation" (request schema)
      https://datatracker.ietf.org/doc/html/rfc7009#section-2
    Spec: RFC 7009 §2.2 "Revocation Response"
      (200 + empty body uniformly; only invalid_client / 400 errors
      reach the caller)
      https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
    """
    client_id, client_secret, cred_err = _extract_client_credentials()
    if cred_err:
        return _oidc_error('invalid_client',
                           "client authentication failed",
                           http_status=401,
                           www_auth='Basic realm="oidc"')

    args = {
        'client_id':        client_id,
        'client_secret':    client_secret,
        'token':            request.form.get('token'),
        'token_type_hint':  request.form.get('token_type_hint'),
    }

    status, response = _send_oidc_command('oidc_revoke', args)
    if status is None:
        return _oidc_error('server_error',
                           response.get('error_description'),
                           http_status=500)

    if not status:
        err = (response or {}).get('error', 'invalid_request')
        desc = (response or {}).get('error_description')
        http_status = 401 if err == 'invalid_client' else 400
        www_auth = 'Basic realm="oidc"' if err == 'invalid_client' else None
        return _oidc_error(err, desc, http_status=http_status,
                           www_auth=www_auth)

    # RFC 7009 §2.2: success = 200 with empty (JSON) body.
    #   https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
    return _no_store(make_response(jsonify({}), 200))


# ---------------------------------------------------------------------------
# End Session: /end_session
# ---------------------------------------------------------------------------


def _append_state(target_uri, state):
    """ Append ``state=<value>`` to a redirect URI, preserving any
    existing query string. The OP MUST echo back the ``state`` value
    to the post_logout_redirect_uri.

    Spec: OIDC RP-Initiated Logout 1.0 §3 "Redirection to RP After
      Logout" (state parameter handling)
      https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
    """
    if not target_uri or not state:
        return target_uri
    from urllib.parse import urlencode
    sep = '&' if '?' in target_uri else '?'
    return f"{target_uri}{sep}{urlencode([('state', state)])}"


def _logged_out_page(error_notice=None):
    """ Generic OP logout-success page when no validated
    post_logout_redirect_uri is available. ``error_notice`` (e.g.
    the requested redirect URI was rejected because it's not in the
    client's allowlist) is shown to the user so they know the
    silent-redirect-back didn't happen by accident -- required by
    OIDC RP-Initiated Logout 1.0 cert tests.
    """
    from markupsafe import escape
    notice_html = ""
    if error_notice:
        notice_html = (
            "<p style=\"color:#b00020;\"><strong>"
            f"{escape(error_notice)}"
            "</strong></p>"
        )
    html = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<title>Logged out</title></head>"
        "<body><h1>Logged out</h1>"
        "<p>You have been logged out.</p>"
        f"{notice_html}"
        "</body></html>"
    )
    resp = make_response(html, 200)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@oidc_bp.route('/end_session', methods=['GET', 'POST'])
def end_session():
    """ /end_session endpoint.

    Browser-driven, no client_secret envelope -- trust comes from
    the signed ``id_token_hint``.

    ssod decides scope per the resolved client's
    ``oidc_logout_scope`` config (sso or rp) and validates the
    requested ``post_logout_redirect_uri`` against the client's
    allowlist. The web layer just acts on the action ssod returns.

    Spec: OIDC RP-Initiated Logout 1.0 §2 "RP-Initiated Logout"
      (id_token_hint, post_logout_redirect_uri, state)
      https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
    Spec: OIDC Back-Channel Logout 1.0 (sid claim, side-effect
      logout to other RPs in the SSO session)
      https://openid.net/specs/openid-connect-backchannel-1_0.html
    """
    id_token_hint = request.values.get('id_token_hint')
    client_id_q = request.values.get('client_id')
    post_logout_redirect_uri = request.values.get('post_logout_redirect_uri')
    state = request.values.get('state')

    # OIDC RP-Initiated Logout 1.0 §2: id_token_hint is RECOMMENDED,
    # not REQUIRED. Two hintless cases, treated differently:
    #
    # - ``post_logout_redirect_uri`` present but no hint -> we
    #   cannot tie the request to a specific client/session and
    #   therefore cannot safely honor the redirect (open-redirect
    #   defense). Reject with an error page. Confirm dialogs are
    #   not viable: automated test runners auto-submit them.
    # - No params at all -> equivalent to the user navigating
    #   directly to /end_session. Honor it via the browser
    #   session and show a logged-out page.
    hintless_username = None
    if not id_token_hint:
        if post_logout_redirect_uri:
            return _oidc_html_error_page(
                    'invalid_request',
                    ('id_token_hint is required when '
                     'post_logout_redirect_uri is provided.'),
                    title=gettext("Logout error"))
        hintless_username = flask_session.get('otpme_username')
        if not hintless_username:
            # Nothing to do -- no session and no hint. Show a
            # generic page rather than an error since the user
            # asked to log out and there's nothing more to undo.
            return _logged_out_page()

    args = {
        'id_token_hint':            id_token_hint,
        'client_id':                client_id_q,
        'post_logout_redirect_uri': post_logout_redirect_uri,
        'username':                 hintless_username,
    }
    status, response = _send_oidc_command('oidc_end_session', args)
    if status is None:
        return _oidc_html_error_page(
                'server_error',
                (response or {}).get('error_description', ''),
                title=gettext("Logout error"),
                http_status=500)

    if not status:
        err = (response or {}).get('error', 'invalid_request')
        desc = (response or {}).get('error_description')
        return _oidc_html_error_page(err, desc,
                                      title=gettext("Logout error"))

    action = (response or {}).get('action')
    validated_uri = (response or {}).get('post_logout_redirect_uri')
    initiating_client_uuid = (response or {}).get('initiating_client_uuid')
    target = _append_state(validated_uri, state)
    # The RP asked us to redirect back, but the URI wasn't in the
    # client's allowlist (ssod returned no validated URI). Per OIDC
    # RP-Initiated Logout 1.0 we MUST NOT honor the redirect; we
    # still log the user out but show a notice so they aren't left
    # wondering why they didn't bounce back.
    rejected_notice = None
    if post_logout_redirect_uri and not validated_uri:
        rejected_notice = (
            "The requested post_logout_redirect_uri is not registered "
            "for this client and was ignored."
        )

    if action == 'redirect_logout':
        # scope=sso: terminate the user's SSO session via the
        # existing SLP-based logout (cascades into all child
        # OIDCSessions; backchannel-logout fires for each child
        # except the initiating RP -- it already logged out).
        if target:
            resp = make_response(redirect(target))
        else:
            resp = _logged_out_page(error_notice=rejected_notice)
        # Hintless logout: we can't reliably identify which RP
        # initiated the call, so suppress backchannel cascade to
        # every attached RP. The SSO session is still terminated;
        # other RPs find out lazily when their AT/RT stops working.
        return _do_sso_logout(resp,
                skip_backchannel_client=initiating_client_uuid,
                skip_backchannel=(id_token_hint is None))

    if action == 'redirect_post_logout':
        # scope=rp: ssod already killed the calling RP's OIDCSession
        # (and fired its backchannel logout). SSO session + other RPs
        # stay logged in. Just send the user back to the RP.
        if target:
            return redirect(target)
        return _logged_out_page(error_notice=rejected_notice)

    # Unknown action -- fall back to generic confirmation.
    return _logged_out_page(error_notice=rejected_notice)


# ---------------------------------------------------------------------------
# Authorize: /authorize
# ---------------------------------------------------------------------------


def _build_redirect_with_params(redirect_uri, params):
    """ Append OIDC response params to the registered redirect_uri.
    Preserves any pre-existing query string. """
    from urllib.parse import urlencode
    pairs = [(k, v) for (k, v) in params.items() if v is not None]
    if not pairs:
        return redirect_uri
    sep = '&' if '?' in redirect_uri else '?'
    return f"{redirect_uri}{sep}{urlencode(pairs)}"


_SCOPE_FRIENDLY = {
    'openid':        (lazy_gettext('Verify your identity'),
                      lazy_gettext('Confirm who you are so the application can sign you in.')),
    'profile':       (lazy_gettext('Basic profile information'),
                      lazy_gettext('Your name, username and basic profile fields.')),
    'email':         (lazy_gettext('Email address'),
                      lazy_gettext('Your primary email address.')),
    'address':       (lazy_gettext('Postal address'),
                      lazy_gettext('Your postal/mailing address attributes.')),
    'phone':         (lazy_gettext('Phone number'),
                      lazy_gettext('Your phone number on file.')),
    'groups':        (lazy_gettext('Group memberships'),
                      lazy_gettext('Which groups you belong to (used by the app for access control).')),
    'offline_access': (lazy_gettext('Stay signed in when offline'),
                       lazy_gettext('Allow the application to refresh its session without asking you again.')),
}


# Which claim keys are populated by which OIDC scope. Mirrors the
# logic in sso1.py:_get_user_claims -- when that gets a new scope or
# claim, this table needs updating too so the consent screen stays
# accurate. Custom scopes get a generic preview ("any claims the
# application has access to").
_SCOPE_CLAIM_MAP = {
    'openid':  ['sub'],  # not actually emitted as a user claim by _get_user_claims,
                          # but conceptually "the user identifier"
    'profile': ['name', 'given_name', 'family_name', 'preferred_username'],
    'email':   ['email'],
    'phone':   ['phone_number'],
    'address': ['address'],
    'groups':  ['groups'],
}


def _format_claim_value(value):
    """ Render a single OIDC claim value for the consent UI. Lists
    join with commas; dicts (e.g. ``address``) show as ``key: val``
    bullets; everything else is stringified. """
    if value is None or value == '' or value == []:
        return ''
    if isinstance(value, list):
        return ', '.join(str(v) for v in value)
    if isinstance(value, dict):
        return '; '.join(f"{k}: {v}" for k, v in value.items() if v)
    return str(value)


def _scope_descriptions(scopes, claims_preview=None):
    """ Map OIDC scopes to (label, description, claim previews) for
    the consent screen. ``claims_preview`` is the dict the ssod
    pre-computed via :py:func:`_get_user_claims` so the user can see
    the concrete values the RP would receive, not just the category.
    """
    claims_preview = claims_preview or {}
    out = []
    for s in scopes:
        if s in _SCOPE_FRIENDLY:
            label, desc = _SCOPE_FRIENDLY[s]
        else:
            label = s
            desc = gettext("Application-specific permission '%(scope)s'.", scope=s)
        claim_items = []
        # openid by itself doesn't generate user claims in _get_user_claims;
        # the identifier travels as `sub` which is wholly managed by the OP.
        # Skip the per-claim listing for it so we don't show an empty row.
        if s == 'openid':
            pass
        elif s in _SCOPE_CLAIM_MAP:
            for ck in _SCOPE_CLAIM_MAP[s]:
                if ck in claims_preview:
                    val_str = _format_claim_value(claims_preview[ck])
                    if val_str:
                        claim_items.append({'name': ck, 'value': val_str})
        else:
            # Custom scope -- we don't know which claim keys it
            # contributes. Show whatever the preview offered that we
            # haven't already shown under a known scope (best effort).
            pass
        out.append({'name': s, 'label': label,
                    'description': desc, 'claims': claim_items})
    return out


def _authorize_error_page(error, description):
    """ Tier-1 error page -- displayed when redirect_uri/client_id
    is invalid and we MUST NOT redirect (open-redirect defense).
    """
    return _oidc_html_error_page(error, description,
                                  title=gettext("Authorization error"))


def _oidc_html_error_page(error, description, title=None, http_status=400):
    """ Browser-facing HTML error page for OIDC endpoints that have
    no safe redirect target (e.g. /end_session with a bogus
    id_token_hint -- we can't trust the post_logout_redirect_uri,
    so we render here instead of bouncing back). JSON-style
    ``_oidc_error`` is for server-to-server endpoints only.
    """
    safe_err = (error or "invalid_request").replace("<", "&lt;").replace(">", "&gt;")
    safe_desc = (description or "").replace("<", "&lt;").replace(">", "&gt;")
    title = title or gettext("Error")
    html = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title></head>"
        f"<body><h1>{title}</h1>"
        f"<p><strong>{safe_err}</strong></p>"
        f"<p>{safe_desc}</p>"
        "</body></html>"
    )
    resp = make_response(html, http_status)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@oidc_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """ /authorize endpoint.

    Browser-driven. Three roundtrips:
      1. ssod ``oidc_authorize_validate`` -> validates + issues SOTP
      2. authd ``verify`` with SOTP + oidc_context=True -> auth_code
      3. 302 to redirect_uri with code + state

    If the user has no SSO session yet, /login is invoked with
    ``next=<this URL>`` so they come back here after authenticating.

    Spec: OIDC Core 1.0 §3.1.2 "Authorization Endpoint"
      https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
    Spec: OIDC Core 1.0 §3.1.2.1 "Authentication Request"
      (client_id, redirect_uri, response_type, scope, state, nonce,
      code_challenge, code_challenge_method)
      https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    Spec: OIDC Core 1.0 §3.1.2.5 "Successful Authentication Response"
      (302 to redirect_uri with code + state)
      https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
    Spec: OIDC Core 1.0 §3.1.2.6 "Authentication Error Response"
      (two-tier reporting: redirect_uri-invalid stays on OP, others
      redirect with error+state)
      https://openid.net/specs/openid-connect-core-1_0.html#AuthError
    Spec: RFC 6749 §4.1.1 "Authorization Request"
      https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
    Spec: RFC 7636 §4.3 "Client Sends the Code Challenge with the
      Authorization Request"
      https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
    """
    # OIDC accepts params via GET query or POST body; ``request.values``
    # covers both.
    client_id = request.values.get('client_id')
    redirect_uri = request.values.get('redirect_uri')
    response_type = request.values.get('response_type')
    scope = request.values.get('scope')
    state = request.values.get('state')
    nonce = request.values.get('nonce')
    code_challenge = request.values.get('code_challenge')
    code_challenge_method = request.values.get('code_challenge_method') or 'plain'
    # OIDC ``prompt`` parameter (Core 3.1.2.1). Forwarded to ssod
    # which encodes the policy (``consent`` forces re-prompt,
    # ``none`` forbids any user interaction).
    prompt_param = request.values.get('prompt') or ''
    # OIDC ``max_age`` (Core 3.1.2.1): maximum allowable age of the
    # last authentication in seconds. ssod compares against the SSO
    # session's reauth_time / creation_time and signals
    # ``REAUTH_REQUIRED`` if the session is stale.
    max_age_param = request.values.get('max_age') or ''

    # Build a /oidc/authorize URL that survives a redirect through
    # /login or /reauth. Both bounce-back via GET, so a POSTed
    # authorization request would otherwise lose its body params
    # (request.full_path only covers path+query). Rebuilding from
    # request.values picks up params regardless of how they came in.
    def _self_url(prompt_override=None):
        from urllib.parse import urlencode
        OIDC_PARAMS = (
            'client_id', 'redirect_uri', 'response_type', 'scope',
            'state', 'nonce', 'code_challenge',
            'code_challenge_method', 'prompt', 'max_age',
            'login_hint', 'id_token_hint', 'ui_locales',
            'acr_values', 'display', 'response_mode', 'claims',
            'claims_locales', 'request', 'request_uri',
        )
        items = []
        for k in OIDC_PARAMS:
            if k == 'prompt' and prompt_override is not None:
                if prompt_override:
                    items.append(('prompt', prompt_override))
                continue
            v = request.values.get(k)
            if v not in (None, ''):
                items.append((k, v))
        qs = urlencode(items)
        return '/oidc/authorize' + ('?' + qs if qs else '')

    # SSO cookie check -- if user isn't logged in, hand off to /login
    # with our full URL as next= so they bounce back here after auth.
    sso_jwt = request.cookies.get('otpme_jwt')
    username = flask_session.get('otpme_username')
    session_uuid = request.cookies.get('otpme_sso_session')
    if not sso_jwt or not username or not session_uuid:
        # OIDC Core §3.1.2.6: ``prompt=none`` forbids any user-facing
        # interaction. Without an active session we can't authenticate
        # silently, so we MUST redirect back to the RP with
        # ``error=login_required`` instead of rendering /login.
        if 'none' in (prompt_param or '').split():
            v_status, v_response = _send_oidc_command(
                    'oidc_prompt_none_no_session',
                    {'client_id': client_id,
                     'redirect_uri': redirect_uri})
            if (v_status and isinstance(v_response, dict)
                    and v_response.get('valid') and redirect_uri):
                target = _build_redirect_with_params(redirect_uri, {
                    'error': 'login_required',
                    'error_description': 'no active session and prompt=none',
                    'state': state,
                })
                return redirect(target)
            return _authorize_error_page(
                    'login_required',
                    'no active session and prompt=none')
        return redirect(url_for('login',
                                next=_self_url(),
                                _external=True, _scheme='https'))

    # OIDC Core §3.1.2.1: prompt=login MUST trigger reauthentication.
    # Redirect through /reauth (a step-up FIDO2 verify) so the user
    # gets a fresh auth_time without losing the SSO session or peer
    # RP sessions. We strip ``login`` from the prompt before sending
    # the user back, otherwise we'd loop indefinitely.
    prompt_values = prompt_param.split()
    if 'login' in prompt_values:
        remaining = [v for v in prompt_values if v != 'login']
        next_url = _self_url(prompt_override=' '.join(remaining))
        return redirect(url_for('reauth', next=next_url,
                                _external=True, _scheme='https'))

    client_ip = check_forwarded_for()[0]

    # Consent-screen continuation: if the user just clicked Allow on
    # the consent template (rendered earlier in this same /authorize
    # flow), the form POST carries the flag plus a CSRF nonce from
    # flask_session so a fresh /authorize hit can't bypass consent
    # by guessing the parameter.
    consent_granted = False
    if request.method == 'POST' and request.form.get('_oidc_consent_grant'):
        nonce_stored = flask_session.pop('oidc_consent_nonce', None)
        nonce_form = request.form.get('_oidc_consent_nonce')
        if nonce_stored and nonce_form and nonce_stored == nonce_form:
            consent_granted = True

    # Deny-button: redirect back to the RP with access_denied per
    # OIDC Core 3.1.2.6 / OAuth 2.0 §4.1.2.1. We honor the user's no
    # without storing anything; a future /authorize re-prompts.
    if request.method == 'POST' and request.form.get('_oidc_consent_deny'):
        nonce_stored = flask_session.pop('oidc_consent_nonce', None)
        nonce_form = request.form.get('_oidc_consent_nonce')
        if nonce_stored and nonce_form and nonce_stored == nonce_form \
                and redirect_uri:
            target = _build_redirect_with_params(redirect_uri, {
                'error':             'access_denied',
                'error_description': 'user denied the request',
                'state':             state,
            })
            return redirect(target)
        # Without a valid nonce we can't trust the request -- fall
        # through to normal validation (which will re-prompt).

    # Step 1: ssod validates the request and -- on success -- hands
    # back a SOTP scoped to the OIDC client's access_group, or
    # signals that user consent is needed first.
    validate_args = {
        'username':              username,
        'sso_jwt':               sso_jwt,
        'session_uuid':          session_uuid,
        'client_ip':             client_ip,
        'client_id':              client_id,
        'redirect_uri':           redirect_uri,
        'response_type':          response_type,
        'scope':                  scope,
        'code_challenge':         code_challenge,
        'code_challenge_method':  code_challenge_method,
        'prompt':                 prompt_param,
        'max_age':                max_age_param,
        # Unsupported but checked: if present, ssod rejects with the
        # spec-mandated request_not_supported / request_uri_not_supported
        # error (OIDC Core §6.1 / §3.1.2.6) rather than silently
        # ignoring as the OIDC conformance suite explicitly forbids.
        'request':                request.values.get('request') or '',
        'request_uri':            request.values.get('request_uri') or '',
        'consent_granted':        consent_granted,
    }
    # consent_granted=True implies user.set_oidc_consent + user._write
    # on the ssod side. Object modifications must happen on the
    # master node, so route through the mgmt FQDN in that case.
    # The read-only validate path stays local.
    ssod_conn = get_ssod_conn(username, mgmt=bool(consent_granted))
    try:
        v_status, _vc, v_response, _vbin = ssod_conn.send(
                            command='oidc_authorize_validate',
                            command_args=validate_args)
    except Exception as e:
        log_msg = _("oidc_authorize_validate failed: {err}", log=True)[1]
        log_msg = log_msg.format(err=e)
        logger.critical(log_msg)
        return _authorize_error_page('server_error',
                                     'authorization service unavailable')
    finally:
        try:
            ssod_conn.close()
        except Exception:
            pass

    if not v_status:
        # Validation failed. Two paths depending on can_redirect.
        if isinstance(v_response, dict):
            err = v_response.get('error', 'invalid_request')
            desc = v_response.get('error_description', '')
            can_redirect = v_response.get('can_redirect', False)
            # JWT trouble -> try to logout user which redirects to login.
            if v_response.get('message') == 'JWT_INVALID':
                return redirect(url_for('logout',
                                        next=_self_url(),
                                        _external=True, _scheme='https'))
            # max_age exceeded -> route through /reauth (FIDO2
            # step-up) so the SSO session gets a fresh reauth_time
            # without losing the session itself. After reauth the
            # user bounces back to /authorize with the original
            # query (max_age still present, but now satisfied).
            if v_response.get('message') == 'REAUTH_REQUIRED':
                return redirect(url_for('reauth',
                                        next=_self_url(),
                                        _external=True, _scheme='https'))
            if can_redirect and redirect_uri:
                target = _build_redirect_with_params(redirect_uri, {
                    'error':             err,
                    'error_description': desc,
                    'state':             state,
                })
                return redirect(target)
            return _authorize_error_page(err, desc)
        return _authorize_error_page('server_error',
                                     'invalid validation response')

    # Consent gate: ssod tells us the user must approve scopes before
    # we issue a SOTP. Render the consent template; the form POSTs
    # back to /authorize with _oidc_consent_grant=1 to continue.
    if isinstance(v_response, dict) and v_response.get('consent_required'):
        import secrets as _secrets
        consent_nonce = _secrets.token_urlsafe(16)
        flask_session['oidc_consent_nonce'] = consent_nonce
        # Carry every /authorize input forward as hidden form fields
        # so the POST is a complete re-submission, not a stub.
        return render_template('oidc_consent.html',
            client_name=v_response.get('client_name') or client_id,
            client_description=v_response.get('client_description') or '',
            scopes=v_response.get('scopes') or [],
            scope_descriptions=_scope_descriptions(
                    v_response.get('scopes') or [],
                    claims_preview=v_response.get('claims_preview') or {}),
            consent_nonce=consent_nonce,
            authorize_url=url_for('oidc.authorize',
                                  _external=True, _scheme='https'),
            params={
                'client_id':              client_id or '',
                'redirect_uri':           redirect_uri or '',
                'response_type':          response_type or '',
                'scope':                  scope or '',
                'state':                  state or '',
                'nonce':                  nonce or '',
                'code_challenge':         code_challenge or '',
                'code_challenge_method':  code_challenge_method or '',
                'prompt':                 prompt_param or '',
            },
        )

    # Success: extract SOTP from the response.
    sotp_value = v_response.get('sotp')
    if not sotp_value:
        return _authorize_error_page('server_error',
                                     'failed to obtain SOTP')

    # Step 2: authd verify with SOTP + OIDC context. auth_handler
    # validates SOTP -> finds parent SSO session -> attaches OIDCSession
    # via add_oidc_child_session -> returns oidc_authcode.
    verify_args = {
        'oidc_login':                     True,
        'username':                       username,
        'password':                       sotp_value,
        'client':                         client_id,
        'client_ip':                      client_ip,
        'oidc_context':                   True,
        'oidc_scope':                     scope,
        'oidc_nonce':                     nonce,
        'oidc_redirect_uri':              redirect_uri,
        'oidc_code_challenge':            code_challenge,
        'oidc_code_challenge_method':     code_challenge_method,
    }
    authd_conn = get_authd_conn(username, sotp_value)
    try:
        a_status, _ac, auth_response, _abin = authd_conn.send(
                            command='verify',
                            command_args=verify_args)
    except Exception as e:
        log_msg = _("authd verify (oidc) failed: {err}", log=True)[1]
        log_msg = log_msg.format(err=e)
        logger.critical(log_msg)
        target = _build_redirect_with_params(redirect_uri, {
            'error':             'server_error',
            'error_description': 'authentication failed',
            'state':             state,
        })
        return redirect(target)
    finally:
        try:
            authd_conn.close()
        except Exception:
            pass

    if not a_status:
        target = _build_redirect_with_params(redirect_uri, {
            'error':             'server_error',
            'error_description': 'authentication failed',
            'state':             state,
        })
        return redirect(target)

    authcode = None
    if isinstance(auth_response, dict):
        authcode = auth_response.get('oidc_authcode')
    if not authcode:
        target = _build_redirect_with_params(redirect_uri, {
            'error':             'server_error',
            'error_description': 'failed to issue auth code',
            'state':             state,
        })
        return redirect(target)

    # Success: 302 back to the RP with code + state.
    target = _build_redirect_with_params(redirect_uri, {
        'code':  authcode,
        'state': state,
    })
    return redirect(target)
