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

Endpoints:
    /.well-known/openid-configuration   - discovery
    /jwks                               - JWKS public keys
    /authorize                          - browser-driven login start
    /token                              - code exchange / refresh
    /userinfo                           - claims for AT
    /introspect                         - RFC 7662
    /revoke                             - RFC 7009
    /end_session                        - RP-initiated logout
"""
from flask import jsonify, request, make_response, redirect, session as flask_session, url_for

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
    """ Mark a response as non-cacheable per OIDC spec for token-
    bearing endpoints (/token, /userinfo, /introspect, /revoke). """
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


def _extract_client_credentials():
    """ Parse client_id + client_secret from the request.

    Per RFC 6749 §2.3.1 the OP MUST support
    ``client_secret_basic`` (HTTP Basic) and SHOULD support
    ``client_secret_post`` (form body). Returns
    ``(client_id, client_secret)`` -- either may be ``None``.

    A client MUST NOT use both methods in the same request; if it
    does, RFC 6749 says the OP MUST reject. We surface that to the
    caller via a third return slot ``error_msg``.
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
                    # Per RFC 6749, client_id and client_secret
                    # in Basic must be form-urlencoded.
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
    """ Build an OIDC-spec error response. """
    payload = {'error': error}
    if description:
        payload['error_description'] = description
    resp = make_response(jsonify(payload), http_status)
    if www_auth:
        resp.headers['WWW-Authenticate'] = www_auth
    return _no_store(resp)


def _extract_bearer_token():
    """ Extract a Bearer access token from the request per RFC 6750.

    Sources, in order of preference:
      1. ``Authorization: Bearer <token>`` header  (recommended)
      2. ``access_token=<token>`` form parameter   (POST only)

    The URL-query form (``?access_token=...``) is intentionally
    NOT supported -- it leaks tokens to logs, Referer headers, and
    browser history.
    """
    auth = request.headers.get('Authorization', '')
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    # Form body (POST) -- per RFC 6750 §2.2 allowed only for
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
                           auto_preauth=True,
                           auto_auth=False)


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
    """ OIDC Discovery 1.0 metadata. ssod builds the doc from the
    site's runtime config (issuer, signing-alg list, supported
    scopes, ...) -- web layer just relays. """
    status, response = _send_oidc_command('oidc_discovery', {})
    if status is None:
        return jsonify(response), 500
    if not status:
        return jsonify(response), 500
    return jsonify(response), 200


# ---------------------------------------------------------------------------
# JWKS: /jwks
# ---------------------------------------------------------------------------


@oidc_bp.route('/jwks', methods=['GET', 'OPTIONS'])
def jwks():
    """ Public signing keys (active + retired). ssod strips private
    parameters via joserfc per-kty allowlist; only public material
    leaves the OP. """
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
    """ /token endpoint per RFC 6749 §3.2 + OIDC Core 3.1.3.

    Dispatches by ``grant_type`` (server-side in ssod). Currently
    handles ``authorization_code`` and ``refresh_token``.

    Client auth: ``client_secret_basic`` (Authorization: Basic) or
    ``client_secret_post`` (form body). Public clients with
    ``token_endpoint_auth_method=none`` may omit the secret as long
    as PKCE is in play.

    Responses are RFC-mandated to be ``Cache-Control: no-store``.
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
        # Per RFC 6749 §5.2: invalid_client => 401, others => 400.
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
    """ /userinfo per OIDC Core 5.3.

    Auth: ``Authorization: Bearer <access_token>``. The token is
    self-identifying; no client credentials. Returns user claims
    filtered by the granted scope of the originating session.

    On authentication failure: HTTP 401 with
    ``WWW-Authenticate: Bearer error="invalid_token"`` per RFC 6750
    §3.
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
    """ /introspect per RFC 7662.

    Server-to-server: RP authenticates via ``client_id`` +
    ``client_secret`` (Basic header or form body).

    Request body: ``token`` (REQUIRED), ``token_type_hint``
    (OPTIONAL: ``access_token``/``refresh_token``).

    Response per RFC 7662 §2.2: HTTP 200 with ``{"active": true,
    ...}`` for currently-valid tokens, ``{"active": false}`` for
    anything else. The "anything else" branch covers unknown,
    expired, revoked, AND tokens belonging to a different client --
    no information leak about token existence.

    Real HTTP errors (4xx) only on client-auth failure or missing
    ``token`` parameter.
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

    # Per RFC 7662, success = HTTP 200 regardless of active true/false.
    return _no_store(make_response(jsonify(response), 200))


# ---------------------------------------------------------------------------
# Revocation: /revoke
# ---------------------------------------------------------------------------


@oidc_bp.route('/revoke', methods=['POST', 'OPTIONS'])
def revoke():
    """ /revoke per RFC 7009.

    Server-to-server: RP authenticates via ``client_id`` +
    ``client_secret``.

    Request body: ``token`` (REQUIRED), ``token_type_hint``
    (OPTIONAL).

    Response per RFC 7009 §2.2: HTTP 200 with empty body for ANY
    valid request -- whether the token existed, was already
    revoked, or belongs to a different client. This prevents
    token-existence probing. Real HTTP errors only on client-auth
    failure or missing ``token`` parameter.
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

    # Success per RFC 7009: 200 with empty JSON body.
    return _no_store(make_response(jsonify({}), 200))


# ---------------------------------------------------------------------------
# End Session: /end_session
# ---------------------------------------------------------------------------


def _append_state(target_uri, state):
    """ Append ``state=<value>`` to a redirect URI, preserving any
    existing query string. Per OIDC RP-Initiated Logout 1.0 the OP
    MUST echo back the state value to the post_logout_redirect_uri.
    """
    if not target_uri or not state:
        return target_uri
    from urllib.parse import urlencode
    sep = '&' if '?' in target_uri else '?'
    return f"{target_uri}{sep}{urlencode([('state', state)])}"


def _logged_out_page():
    """ Generic OP logout-success page when no validated
    post_logout_redirect_uri is available. """
    html = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<title>Logged out</title></head>"
        "<body><h1>Logged out</h1>"
        "<p>You have been logged out.</p>"
        "</body></html>"
    )
    resp = make_response(html, 200)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@oidc_bp.route('/end_session', methods=['GET', 'POST'])
def end_session():
    """ /end_session per OIDC RP-Initiated Logout 1.0.

    Browser-driven, no client_secret envelope -- trust comes from
    the signed ``id_token_hint``.

    ssod decides scope per the resolved client's
    ``oidc_logout_scope`` config (sso or rp) and validates the
    requested ``post_logout_redirect_uri`` against the client's
    allowlist. The web layer just acts on the action ssod returns.
    """
    id_token_hint = request.values.get('id_token_hint')
    client_id_q = request.values.get('client_id')
    post_logout_redirect_uri = request.values.get('post_logout_redirect_uri')
    state = request.values.get('state')

    if not id_token_hint:
        return _oidc_error('invalid_request',
                           'id_token_hint missing',
                           http_status=400)

    args = {
        'id_token_hint':            id_token_hint,
        'client_id':                client_id_q,
        'post_logout_redirect_uri': post_logout_redirect_uri,
    }
    status, response = _send_oidc_command('oidc_end_session', args)
    if status is None:
        return _oidc_error('server_error',
                           response.get('error_description'),
                           http_status=500)

    if not status:
        err = (response or {}).get('error', 'invalid_request')
        desc = (response or {}).get('error_description')
        return _oidc_error(err, desc, http_status=400)

    action = (response or {}).get('action')
    validated_uri = (response or {}).get('post_logout_redirect_uri')
    target = _append_state(validated_uri, state)

    if action == 'redirect_logout':
        # scope=sso: terminate the user's SSO session via the
        # existing SLP-based logout (cascades into all child
        # OIDCSessions; each fires backchannel-logout if configured).
        if target:
            resp = make_response(redirect(target))
        else:
            resp = _logged_out_page()
        return _do_sso_logout(resp)

    if action == 'redirect_post_logout':
        # scope=rp: ssod already killed the calling RP's OIDCSession
        # (and fired its backchannel logout). SSO session + other RPs
        # stay logged in. Just send the user back to the RP.
        if target:
            return redirect(target)
        return _logged_out_page()

    # Unknown action -- fall back to generic confirmation.
    return _logged_out_page()


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


def _authorize_error_page(error, description):
    """ Tier-1 error page -- displayed when redirect_uri/client_id
    is invalid and we MUST NOT redirect (open-redirect defense).
    """
    safe_err = (error or "invalid_request").replace("<", "&lt;").replace(">", "&gt;")
    safe_desc = (description or "").replace("<", "&lt;").replace(">", "&gt;")
    html = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<title>Authorization error</title></head>"
        "<body><h1>Authorization error</h1>"
        f"<p><strong>{safe_err}</strong></p>"
        f"<p>{safe_desc}</p>"
        "</body></html>"
    )
    resp = make_response(html, 400)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@oidc_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """ /authorize per OIDC Core 3.1.

    Browser-driven. Three roundtrips:
      1. ssod ``oidc_authorize_validate`` -> validates + issues SOTP
      2. authd ``verify`` with SOTP + oidc_context=True -> auth_code
      3. 302 to redirect_uri with code + state

    If the user has no SSO session yet, /login is invoked with
    ``next=<this URL>`` so they come back here after authenticating.
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

    # SSO cookie check -- if user isn't logged in, hand off to /login
    # with our full URL as next= so they bounce back here after auth.
    sso_jwt = request.cookies.get('otpme_jwt')
    username = flask_session.get('otpme_username')
    session_uuid = request.cookies.get('otpme_sso_session')
    if not sso_jwt or not username or not session_uuid:
        return redirect(url_for('login',
                                next=request.full_path,
                                _external=True, _scheme='https'))

    client_ip = check_forwarded_for()[0]

    # Step 1: ssod validates the request and -- on success -- hands
    # back a SOTP scoped to the OIDC client's access_group.
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
    }
    ssod_conn = get_ssod_conn(username)
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
            # JWT trouble -> back to login (treat like missing SSO).
            if v_response.get('message') == 'JWT_INVALID':
                return redirect(url_for('login',
                                        next=request.full_path,
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

    # Success: extract SOTP from the response.
    sotp_value = v_response.get('sotp')
    if not sotp_value:
        return _authorize_error_page('server_error',
                                     'failed to obtain SOTP')

    # Step 2: authd verify with SOTP + OIDC context. auth_handler
    # validates SOTP -> finds parent SSO session -> attaches OIDCSession
    # via add_oidc_child_session -> returns oidc_authcode.
    verify_args = {
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
