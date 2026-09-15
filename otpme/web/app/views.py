# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import json
import time
import threading

from urllib.parse import urlparse, urljoin

from flask import g
from flask import flash
from flask import jsonify
#from flask import abort
from flask import url_for
from flask import request
from flask import redirect
from flask import make_response
from flask import render_template
from flask_login import UserMixin
from flask_login import login_user
from flask_login import logout_user
from flask_login import current_user
from flask_login import login_required
from flask import session as flask_session
from flask_babel import gettext

#from markupsafe import escape

from otpme.web.app import lm
from otpme.web.app import app
from otpme.web.app import csrf
from otpme.web.app import limiter
from otpme.web.app.forms import LoginForm

from otpme.lib import jwt
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections

from otpme.lib.exceptions import *

logger = config.logger

class WebUser(UserMixin):
    """ Flask-login compatible user object decoupled from OTPme backend. """
    def __init__(self, uuid, name):
        self.id = uuid
        self.uuid = uuid
        self.name = name

def get_authd_conn(username,  password=None, node=None):
    if config.host_data['type'] == "node":
        authd_conn = connections.get("authd",
                                    realm=config.realm,
                                    site=config.site,
                                    username=username,
                                    password=password,
                                    #auto_preauth=True,
                                    auto_auth=False,
                                    socket_uri=config.authd_socket_path,
                                    local_socket=True,
                                    use_ssl=False,
                                    handle_host_auth=False,
                                    handle_user_auth=False,
                                    encrypt_session=False)
    else:
        authd_conn = connections.get("authd",
                                    node=node,
                                    realm=config.realm,
                                    site=config.site,
                                    username=username,
                                    password=password,
                                    auto_preauth=True,
                                    follow_redirect=False,
                                    request_token=False,
                                    auto_auth=False)
    return authd_conn

def get_ssod_conn(username, master_failover_timeout=10, mgmt=False):
    use_socket = False
    if config.host_data['type'] == "node":
        if mgmt:
            if config.master_node:
                use_socket = True
        else:
            use_socket = True
    if use_socket:
        ssod_conn = connections.get("ssod",
                                    realm=config.realm,
                                    site=config.site,
                                    username=username,
                                    auto_auth=False,
                                    socket_uri=config.ssod_socket_path,
                                    local_socket=True,
                                    use_ssl=False,
                                    handle_host_auth=False,
                                    handle_user_auth=False,
                                    encrypt_session=False)
    else:
        start_time = time.time()
        while True:
            try:
                ssod_conn = connections.get("ssod",
                                            mgmt=mgmt,
                                            realm=config.realm,
                                            site=config.site,
                                            username=username,
                                            follow_redirect=False,
                                            request_token=False,
                                            auto_preauth=False,
                                            auto_auth=False,
                                            encrypt_session=False)
            except (MasterFailover, ConnectionQuit, ConnectionError):
                now = time.time()
                if (now - start_time) <= master_failover_timeout:
                    continue
            except Exception:
                raise
            else:
                break
    return ssod_conn

def check_forwarded_for():
    """ Get X-Forwarded-For and X-Forwarded-Host for reverse proxy setups. """
    from otpme.lib import net
    client = net.normalize_ip(request.remote_addr)
    hostname = request.host.split(':')[0]
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    x_forwarded_host = request.headers.get('X-Forwarded-Host')
    if not x_forwarded_for:
        if not x_forwarded_host:
            return client, hostname
    site = backend.get_object(object_type="site", uuid=config.site_uuid)
    reverse_proxy_ips = site.get_config_parameter("reverse_proxy_ips")
    if not reverse_proxy_ips:
        return client, hostname
    if client not in reverse_proxy_ips:
        return client, hostname
    if x_forwarded_for:
        client = x_forwarded_for.split(',')[0].strip()
        client = net.normalize_ip(client)
    if x_forwarded_host:
        hostname = x_forwarded_host.split(',')[0].strip().split(':')[0]
    return client, hostname

def _ssod_error_message(response, default):
    """ Extract a user-friendly error message from an ssod response. """
    if isinstance(response, dict):
        return response.get('message') or response.get('error') or default
    if response:
        return str(response)
    return default

def _card_max_tokens(response):
    """ sso_max_<type>_token from a token listing, or None for no limit.
    The JS compares it with the listing's length. """
    if not isinstance(response, dict):
        return None
    try:
        return int(response['max_tokens'])
    except (KeyError, TypeError, ValueError):
        return None

def _get_fido2_rp_id():
    """ Get RP ID from request host for WebAuthn browser compatibility.
        Checks X-Forwarded-Host for reverse proxy setups. """
    rp_id = check_forwarded_for()[1]
    return rp_id

@lm.user_loader
def load_user(id):
    # Restore user from Flask session data.
    username = flask_session.get('otpme_username')
    if not username:
        return None
    return WebUser(uuid=id, name=username)

@app.before_request
def before_request():
    config.proc_mode = "threading"
    g.user = current_user

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        # No 'unsafe-inline': all dynamic show/hide goes through the
        # utility classes in otpme.css (.is-hidden / .is-block / .mt-8 /
        # ...). Keeping 'unsafe-inline' out closes CSS-based exfiltration
        # and click-hijacking vectors should HTML injection ever slip
        # past escaping somewhere else.
        "style-src 'self'; "
        "img-src 'self' data:; "
        # frame-ancestors is the CSP-native replacement for the
        # X-Frame-Options header below. Modern browsers prefer it and
        # some have started ignoring X-Frame-Options when CSP is set
        # -- shipping both keeps older browsers covered.
        "frame-ancestors 'none';"
    )
    # Force HTTPS for a year. includeSubDomains locks down anything
    # under the same registered domain -- safe for a dedicated SSO
    # FQDN. preload is intentionally NOT set (that's an opt-in to
    # browser HSTS-preload lists, requires separate submission).
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
    # Disallow MIME-type sniffing.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Disallow framing entirely. We don't enable OIDC front-channel
    # logout (frontchannel_logout_supported=False in discovery), so
    # DENY is correct. Relax to SAMEORIGIN per-route if a future
    # page legitimately needs framing.
    response.headers['X-Frame-Options'] = 'DENY'
    # Send Referer only to same origin on cross-origin navigations.
    # Avoids leaking auth-flow URLs (codes, state) to arbitrary
    # referrers while keeping intra-app referrers for analytics.
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Block browser access to powerful features the SSO portal has no
    # legitimate use for. Anything not listed defaults to "deny for
    # cross-origin contexts only" per the spec; we additionally lock
    # down camera/microphone/geolocation/payment/usb to allow no
    # origin at all (including same-origin) -- the portal doesn't
    # need them, so a future XSS can't pop a permission prompt.
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), '
        'autoplay=(), '
        'camera=(), '
        'display-capture=(), '
        'fullscreen=(), '
        'geolocation=(), '
        'gyroscope=(), '
        'magnetometer=(), '
        'microphone=(), '
        'midi=(), '
        'payment=(), '
        'usb=()'
    )
    return response

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/')
@app.route('/index')
def index():
    if not g.user:
        return redirect(url_for('login', _external=True, _scheme='https'))
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Redirect to deploy page if token enrollment is required.
    sso_deploy = flask_session.get('sso_deploy')
    if sso_deploy:
        # Voluntary redeploy from settings: clear flag and let the user leave.
        if flask_session.pop('sso_deploy_optional', False):
            flask_session.pop('sso_deploy', None)
        else:
            return redirect(url_for('deploy', _external=True, _scheme='https'))
    return render_template("index.html", title=gettext('SSO Portal'))

# Rate-limit helpers for the authenticated /settings/* and credential-
# change endpoints. Defined above the first route that uses them
# because `@limiter.limit(...)` decorator arguments are evaluated at
# module import time -- the callable itself only runs per request.
# _site_rate_limit lives further down but is only called at request
# time, so its later definition is fine (name resolution deferred).
def _rate_limit_settings():
    return _site_rate_limit("sso_rate_limit_settings") or "60/minute"


def _settings_user_key():
    """ Rate-limit key for authenticated /settings/* and credential-
    change endpoints. Keyed on the authenticated username so a
    single user hammering the settings backend from many browser
    tabs / a runaway poll loop can't burn a shared IP bucket.
    Falls back to remote IP if somehow called outside an active
    login session (defense in depth; every settings route is
    @login_required). """
    try:
        if getattr(current_user, 'is_authenticated', False):
            name = getattr(current_user, 'name', None)
            if name:
                return f"settings-user:{name}"
    except Exception:
        pass
    from otpme.web.app import _ratelimit_key
    return _ratelimit_key()


@app.route('/settings')
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def settings():
    login_token_pass_type = flask_session.get('login_token_pass_type')
    login_token_type = flask_session.get('login_token_type')
    show_password_change = (login_token_pass_type == "static")
    show_pin_change = (login_token_pass_type == "otp")
    # Re-deploy hidden when the user logged in with a passkey: passkeys
    # are web-only (no CLI/QR enrollment flow), so the existing
    # settings_redeploy → /deploy path doesn't apply.
    show_redeploy = (login_token_type != "passkey")
    from otpme.web.app import SUPPORTED_LOCALES
    # Stashed value reflects user.language only when language_set=True;
    # the "default" sentinel is what we POST back to clear it.
    current_language = flask_session.get('user_language') or "default"
    # Build (code, label) pairs. Label is the locale's native display
    # name ("Deutsch", "English"); falls back to the bare code if Babel
    # can't parse it (custom locales).
    from babel import Locale, UnknownLocaleError
    locale_choices = []
    for code in SUPPORTED_LOCALES:
        try:
            label = Locale.parse(code).get_display_name(code)
        except (UnknownLocaleError, Exception):
            label = code
        locale_choices.append({'code': code, 'label': label})
    return render_template("settings.html", title=gettext('Settings'),
                           show_password_change=show_password_change,
                           show_pin_change=show_pin_change,
                           show_redeploy=show_redeploy,
                           locale_choices=locale_choices,
                           current_language=current_language)

def _stash_user_language(language):
    """ Stash the user's persisted language pref in the Flask session
    so Babel's locale selector can pick it up on every subsequent
    request without re-hitting authd. The web layer can run on an
    SSO host that has no local backend access, so the value must
    arrive from authd's auth_response -- we never look it up here. """
    if language:
        flask_session['user_language'] = language
    else:
        flask_session.pop('user_language', None)

def _stash_admin_access_state(state):
    """ Cache the user's admin-access flag in the Flask session so a
    context processor can surface a "Admin access enabled" badge on
    every page without re-hitting ssod. Accepts either the raw dict
    returned by the get/set_admin_access_state SSOD response
    (``{'available': bool, 'enabled': bool, ...}``) or a plain bool
    (from a toggle). Cleared with ``None``. """
    if state is None:
        flask_session.pop('admin_access_enabled', None)
        return
    if isinstance(state, dict):
        enabled = bool(state.get('enabled'))
    else:
        enabled = bool(state)
    flask_session['admin_access_enabled'] = enabled

def _refresh_admin_access_state_post_login(username, sso_jwt, session_uuid):
    """ Fetch admin-access state directly against ssod without going
    through ``_send_ssod_command`` -- the login handler has just called
    ``login_user()`` but ``g.user`` and the request cookies aren't
    updated yet, so we pass the freshly-issued JWT / session_uuid in
    explicitly. Best-effort: ssod hiccups don't fail the login. """
    try:
        client_ip = check_forwarded_for()[0]
        command_args = {
                        'username'      : username,
                        'sso_jwt'       : sso_jwt,
                        'client'        : config.sso_client_name,
                        'client_ip'     : client_ip,
                        'session_uuid'  : session_uuid,
                    }
        accept_language = _browser_preferred_language()
        if accept_language:
            command_args['accept_language'] = accept_language
        ssod_conn = get_ssod_conn(username, mgmt=False)
        try:
            status, _status_code, response, _binary = ssod_conn.send(
                    command="get_admin_access_state",
                    command_args=command_args)
        finally:
            try:
                ssod_conn.close()
            except Exception:
                pass
        if not status:
            return
        _stash_admin_access_state(response)
    except Exception as e:
        logger.debug(f"admin-access post-login refresh failed: {e}")

def _browser_preferred_language():
    """ Pull the highest-quality language tag from the request's
    Accept-Language header and reduce it to a short code (e.g. "de-CH"
    -> "de"). Returned as a soft hint -- the server still prioritizes
    an explicit CLI/API `language` arg and the user's stored language
    pref above this. Returns None if the header is absent or unparseable
    (we never invent a default here; that decision belongs on the
    server). """
    try:
        accept = request.accept_languages
        if not accept:
            return None
        best = accept.best
        if not best:
            return None
        return best.split('-', 1)[0].split('_', 1)[0].lower()
    except Exception:
        return None

def _send_ssod_command(command, extra_args=None, default_error=None, mgmt=False,
    error_messages=None):
    """ Send a command to ssod using the current user's JWT.

    ``error_messages`` maps the codes ssod answers with to the text the
    user gets instead.

    Returns a Flask response on error, otherwise the response payload dict. """
    if extra_args is None:
        extra_args = {}
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    session_uuid = request.cookies.get('otpme_sso_session')
    command_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                    'session_uuid'  : session_uuid,
                }
    accept_language = _browser_preferred_language()
    if accept_language:
        command_args['accept_language'] = accept_language
    command_args.update(extra_args)
    ssod_conn = get_ssod_conn(g.user.name, mgmt=mgmt)
    try:
        status, \
        status_code, \
        response, \
        binary_data = ssod_conn.send(command=command, command_args=command_args)
    except Exception as e:
        log_msg = _("ssod command '{command}' failed: {user_name}", log=True)[1]
        log_msg = log_msg.format(command=command, user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return None, (jsonify({"error": default_error}), 500)
    finally:
        ssod_conn.close()
    if not status:
        # Invalid/expired JWT: force logout so the user re-authenticates.
        do_logout = False
        if isinstance(response, dict) and response.get('message') == 'JWT_INVALID':
            do_logout = True
        if isinstance(response, dict) and response.get('message') == 'UNKNOWN_SESSION':
            do_logout = True
        if do_logout:
            log_msg = _("SSO JWT invalid for user '{user_name}', logging out.", log=True)[1]
            log_msg = log_msg.format(user_name=g.user.name)
            logger.warning(log_msg)
            resp = make_response(jsonify({
                    "error": gettext("Session expired. Please log in again."),
                    "redirect": url_for('login', _external=True, _scheme='https'),
                }), 401)
            return None, _do_sso_logout(resp)
        # Sensitive action requires a fresh step-up reauth (ssod's
        # _require_fresh_step_up rejected). Signal to the JS layer so
        # it can drive the user through /reauth?next=... and retry
        # the action after the SSO session's reauth_time is bumped.
        if isinstance(response, dict) and response.get('message') == 'STEP_UP_REQUIRED':
            return None, (jsonify({
                    "error": gettext("Please re-authenticate to continue."),
                    "step_up_required": True,
                }), 401)
        error_msg = _ssod_error_message(response, default_error)
        if error_messages and error_msg in error_messages:
            error_msg = error_messages[error_msg]
        return None, (jsonify({"error": error_msg}), 400)
    return response, None

@app.route('/settings/device_tokens', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_device_tokens():
    try:
        response, error = _send_ssod_command(command="list_device_tokens",
                                        default_error=gettext("Failed to list device tokens."))
    except Exception as e:
        logger.critical(f"list_device_tokens failed: {e}")
        return jsonify({"error": gettext("Failed to list device tokens.")}), 500
    if error:
        return error
    roles = []
    roles_configured = False
    if isinstance(response, dict):
        roles = response.get('roles', []) or []
        roles_configured = bool(response.get('roles_configured', False))
    return jsonify({
                "roles"             : roles,
                "roles_configured"  : roles_configured,
            })

@app.route('/settings/device_tokens', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def add_device_token():
    data = request.json or {}
    device_name = data.get('device_name', '').strip()
    role_uuid = (data.get('role_uuid') or '').strip()
    # One of the role's device_token_types; ssod picks the role's first
    # when there is none.
    token_type = (data.get('token_type') or '').strip()
    if not device_name:
        return jsonify({"error": gettext("Device name is required.")}), 400
    if not role_uuid:
        return jsonify({"error": gettext("Role is required.")}), 400
    extra_args = {'device_name': device_name, 'role_uuid': role_uuid}
    if token_type:
        extra_args['token_type'] = token_type
    response, error = _send_ssod_command(command="add_device_token",
                                        extra_args=extra_args,
                                        default_error=gettext("Failed to add device token."),
                                        mgmt=True)
    if error:
        return error
    # Shown to the user once: the password of a password token, the
    # secret and its QR code of a TOTP one.
    return jsonify({
                "status"        : "ok",
                "name"          : response.get('name'),
                "device_name"   : response.get('device_name'),
                "token_type"    : response.get('token_type') or 'password',
                "password"      : response.get('password'),
                "secret"        : response.get('secret'),
                "qrcode_img"    : response.get('qrcode_img'),
            })

@app.route('/settings/device_tokens/delete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def del_device_token():
    data = request.json or {}
    token_name = data.get('name', '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    response, error = _send_ssod_command(command="del_device_token",
                                        extra_args={'token_name': token_name},
                                        default_error=gettext("Failed to delete device token."),
                                        mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok", "message": "Device token deleted."})

@app.route('/settings/device_tokens/toggle', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def toggle_device_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    if 'enabled' not in data:
        return jsonify({"error": gettext("Missing 'enabled' flag.")}), 400
    enabled = bool(data.get('enabled'))
    command = "enable_device_token" if enabled else "disable_device_token"
    default_error = (gettext("Failed to enable device token.")
                    if enabled
                    else gettext("Failed to disable device token."))
    response, error = _send_ssod_command(command=command,
                                        extra_args={'token_name': token_name},
                                        default_error=default_error,
                                        mgmt=True)
    if error:
        return error
    new_enabled = bool(response.get('enabled')) if isinstance(response, dict) else enabled
    return jsonify({"status": "ok", "enabled": new_enabled})

@app.route('/settings/passkeys', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_passkeys():
    try:
        response, error = _send_ssod_command(
                command="list_passkeys",
                default_error=gettext("Failed to list passkeys."))
    except Exception as e:
        logger.critical(f"list_passkeys failed: {e}")
        return jsonify({"error": gettext("Failed to list passkeys.")}), 500
    if error:
        return error
    passkeys = []
    # ``allowed`` is what ssod answers when sso_allow_passkeys is off
    # for this user -- an empty list on its own does not say whether
    # the feature is disabled or the user simply has no passkey yet,
    # and the JS hides the whole card on the first but not the second.
    # Dropping it here left the card visible with an add button behind
    # a command that refuses.
    allowed = False
    if isinstance(response, dict):
        passkeys = response.get('passkeys', []) or []
        allowed = bool(response.get('allowed', False))
    return jsonify({"passkeys": passkeys,
                    "allowed": allowed,
                    "max_tokens": _card_max_tokens(response)})

@app.route('/settings/passkeys/register/begin', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def passkey_register_begin():
    """ Start passkey enrollment.

    Returns the WebAuthn ``create_options`` for the browser, and stashes
    the reg_state + sanitized token_name + display name in the Flask
    session so ``complete`` can verify them server-side without
    trusting client-supplied values. """
    data = request.json or {}
    device_name = (data.get('device_name') or '').strip()
    if not device_name:
        return jsonify({"error": gettext("Device name is required.")}), 400
    rp_id = _get_fido2_rp_id()
    response, error = _send_ssod_command(
            command="passkey_register_begin",
            extra_args={'device_name': device_name, 'rp_id': rp_id},
            default_error=gettext("Failed to start passkey registration."),
            mgmt=True)
    if error:
        return error
    if not isinstance(response, dict):
        return jsonify({"error": gettext("Failed to start passkey registration.")}), 500
    # State lives on the ssod-side master node in
    # multiprocessing.passkey_reg_states keyed by an opaque state-id.
    # Registration always routes through the master (mgmt=True; no
    # multi-master in OTPme), so the Flask session only carries the
    # state-id -- no WebAuthn challenge / device-name leak via cookie.
    flask_session['passkey_state_id'] = response.get('passkey_state_id')
    return jsonify(response.get('create_options', {}))

@app.route('/settings/passkeys/register/complete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def passkey_register_complete():
    passkey_state_id = flask_session.pop('passkey_state_id', None)
    if not passkey_state_id:
        return jsonify({"error": gettext("No passkey registration in progress")}), 400
    registration_data = request.json
    if not registration_data:
        return jsonify({"error": gettext("Missing registration data")}), 400
    rp_id = _get_fido2_rp_id()
    response, error = _send_ssod_command(
            command="passkey_register_complete",
            extra_args={
                'rp_id'             : rp_id,
                'passkey_state_id'  : passkey_state_id,
                'registration_data' : registration_data,
            },
            default_error=gettext("Failed to complete passkey registration."),
            mgmt=True)
    if error:
        return error
    return jsonify({
                "status"        : "ok",
                "name"          : response.get('name'),
                "device_name"   : response.get('device_name'),
                # ssod sets this only when the account lives on another
                # site and it had to push the assignment there. The UI
                # then says the login may take a moment; without it,
                # nothing to say.
                "sync_pending"  : bool(response.get('sync_pending')),
            })

@app.route('/settings/passkeys/delete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def del_passkey():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    response, error = _send_ssod_command(
            command="del_passkey",
            extra_args={'token_name': token_name},
            default_error=gettext("Failed to delete passkey."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok", "message": "Passkey deleted."})

@app.route('/settings/passkeys/toggle', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def toggle_passkey():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    if 'enabled' not in data:
        return jsonify({"error": gettext("Missing 'enabled' flag.")}), 400
    enabled = bool(data.get('enabled'))
    command = "enable_passkey" if enabled else "disable_passkey"
    default_error = (gettext("Failed to enable passkey.")
                    if enabled
                    else gettext("Failed to disable passkey."))
    response, error = _send_ssod_command(
            command=command,
            extra_args={'token_name': token_name},
            default_error=default_error,
            mgmt=True)
    if error:
        return error
    new_enabled = bool(response.get('enabled')) if isinstance(response, dict) else enabled
    return jsonify({"status": "ok", "enabled": new_enabled})

@app.route('/settings/fido2', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_fido2_tokens():
    """ The user's security keys.

    Includes the SSO token when that is a fido2 one, flagged as such --
    same reasoning as the tiqr listing. ``allowed`` reports the
    sso_allow_fido2 cascade so the frontend can hide the whole card. """
    try:
        response, error = _send_ssod_command(
                command="list_fido2_tokens",
                default_error=gettext("Failed to list security keys."))
    except Exception as e:
        logger.critical(f"list_fido2_tokens failed: {e}")
        return jsonify({"error": gettext("Failed to list security keys.")}), 500
    if error:
        return error
    fido2_tokens = []
    allowed = False
    sso_token = {}
    if isinstance(response, dict):
        fido2_tokens = response.get('fido2_tokens', []) or []
        allowed = bool(response.get('allowed', False))
        sso_token = {
                    'name'      : response.get('sso_token_name'),
                    'type'      : response.get('sso_token_type'),
                    'label'     : response.get('sso_token_label'),
                    'suggested' : response.get('sso_token_suggested_label'),
                    'ask_label' : bool(response.get('sso_token_ask_label', True)),
                    # False: an administrator chose the SSO token, the
                    # cards offer no promotion.
                    'managed'   : bool(response.get('sso_token_managed', False)),
                }
    return jsonify({"fido2_tokens": fido2_tokens,
                    "allowed": allowed,
                    "max_tokens": _card_max_tokens(response),
                    "sso_token": sso_token})

@app.route('/settings/fido2/add/begin', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def fido2_add_begin():
    """ Start registering another security key.

    Same shape as passkey_register_begin: the state lives on the ssod
    master under an opaque id, and only that id goes into the Flask
    session -- no WebAuthn challenge or in-flight device name in a
    cookie. """
    data = request.json or {}
    device_name = (data.get('device_name') or '').strip()
    if not device_name:
        return jsonify({"error": gettext("Device name is required.")}), 400
    rp_id = _get_fido2_rp_id()
    response, error = _send_ssod_command(
            command="fido2_add_begin",
            extra_args={'device_name': device_name, 'rp_id': rp_id},
            default_error=gettext("Failed to start security key registration."),
            mgmt=True)
    if error:
        return error
    if not isinstance(response, dict):
        return jsonify({"error": gettext("Failed to start security key registration.")}), 500
    flask_session['fido2_add_state_id'] = response.get('fido2_state_id')
    return jsonify(response.get('create_options', {}))

@app.route('/settings/fido2/add/complete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def fido2_add_complete():
    fido2_state_id = flask_session.pop('fido2_add_state_id', None)
    if not fido2_state_id:
        return jsonify({"error": gettext("No security key registration in progress")}), 400
    registration_data = request.json
    if not registration_data:
        return jsonify({"error": gettext("Missing registration data")}), 400
    rp_id = _get_fido2_rp_id()
    response, error = _send_ssod_command(
            command="fido2_add_complete",
            extra_args={
                'rp_id'             : rp_id,
                'fido2_state_id'    : fido2_state_id,
                'registration_data' : registration_data,
            },
            default_error=gettext("Failed to complete security key registration."),
            mgmt=True)
    if error:
        return error
    return jsonify({
                "status"        : "ok",
                "name"          : response.get('name'),
                "device_name"   : response.get('device_name'),
                # See passkey_register_complete.
                "sync_pending"  : bool(response.get('sync_pending')),
            })

@app.route('/settings/fido2/delete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def del_fido2_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    response, error = _send_ssod_command(
            command="del_fido2_token",
            extra_args={'token_name': token_name},
            default_error=gettext("Failed to delete security key."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok"})

@app.route('/settings/fido2/toggle', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def toggle_fido2_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    if 'enabled' not in data:
        return jsonify({"error": gettext("Missing 'enabled' flag.")}), 400
    enabled = bool(data.get('enabled'))
    command = "enable_fido2_token" if enabled else "disable_fido2_token"
    default_error = (gettext("Failed to enable security key.")
                    if enabled
                    else gettext("Failed to disable security key."))
    response, error = _send_ssod_command(
            command=command,
            extra_args={'token_name': token_name},
            default_error=default_error,
            mgmt=True)
    if error:
        return error
    new_enabled = bool(response.get('enabled')) if isinstance(response, dict) else enabled
    return jsonify({"status": "ok", "enabled": new_enabled})

@app.route('/settings/tiqr', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_tiqr_tokens():
    """ The user's enrolled phones.

    Includes the SSO token when that is a tiqr one, flagged as such.
    Hiding it would be worse: somebody with two phones would see one,
    and the one they cannot see is the one that matters most. """
    try:
        response, error = _send_ssod_command(
                command="list_tiqr_tokens",
                default_error=gettext("Failed to list tiqr tokens."))
    except Exception as e:
        logger.critical(f"list_tiqr_tokens failed: {e}")
        return jsonify({"error": gettext("Failed to list tiqr tokens.")}), 500
    if error:
        return error
    tiqr_tokens = []
    allowed = False
    sso_token = {}
    if isinstance(response, dict):
        tiqr_tokens = response.get('tiqr_tokens', []) or []
        allowed = bool(response.get('allowed', False))
        # Passed on so the promote dialog can name the token it is
        # about to rename, which need not be one of the phones above.
        # ask_label says whether the suggestion is the token's own
        # label or one we made up; only the latter is worth a dialog.
        sso_token = {
                    'name'      : response.get('sso_token_name'),
                    'type'      : response.get('sso_token_type'),
                    'label'     : response.get('sso_token_label'),
                    'suggested' : response.get('sso_token_suggested_label'),
                    'ask_label' : bool(response.get('sso_token_ask_label', True)),
                    # False: an administrator chose the SSO token, the
                    # cards offer no promotion.
                    'managed'   : bool(response.get('sso_token_managed', False)),
                }
    return jsonify({"tiqr_tokens": tiqr_tokens,
                    "allowed": allowed,
                    "max_tokens": _card_max_tokens(response),
                    "sso_token": sso_token})


@app.route('/settings/tiqr/enroll/begin', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def tiqr_enroll_begin():
    """ Start enrolling a phone.

    Nothing is created here -- the token appears once the phone has
    delivered its secret, the same way a passkey slot does. The name
    the token will get is stashed so the status poll knows what to
    look for. """
    data = request.json or {}
    device_name = (data.get('device_name') or '').strip()
    if not device_name:
        return jsonify({"error": gettext("Device name is required.")}), 400
    response, error = _send_ssod_command(
            command="tiqr_enroll_begin",
            extra_args={'device_name': device_name},
            default_error=gettext("Failed to start tiqr enrollment."))
    if error:
        return error
    if not isinstance(response, dict):
        return jsonify({"error": gettext("Failed to start tiqr enrollment.")}), 500
    flask_session['tiqr_enroll_token_name'] = response.get('token_name')
    # Carried from begin to the poll below: the enrollment itself is
    # answered to the phone, so this is the only place the browser
    # learns whether there will be anything to wait for, and the poll
    # is where it gets to say so.
    flask_session['tiqr_enroll_sync_pending'] = bool(response.get('sync_pending'))
    return jsonify({
                "status"        : "ok",
                "enroll_url"    : response.get('enroll_url'),
                "qrcode_img"    : response.get('qrcode_img'),
                "device_name"   : response.get('device_name'),
            })


@app.route('/settings/tiqr/enroll/status', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def tiqr_enroll_status():
    """ Has the phone finished?

    Asks the same list the settings page shows rather than a command of
    its own: the token existing there IS the answer, and there is no
    enrollment state anywhere else to ask. """
    token_name = flask_session.get('tiqr_enroll_token_name')
    if not token_name:
        return jsonify({"status": "none"})
    response, error = _send_ssod_command(
            command="list_tiqr_tokens",
            default_error=gettext("Failed to list tiqr tokens."))
    if error:
        return error
    tiqr_tokens = []
    if isinstance(response, dict):
        tiqr_tokens = response.get('tiqr_tokens', []) or []
    for token in tiqr_tokens:
        if token.get('name') != token_name:
            continue
        flask_session.pop('tiqr_enroll_token_name', None)
        sync_pending = flask_session.pop('tiqr_enroll_sync_pending', False)
        return jsonify({"status": "ok",
                        "token": token,
                        "sync_pending": bool(sync_pending)})
    return jsonify({"status": "pending"})


@app.route('/settings/tiqr/delete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def del_tiqr_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    response, error = _send_ssod_command(
            command="del_tiqr_token",
            extra_args={'token_name': token_name},
            default_error=gettext("Failed to delete tiqr token."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok"})


@app.route('/settings/tiqr/toggle', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def toggle_tiqr_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    enable = bool(data.get('enabled'))
    command = "enable_tiqr_token" if enable else "disable_tiqr_token"
    response, error = _send_ssod_command(
            command=command,
            extra_args={'token_name': token_name},
            default_error=gettext("Failed to update tiqr token."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok", "enabled": enable})


@app.route('/settings/totp', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_totp_tokens():
    """ The user's authenticator apps. Same shape as the tiqr listing. """
    try:
        response, error = _send_ssod_command(
                command="list_totp_tokens",
                default_error=gettext("Failed to list authenticator apps."))
    except Exception as e:
        logger.critical(f"list_totp_tokens failed: {e}")
        return jsonify({"error": gettext("Failed to list authenticator apps.")}), 500
    if error:
        return error
    totp_tokens = []
    allowed = False
    sso_token = {}
    if isinstance(response, dict):
        totp_tokens = response.get('totp_tokens', []) or []
        allowed = bool(response.get('allowed', False))
        sso_token = {
                    'name'      : response.get('sso_token_name'),
                    'type'      : response.get('sso_token_type'),
                    'label'     : response.get('sso_token_label'),
                    'suggested' : response.get('sso_token_suggested_label'),
                    'ask_label' : bool(response.get('sso_token_ask_label', True)),
                    # False: an administrator chose the SSO token, the
                    # cards offer no promotion.
                    'managed'   : bool(response.get('sso_token_managed', False)),
                }
    return jsonify({"totp_tokens": totp_tokens,
                    "allowed": allowed,
                    "max_tokens": _card_max_tokens(response),
                    "sso_token": sso_token})


@app.route('/settings/login_token_options', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def get_login_token_options():
    """ Whether the settings page offers the PIN change and the re-deploy
    of the login token. Both off when ssod cannot be asked: deploy_begin
    and change_pin refuse on their own anyway. """
    response, error = _send_ssod_command(
            command="get_login_token_options",
            default_error=gettext("Failed to load login token options."))
    if error:
        return error
    pin_change = False
    redeploy = False
    if isinstance(response, dict):
        pin_change = bool(response.get('pin_change', False))
        redeploy = bool(response.get('redeploy', False))
    return jsonify({"pin_change": pin_change, "redeploy": redeploy})


@app.route('/settings/totp/enroll/begin', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def totp_enroll_begin():
    """ Start adding an authenticator app.

    Nothing is created here -- ssod keeps secret and PIN under an opaque
    state id until the first code arrives. Only that id goes into the
    Flask session, like the security key flow does. Secret and PIN go to
    the browser: the user has to see them. """
    data = request.json or {}
    device_name = (data.get('device_name') or '').strip()
    if not device_name:
        return jsonify({"error": gettext("Device name is required.")}), 400
    response, error = _send_ssod_command(
            command="totp_enroll_begin",
            extra_args={'device_name': device_name},
            default_error=gettext("Failed to start authenticator app setup."),
            mgmt=True)
    if error:
        return error
    if not isinstance(response, dict):
        return jsonify({"error": gettext("Failed to start authenticator app setup.")}), 500
    flask_session['totp_enroll_state_id'] = response.get('state_id')
    return jsonify({
                "status"        : "ok",
                "qrcode_img"    : response.get('qrcode_img'),
                "secret"        : response.get('secret'),
                "pin"           : response.get('pin'),
                "device_name"   : response.get('device_name'),
            })


@app.route('/settings/totp/enroll/verify', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def totp_enroll_verify():
    """ Check the first code and create the token.

    A wrong code comes back with a new state id, which replaces the old
    one in the Flask session so the user can simply try again. """
    state_id = flask_session.pop('totp_enroll_state_id', None)
    if not state_id:
        return jsonify({"error": gettext("No authenticator app setup in progress.")}), 400
    data = request.json or {}
    otp = (data.get('otp') or '').strip()
    if not otp:
        flask_session['totp_enroll_state_id'] = state_id
        return jsonify({"error": gettext("Code is required.")}), 400
    response, error = _send_ssod_command(
            command="totp_enroll_verify",
            extra_args={'state_id': state_id, 'otp': otp},
            default_error=gettext("Failed to verify the code."),
            mgmt=True)
    if error:
        return error
    if not isinstance(response, dict):
        return jsonify({"error": gettext("Failed to verify the code.")}), 500
    if not response.get('verified'):
        flask_session['totp_enroll_state_id'] = response.get('state_id')
        return jsonify({"error": gettext("Invalid code. Please try again."),
                        "retry": True}), 400
    return jsonify({
                "status"        : "ok",
                "name"          : response.get('name'),
                "device_name"   : response.get('device_name'),
                # See passkey_register_complete.
                "sync_pending"  : bool(response.get('sync_pending')),
            })


@app.route('/settings/totp/delete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def del_totp_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    response, error = _send_ssod_command(
            command="del_totp_token",
            extra_args={'token_name': token_name},
            default_error=gettext("Failed to delete authenticator app."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok"})


@app.route('/settings/totp/toggle', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def toggle_totp_token():
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    enable = bool(data.get('enabled'))
    command = "enable_totp_token" if enable else "disable_totp_token"
    response, error = _send_ssod_command(
            command=command,
            extra_args={'token_name': token_name},
            default_error=gettext("Failed to update authenticator app."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok", "enabled": enable})


@app.route('/settings/totp/pin', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def change_totp_pin():
    """ Set a new PIN on one of the user's authenticator apps. """
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    new_pin = (data.get('new_pin') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    if not new_pin:
        return jsonify({"error": gettext("New PIN is required.")}), 400
    response, error = _send_ssod_command(
            command="change_totp_pin",
            extra_args={'token_name': token_name, 'new_pin': new_pin},
            default_error=gettext("PIN change failed."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok"})


@app.route('/settings/promote', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def promote_token():
    """ Make another of the user's tokens the SSO token.

    Not under /settings/tiqr/ any more: a phone and a security key can
    both hold the role, and the card the button sits on says which one
    is meant.

    Nothing is deleted: the token that held the role keeps working
    under a new name. The caller may supply that name; without one it
    is derived from the device name server-side. """
    data = request.json or {}
    token_name = (data.get('name') or '').strip()
    if not token_name:
        return jsonify({"error": gettext("Token name is required.")}), 400
    extra_args = {'token_name': token_name}
    old_token_name = (data.get('old_name') or '').strip()
    if old_token_name:
        extra_args['old_token_name'] = old_token_name
    response, error = _send_ssod_command(
            command="promote_token",
            extra_args=extra_args,
            default_error=gettext("Failed to change the default token."),
            mgmt=True)
    if error:
        return error
    if not isinstance(response, dict):
        return jsonify({"error": gettext("Failed to change the default token.")}), 500
    return jsonify({
                "status"    : "ok",
                "name"      : response.get('name'),
                "old_name"  : response.get('old_name'),
            })


@app.route('/settings/admin_access', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def get_admin_access_state():
    """ Return whether the admin-access toggle should be shown
    (``available``) and its current state (``enabled``). """
    try:
        response, error = _send_ssod_command(
                command="get_admin_access_state",
                default_error=gettext("Failed to load admin access state."))
    except Exception as e:
        logger.critical(f"get_admin_access_state failed: {e}")
        return jsonify({"error": gettext("Failed to load admin access state.")}), 500
    if error:
        return error
    available = False
    enabled = False
    if isinstance(response, dict):
        available = bool(response.get('available'))
        enabled = bool(response.get('enabled'))
    _stash_admin_access_state(enabled)
    return jsonify({"available": available, "enabled": enabled})

@app.route('/settings/admin_access', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def set_admin_access_state():
    data = request.json or {}
    if 'enabled' not in data:
        return jsonify({"error": gettext("Missing 'enabled' flag.")}), 400
    enabled = bool(data.get('enabled'))
    response, error = _send_ssod_command(
            command="set_admin_access_state",
            extra_args={'enabled': enabled},
            default_error=gettext("Failed to update admin access."),
            mgmt=True)
    if error:
        return error
    new_enabled = bool(response.get('enabled')) if isinstance(response, dict) else enabled
    _stash_admin_access_state(new_enabled)
    return jsonify({
                "status"    : "ok",
                "enabled"   : new_enabled,
            })

@app.route('/settings/step_up_state', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def get_step_up_state():
    """ Which add forms need a fresh /reauth before they are
    shown. Asked when an add button is pressed, so the settings page can
    ask for the reauth before the user types a name -- see
    get_step_up_state in sso1.py for why asking at the button that
    registers does not work. """
    try:
        response, error = _send_ssod_command(
                command="get_step_up_state",
                default_error=gettext("Failed to load settings."))
    except Exception as e:
        logger.critical(f"get_step_up_state failed: {e}")
        return jsonify({"error": gettext("Failed to load settings.")}), 500
    if error:
        return error
    missing = {}
    max_age = 0
    if isinstance(response, dict):
        missing = response.get('step_up_missing') or {}
        max_age = int(response.get('step_up_max_age') or 0)
    return jsonify({
            "step_up_missing":  missing,
            "step_up_max_age":  max_age,
        })

@app.route('/settings/recovery_mail', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def get_recovery_mail():
    """ Return the user's recovery e-mail address (from the
    otpmeRecoveryMail LDIF attribute on the user object) plus the
    step-up max-age so the UI knows how long a fresh /reauth stays
    valid. """
    try:
        response, error = _send_ssod_command(
                command="get_recovery_mail",
                default_error=gettext("Failed to load recovery mail."))
    except Exception as e:
        logger.critical(f"get_recovery_mail failed: {e}")
        return jsonify({"error": gettext("Failed to load recovery mail.")}), 500
    if error:
        return error
    recovery_mail = None
    step_up_max_age = 0
    if isinstance(response, dict):
        recovery_mail = response.get('recovery_mail')
        step_up_max_age = int(response.get('step_up_max_age') or 0)
    return jsonify({
            "recovery_mail":   recovery_mail,
            "step_up_max_age": step_up_max_age,
        })

@app.route('/settings/recovery_mail', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def set_recovery_mail():
    """ Write / clear the user's recovery e-mail address. Requires a
    fresh /reauth (checked in ssod via session.reauth_time within
    sso_reauth_timeout); a stale session triggers step_up_required=True
    in the response so the JS drives the user through /reauth and
    retries. Empty string clears the attribute. """
    data = request.json or {}
    raw = data.get('recovery_mail')
    if raw is None:
        return jsonify({"error": gettext("Missing 'recovery_mail' field.")}), 400
    value = raw.strip() if isinstance(raw, str) else raw
    response, error = _send_ssod_command(
            command="set_recovery_mail",
            extra_args={'recovery_mail': value},
            default_error=gettext("Failed to update recovery mail."),
            mgmt=True)
    if error:
        return error
    stored = None
    if isinstance(response, dict):
        stored = response.get('recovery_mail')
    return jsonify({
            "status":        "ok",
            "recovery_mail": stored,
        })

def _profile_attribute_labels():
    """ What the profile page calls the attributes it knows. Any other
    one is shown by its LDAP name. """
    return {
        'uid'                       : gettext("Username"),
        'cn'                        : gettext("Full name"),
        'givenName'                 : gettext("First name"),
        'sn'                        : gettext("Last name"),
        'displayName'               : gettext("Display name"),
        'initials'                  : gettext("Initials"),
        'mail'                      : gettext("E-mail"),
        'telephoneNumber'           : gettext("Phone"),
        'mobile'                    : gettext("Mobile phone"),
        'homePhone'                 : gettext("Home phone"),
        'facsimileTelephoneNumber'  : gettext("Fax"),
        'title'                     : gettext("Title"),
        'o'                         : gettext("Organization"),
        'ou'                        : gettext("Organizational unit"),
        'departmentNumber'          : gettext("Department"),
        'employeeNumber'            : gettext("Employee number"),
        'manager'                   : gettext("Manager"),
        'roomNumber'                : gettext("Room"),
        'street'                    : gettext("Street"),
        'postalCode'                : gettext("Postal code"),
        'l'                         : gettext("Location"),
        'st'                        : gettext("State"),
        'postalAddress'             : gettext("Postal address"),
        'labeledURI'                : gettext("Website"),
        'preferredLanguage'         : gettext("Preferred language"),
        'description'               : gettext("Description"),
        'uidNumber'                 : gettext("User ID"),
        'gidNumber'                 : gettext("Group ID"),
        'homeDirectory'             : gettext("Home directory"),
        'loginShell'                : gettext("Login shell"),
        'entryUUID'                 : gettext("UUID"),
        'createTimestamp'           : gettext("Created"),
        'modifyTimestamp'           : gettext("Last modified"),
    }

def _profile_error_messages():
    return {
        'PROFILE_EDIT_NOT_ALLOWED'  : gettext("You are not allowed to change this."),
        'PROFILE_VALUE_TOO_LONG'    : gettext("A value is too long."),
        'PROFILE_TOO_MANY_VALUES'   : gettext("Too many values."),
        'PROFILE_INVALID_PHOTO'     : gettext("The photo must be a JPEG image."),
        'PROFILE_PHOTO_TOO_LARGE'   : gettext("The photo is too large."),
    }

@app.route('/profile')
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def profile():
    return render_template("profile.html", title=gettext('Profile'),
                           attribute_labels=_profile_attribute_labels())

@app.route('/profile/data', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def get_profile():
    """ The user's attributes and photo, and which of them may be
    changed. """
    try:
        response, error = _send_ssod_command(
                command="get_profile",
                default_error=gettext("Failed to load profile."))
    except Exception as e:
        logger.critical(f"get_profile failed: {e}")
        return jsonify({"error": gettext("Failed to load profile.")}), 500
    if error:
        return error
    attributes = {}
    order = []
    editable = []
    single_valued = []
    photo = None
    if isinstance(response, dict):
        attributes = response.get('attributes') or {}
        order = response.get('order') or []
        editable = response.get('editable') or []
        single_valued = response.get('single_valued') or []
        photo = response.get('photo')
    return jsonify({
            "attributes":       attributes,
            "order":            order,
            "editable":         editable,
            "single_valued":    single_valued,
            "photo":            photo,
        })

@app.route('/profile/attribute', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def set_profile_attribute():
    """ Replace the values of one attribute; an empty list removes it.
    A stale step-up comes back as step_up_required, see
    _send_ssod_command(). """
    data = request.json or {}
    attribute = data.get('attribute')
    values = data.get('values')
    if not isinstance(attribute, str) or not attribute:
        return jsonify({"error": gettext("Missing 'attribute' field.")}), 400
    if not isinstance(values, list):
        return jsonify({"error": gettext("Missing 'values' field.")}), 400
    response, error = _send_ssod_command(
            command="set_profile_attribute",
            extra_args={'attribute': attribute, 'values': values},
            default_error=gettext("Failed to save profile."),
            error_messages=_profile_error_messages(),
            mgmt=True)
    if error:
        return error
    stored = []
    if isinstance(response, dict):
        stored = response.get('values') or []
    return jsonify({
            "status":       "ok",
            "attribute":    attribute,
            "values":       stored,
        })

@app.route('/profile/photo', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def set_profile_photo():
    """ Set the photo (JPEG as base64) or, with an empty one, remove it.

    A photo of other dimensions than user_photo_dimensions comes back
    with resize_required instead of being stored; the page asks and
    sends it again with resize. """
    data = request.json or {}
    photo = data.get('photo')
    if photo is None:
        return jsonify({"error": gettext("Missing 'photo' field.")}), 400
    if not isinstance(photo, str):
        return jsonify({"error": gettext("The photo must be a JPEG image.")}), 400
    resize = bool(data.get('resize'))
    response, error = _send_ssod_command(
            command="set_profile_photo",
            extra_args={'photo': photo, 'resize': resize},
            default_error=gettext("Failed to save photo."),
            error_messages=_profile_error_messages(),
            mgmt=True)
    if error:
        return error
    if not isinstance(response, dict):
        response = {}
    if response.get('resize_required'):
        return jsonify({
                "status":           "resize_required",
                "resize_required":  True,
                "photo_dimensions": response.get('photo_dimensions'),
                "dimensions":       response.get('dimensions'),
            })
    return jsonify({
            "status":   "ok",
            "photo":    response.get('photo'),
        })

@app.route('/settings/sessions', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_sessions():
    try:
        response, error = _send_ssod_command(
                command="list_sessions",
                default_error=gettext("Failed to list sessions."))
    except Exception as e:
        logger.critical(f"list_sessions failed: {e}")
        return jsonify({"error": gettext("Failed to list sessions.")}), 500
    if error:
        return error
    sessions = []
    allowed = False
    if isinstance(response, dict):
        sessions = response.get('sessions', [])
        allowed = bool(response.get('allowed'))
    return jsonify({"sessions": sessions, "allowed": allowed})


@app.route('/settings/sessions/delete', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def delete_session():
    data = request.json or {}
    target_session = (data.get('session_uuid') or '').strip()
    if not target_session:
        return jsonify({"error": gettext("session_uuid is required.")}), 400
    response, error = _send_ssod_command(
            command="delete_session",
            extra_args={'target_session': target_session},
            default_error=gettext("Failed to end session."),
            mgmt=True)
    if error:
        return error
    return jsonify({"status": "ok",
                    "message": gettext("Session ended.")})


@app.route('/settings/oidc_consents', methods=['GET'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def list_oidc_consents():
    try:
        response, error = _send_ssod_command(
                command="list_oidc_consents",
                default_error=gettext("Failed to list OIDC consents."))
    except Exception as e:
        logger.critical(f"list_oidc_consents failed: {e}")
        return jsonify({"error": gettext("Failed to list OIDC consents.")}), 500
    if error:
        return error
    consents = []
    if isinstance(response, dict):
        consents = response.get('consents', [])
    return jsonify({"consents": consents})


@app.route('/settings/oidc_consents/revoke', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def revoke_oidc_consent():
    data = request.json or {}
    client_uuid = (data.get('client_uuid') or '').strip()
    if not client_uuid:
        return jsonify({"error": gettext("client_uuid is required.")}), 400
    response, error = _send_ssod_command(
            command="revoke_oidc_consent",
            extra_args={'client_uuid': client_uuid},
            default_error=gettext("Failed to revoke consent."),
            mgmt=True)
    if error:
        return error
    killed = 0
    if isinstance(response, dict):
        killed = int(response.get('sessions_killed') or 0)
    msg = "Consent revoked."
    if killed:
        msg = f"Consent revoked; terminated {killed} active session(s)."
    return jsonify({"status": "ok", "message": msg,
                    "sessions_killed": killed})


@app.route('/settings/redeploy')
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def settings_redeploy():
    """ Trigger re-deploy of the login token via the normal deploy flow. """
    flask_session['sso_deploy'] = True
    flask_session['sso_deploy_optional'] = True
    return redirect(url_for('deploy', _external=True, _scheme='https'))

@app.route('/change_password', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def change_password():
    data = request.json
    if not data:
        return jsonify({"error": gettext("Missing data")}), 400
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": gettext("All fields are required.")}), 400
    if new_password != confirm_password:
        return jsonify({"error": gettext("New passwords do not match.")}), 400
    login_token_pass_type = flask_session.get("login_token_pass_type")
    if login_token_pass_type != "static":
        return jsonify({"error": gettext("Token does not support password change.")}), 400
    # Send request to authd.
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'current_password'  : current_password,
                    'new_password'      : new_password,
                }
    ssod_conn = get_ssod_conn(g.user.name, mgmt=True)
    try:
        status, \
        status_code, \
        response, \
        binary_data = ssod_conn.send(command="change_password",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to start password change: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to change password.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(response, "Password change failed.")
        return jsonify({"error": error_msg}), 400
    log_msg = _("Password changed for user '{user_name}' via SSO portal.", log=True)[1]
    log_msg = log_msg.format(user_name=g.user.name)
    logger.info(log_msg)
    return jsonify({"status": "ok", "message": "Password changed successfully."})

@app.route('/change_pin', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def change_pin():
    data = request.json
    if not data:
        return jsonify({"error": gettext("Missing data")}), 400
    current_pin = data.get('current_pin', '')
    new_pin = data.get('new_pin', '')
    confirm_pin = data.get('confirm_pin', '')
    if not current_pin or not new_pin or not confirm_pin:
        return jsonify({"error": gettext("All fields are required.")}), 400
    if new_pin != confirm_pin:
        return jsonify({"error": gettext("New PINs do not match.")}), 400
    login_token_pass_type = flask_session.get("login_token_pass_type")
    if login_token_pass_type != "otp":
        return jsonify({"error": gettext("Token does not support PIN change.")}), 400
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                    'current_pin'   : current_pin,
                    'new_pin'       : new_pin,
                }
    ssod_conn = get_ssod_conn(g.user.name, mgmt=True)
    try:
        status, \
        status_code, \
        response, \
        binary_data = ssod_conn.send(command="change_pin",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to start PIN change: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to change PIN.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(response, "PIN change failed.")
        return jsonify({"error": error_msg}), 400
    log_msg = _("PIN changed for user '{user_name}' via SSO portal.", log=True)[1]
    log_msg = log_msg.format(user_name=g.user.name)
    logger.info(log_msg)
    return jsonify({"status": "ok", "message": "PIN changed successfully."})

@app.route('/settings/language', methods=['POST'])
@login_required
@limiter.limit(_rate_limit_settings, key_func=_settings_user_key)
def change_language():
    """ Persist the user's language preference. Accepts the literal
    "default" to clear the pref (revert to Accept-Language). """
    data = request.json or {}
    language = data.get('language', '')
    if not language:
        return jsonify({"error": gettext("Missing language.")}), 400
    # Whitelist against locales we ship + the reset sentinel; the user
    # object will reject anything else server-side too, but a 400 here
    # is friendlier than a generic ssod error.
    from otpme.web.app import SUPPORTED_LOCALES
    if language != "default" and language not in SUPPORTED_LOCALES:
        return jsonify({"error": gettext("Unsupported language.")}), 400
    response, error = _send_ssod_command(command="change_language",
            extra_args={'language': language},
            default_error=gettext("Failed to change language."),
            mgmt=True)
    if error is not None:
        return error
    # ssod echoes back the effective stored language (None when reset).
    effective = (response or {}).get('language') if isinstance(response, dict) else None
    _stash_user_language(effective)
    return jsonify({"status": "ok"})

# ---- SSO Token Deploy (enrollment) ----

@app.route('/deploy')
@login_required
def deploy():
    sso_deploy = flask_session.get('sso_deploy')
    if not sso_deploy:
        return redirect(url_for('index', _external=True, _scheme='https'))
    # Asked for a fixed token type too: the answer also says whether
    # the user has to prove themselves first (deploy_login_token_reauth),
    # and that has to happen before the choice is shown. Asking only
    # when a button is pressed sent the user to /reauth and back to the
    # very choice they had just made.
    response, _err = _send_ssod_command(
            command="get_allowed_deploy_token_types",
            default_error=None, mgmt=True)
    # sso_allow_login_token_redeploy is off. Never for a forced deploy,
    # ssod only says so for a voluntary one.
    if isinstance(response, dict) and response.get('redeploy_refused'):
        flask_session.pop('sso_deploy', None)
        flask_session.pop('sso_deploy_optional', None)
        flash(gettext("Re-deploying your login token is not allowed."))
        return redirect(url_for('settings', _external=True, _scheme='https'))
    if isinstance(response, dict) and response.get('step_up_required'):
        return redirect(url_for('reauth',
                                next=url_for('deploy'),
                                _external=True, _scheme='https'))
    # Determine allowed token types.
    if isinstance(sso_deploy, str) and sso_deploy is not True:
        deploy_token_types = [sso_deploy]
    else:
        deploy_token_types = ["totp", "fido2", "tiqr"]
        # Filter by per-user/unit/site config (sso_allow_totp_deploy,
        # sso_allow_fido2_deploy, sso_allow_tiqr_deploy). Best-effort:
        # if the query fails, fall back to the full list — deploy_begin
        # enforces the same gate authoritatively, so the worst case is
        # a button that errors out. tiqr defaults to off, so it only
        # shows up where an admin turned it on.
        if isinstance(response, dict):
            ssod_types = response.get('token_types')
            if isinstance(ssod_types, list):
                deploy_token_types = [tt for tt in deploy_token_types
                                      if tt in ssod_types]
    deploy_optional = bool(flask_session.get('sso_deploy_optional'))
    return render_template("deploy.html",
                           title=gettext('Token Enrollment'),
                           deploy_token_types=deploy_token_types,
                           deploy_optional=deploy_optional)

@app.route('/deploy/begin', methods=['POST'])
@login_required
def deploy_begin():
    sso_deploy = flask_session.get('sso_deploy')
    if not sso_deploy:
        return jsonify({"error": gettext("Deployment not required")}), 400
    # Get token type from request (user choice) or sso_deploy setting.
    data = request.json or {}
    if isinstance(sso_deploy, str) and sso_deploy is not True:
        # Fixed token type - ignore user choice.
        token_type = sso_deploy
    else:
        # User can choose.
        token_type = data.get('token_type', 'totp')
        if token_type not in ('totp', 'fido2', 'tiqr'):
            return jsonify({"error": gettext("Invalid token type.")}), 400
    # Send request to authd.
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'token_type'        : token_type,
                    # deploy_login_token_reauth is checked against this
                    # session's reauth_time, so ssod needs to know which
                    # session is asking.
                    'session_uuid'      : request.cookies.get('otpme_sso_session'),
                }
    if token_type in ("tiqr", "fido2", "totp"):
        # For tiqr it also becomes the enrollment's token name; for
        # all of them it is the name the token keeps when the SSO role
        # is handed to another one. ssod refuses without it.
        verify_args['device_name'] = (data.get('device_name') or '').strip()
    ssod_conn = get_ssod_conn(g.user.name, mgmt=True)
    try:
        status, \
        status_code, \
        deploy_data, \
        binary_data = ssod_conn.send(command="deploy_begin",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to start token deploy: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to start token deploy.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        # deploy_login_token_reauth: the session has no fresh reauth, so
        # send the user through /reauth and back here. Same signal the
        # settings page gets from _send_ssod_command().
        if isinstance(deploy_data, dict) \
        and deploy_data.get('message') == 'STEP_UP_REQUIRED':
            return jsonify({
                    "error": gettext("Please re-authenticate to continue."),
                    "step_up_required": True,
                }), 401
        error_msg = _ssod_error_message(deploy_data, "Failed to start token deploy.")
        return jsonify({"error": error_msg}), 400
    # Store info in session for verification step.
    token_type = deploy_data['token_type']
    try:
        pin = deploy_data['pin']
    except KeyError:
        pin = ""
    try:
        secret = deploy_data['secret']
    except KeyError:
        secret = ""
    try:
        qrcode_img = deploy_data['qrcode_img']
    except KeyError:
        qrcode_img = ""
    flask_session['deploy_token_name'] = deploy_data['deploy_token_name']
    flask_session['deploy_login_token_name'] = deploy_data['deploy_login_token_name']
    flask_session['deploy_token_type'] = token_type
    # Build response.
    response_data = {
        "status": "ok",
        "pin": pin,
        "secret": secret,
        "token_type": token_type,
        "qrcode_img": qrcode_img,
    }
    log_msg = f"SSO deploy started for user '{g.user.name}', token type '{token_type}'."
    logger.info(log_msg)
    return jsonify(response_data)

@app.route('/deploy/verify', methods=['POST'])
@login_required
def deploy_verify():
    token_data = request.json or {}
    deploy_name = flask_session.get('deploy_token_name')
    login_token_name = flask_session.get('deploy_login_token_name')
    if not deploy_name or not login_token_name:
        return jsonify({"error": gettext("No deployment in progress.")}), 400
    # Send request to authd.
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'token_data'        : token_data,
                    'login_token_name'  : login_token_name,
                }
    ssod_conn = get_ssod_conn(g.user.name, mgmt=True)
    try:
        status, \
        status_code, \
        verify_data, \
        binary_data = ssod_conn.send(command="deploy_verify",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to verify token deploy: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to verify token deploy.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(verify_data, "Failed to verify token deploy.")
        return jsonify({"error": error_msg}), 400
    # Update login token pass_type to match the newly deployed token so the
    # settings page reflects the correct token (password vs PIN change).
    deploy_token_type = flask_session.get('deploy_token_type')
    pass_type_map = {
                    'totp'  : 'otp',
                    'hotp'  : 'otp',
                    'fido2' : 'smartcard',
                }
    new_pass_type = pass_type_map.get(deploy_token_type)
    if new_pass_type:
        flask_session['login_token_pass_type'] = new_pass_type
    # Clean up session.
    flask_session.pop('sso_deploy', None)
    flask_session.pop('sso_deploy_optional', None)
    flask_session.pop('deploy_token_name', None)
    flask_session.pop('deploy_login_token_name', None)
    flask_session.pop('deploy_token_type', None)
    log_msg = f"SSO deploy completed for user '{g.user.name}', token '{login_token_name}'."
    logger.info(log_msg)
    return jsonify({
        "status": "ok",
        "message": "Token deployed successfully.",
        "redirect": url_for('index', _external=True, _scheme='https'),
    })

def _site_rate_limit(name):
    """ Read a site-level Flask-Limiter rate-limit string. Falls back
    to None on lookup failure so the @limiter.limit decorator can plug
    in a hardcoded default. backend.get_object is cached so the
    per-request cost stays small. """
    try:
        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if site is not None:
            return site.get_config_parameter(name)
    except Exception as e:
        log_msg = _("Rate-limit lookup for {name} failed: {error}", log=True)[1]
        log_msg = log_msg.format(name=name, error=e)
        logger.warning(log_msg)
    return None


def _show_recover_link():
    """ Site-level UI toggle for the SSO-token recovery entry point.
    Anonymous check -- the login page and the /recover route don't
    know the user yet, so the visibility gate is site-only. Per-user
    cascade (``allow_sso_account_recovery``) still runs ssod-side
    once the target user is resolved. """
    try:
        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if site is not None:
            return bool(site.get_config_parameter("sso_show_recover_link"))
    except Exception as e:
        log_msg = _("sso_show_recover_link lookup failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.warning(log_msg)
    return False


def _show_login_button(parameter):
    """ Site-level UI toggle for one of the login mask's buttons.

    Anonymous, like _show_recover_link: the mask is rendered before
    anybody has typed a name, so there is no user whose cascade could
    be resolved -- and resolving one would mean answering questions
    about a name before it has been authenticated.

    Whether the method may be used at all is a different question, and
    a different parameter (sso_allow_fido2 / sso_allow_tiqr), decided
    ssod-side once the user is known. Defaults to showing the button:
    an unreadable site object should not silently remove a way in.
    """
    try:
        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        if site is not None:
            return bool(site.get_config_parameter(parameter))
    except Exception as e:
        log_msg = _("{parameter} lookup failed: {error}", log=True)[1]
        log_msg = log_msg.format(parameter=parameter, error=e)
        logger.warning(log_msg)
    return True


def _rate_limit_login():
    return _site_rate_limit("sso_rate_limit_login") or "100/minute"


def _rate_limit_login_user():
    return _site_rate_limit("sso_rate_limit_login_user") or "10/minute"


def _login_username_key():
    """ Rate-limit key for /login POST: the submitted username, so NAT
    pools (corporate / mobile carrier) don't share a bucket. Falls
    back to remote IP for GET requests or when no username given. """
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip().lower()
        if username:
            return f"login-user:{username}"
    from otpme.web.app import _ratelimit_key
    return _ratelimit_key()


def _tiqr_begin_username_key():
    """ Rate-limit key for /login/tiqr/begin: username from JSON body. """
    try:
        data = request.get_json(silent=True) or {}
    except Exception as e:
        log_msg = _("Rate-limit key: get_json failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.debug(log_msg)
        data = {}
    username = (data.get('username') or '').strip().lower()
    if username:
        return f"tiqr-user:{username}"
    from otpme.web.app import _ratelimit_key
    return _ratelimit_key()


def _tiqr_otp_username_key():
    """ Rate-limit key for /login/tiqr/otp.

    The username is not in the body here -- it comes from the session
    the begin call put it in -- but the six digit response is guessable
    at 1 in 10^6, and tiqr's own SECURITY.md puts the burden of
    limiting guesses on the server. So the limit follows the user
    whose login is in progress. """
    username = (flask_session.get('tiqr_username') or '').strip().lower()
    if username:
        return f"tiqr-user:{username}"
    from otpme.web.app import _ratelimit_key
    return _ratelimit_key()


def _fido2_auth_username_key():
    """ Rate-limit key for /fido2/auth/begin: username from JSON body. """
    try:
        data = request.get_json(silent=True) or {}
    except Exception as e:
        log_msg = _("Rate-limit key: get_json failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.debug(log_msg)
        data = {}
    username = (data.get('username') or '').strip().lower()
    if username:
        return f"fido2-user:{username}"
    from otpme.web.app import _ratelimit_key
    return _ratelimit_key()


def no_store(response):
    """ Mark a response as non-cacheable for endpoints that carry
    one-shot tokens or credentials (SOTP, OIDC token-bearing
    endpoints). Browsers and proxies otherwise might keep the response
    in cache and serve it again later.

    Spec: RFC 6749 §5.1 "Successful Response"
      (Cache-Control: no-store, Pragma: no-cache MUST be set)
      https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    Spec: OIDC Core 1.0 §3.1.3.3 "Successful Token Response"
      https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    """
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


def _safe_next_url(next_url):
    """ Validate a ``next=`` redirect target. Returns the input
    unchanged if it resolves to a same-origin http(s) URL after
    urljoin-normalization, else None.
    """
    if not next_url:
        return None
    # ASCII control chars + DEL are stripped by some browsers BEFORE
    # URL parsing, so "\t//evil.com" could pass urljoin (which sees the
    # control char and keeps a plausible-looking path) but the browser
    # would later normalize the Location: response into a scheme-
    # relative redirect. Reject anything containing them.
    for ch in next_url:
        if ch <= '\x20' or ch == '\x7f':
            return None
    # urljoin normalizes the input against our own origin and then
    # urlparse exposes the resolved scheme/netloc:
    #   "/foo"           -> https://host/foo                 (relative)
    #   "//evil.com/x"   -> https://evil.com/x               (scheme-relative)
    #   "https://evil/x" -> https://evil/x                   (absolute)
    #   "javascript:..." -> "javascript:..."                 (no scheme/host)
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, next_url))
    if test.scheme not in ('http', 'https'):
        return None
    if test.netloc != ref.netloc:
        return None
    return next_url


@app.route('/login', methods=['GET', 'POST'])
# Two stacked limits: per-username keeps single-account brute force in
# check even from large NAT pools; per-IP is a coarser DoS guard
# against username-rotation attacks. Both must pass. The actual values
# are read from the site config (sso_rate_limit_login_user /
# sso_rate_limit_login) at request time -- admins can tune them via
# the management commands.
@limiter.limit(_rate_limit_login_user, key_func=_login_username_key,
               methods=['POST'])
@limiter.limit(_rate_limit_login, methods=['POST'])
def login():
    # Stash the optional ``next=`` target in the flask session so it
    # survives the form-submission roundtrip (the POST won't carry
    # the original GET query string).
    next_url = _safe_next_url(request.args.get('next'))
    if next_url:
        flask_session['next_after_login'] = next_url

    # Step-up reauth targets /login POST too (the reauth form action
    # submits here), but the user is still authenticated at that point.
    # Skip the already-logged-in early-return so the reauth branch
    # below can consume reauth_mode + verify the credential.
    reauth_mode_pending = bool(flask_session.get('reauth_mode'))
    if not reauth_mode_pending and g.user and g.user.is_authenticated:
        # Already logged in -- honor next= if it's there, else /index.
        target = (_safe_next_url(flask_session.pop('next_after_login', None))
                  or url_for('index', _external=True, _scheme='https'))
        return redirect(target)
    form = LoginForm()
    if not form.validate_on_submit():
        # Prefill the username field from a previous failed attempt
        # (set by the auth-failure redirect path below). pop() so a
        # later unrelated visit doesn't resurface it.
        prev_username = flask_session.pop('login_prev_username', '')
        if prev_username and not form.username.data:
            form.username.data = prev_username
        return render_template('login.html',
                               title=gettext('Sign In'),
                               form=form,
                               show_fido2_button=_show_login_button("sso_show_fido2_button"),
                               show_tiqr_button=_show_login_button("sso_show_tiqr_button"),
                               show_recover_link=_show_recover_link())
    # Get client IP.
    client_ip = check_forwarded_for()[0]
    # Get username/password.
    username = request.form['username']
    password = request.form['password']
    # Step-up reauth marker set by /reauth GET. In reauth mode we verify
    # the credential against the existing SSO session (bump reauth_time
    # via authd's reauth branch) instead of creating a new session --
    # keeps cookies, JWT, peer-RP sessions intact. Only honour the flag
    # when the user is actually authenticated at POST time; a stale flag
    # from a prior aborted reauth (session gone, cookie expired) would
    # otherwise break a fresh login by sending reauth=True with no valid
    # session_uuid.
    reauth_mode = bool(flask_session.pop('reauth_mode', False))
    reauth_next = _safe_next_url(flask_session.pop('reauth_next', None))
    if reauth_mode and not (g.user and g.user.is_authenticated):
        reauth_mode = False
        reauth_next = None
    # In reauth mode the form's username field is readonly and prefilled;
    # trust the flask_session copy so a client can't sneak a different
    # username into the reauth submission.
    if reauth_mode:
        username = flask_session.get('otpme_username') or username
    # Get JWT from authd.
    sso_challenge = stuff.gen_secret(len=32)
    verify_args = {
                    'username'          : username,
                    'password'          : password,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'sso_challenge'     : sso_challenge,
                }
    if reauth_mode:
        verify_args['reauth'] = True
        verify_args['session_uuid'] = request.cookies.get('otpme_sso_session')
        log_msg = _("/login POST reauth: user={u} session_uuid_set={s}", log=True)[1]
        log_msg = log_msg.format(u=username, s=bool(verify_args['session_uuid']))
        logger.info(log_msg)

    # Get authd connection. Inside the try: on an SSO host connecting
    # does the preauth check, which fails for an unknown or disabled user.
    authd_conn = None
    try:
        authd_conn = get_authd_conn(username, password)
        auth_status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="verify",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to authenticate user: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        if reauth_mode:
            flask_session['reauth_mode'] = True
            if reauth_next:
                flask_session['reauth_next'] = reauth_next
            return redirect(url_for('reauth', _external=True, _scheme='https'))
        # Stash the typed-in username so the login form prefills it
        # after the redirect-after-POST roundtrip -- the form object
        # is discarded here, but the user shouldn't have to retype.
        flask_session['login_prev_username'] = username
        return redirect(url_for('login', _external=True, _scheme='https'))
    finally:
        if authd_conn is not None:
            authd_conn.close()
    if not auth_status:
        flash(gettext("Login failed."))
        if reauth_mode:
            flask_session['reauth_mode'] = True
            if reauth_next:
                flask_session['reauth_next'] = reauth_next
            return redirect(url_for('reauth', _external=True, _scheme='https'))
        flask_session['login_prev_username'] = username
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Reauth succeeded -- no new session was created; just redirect back
    # to whatever triggered the step-up (Settings recovery-mail card,
    # OIDC /authorize after prompt=login, etc.).
    if reauth_mode:
        target = (reauth_next
                  or url_for('index', _external=True, _scheme='https'))
        return redirect(target)
    try:
        login_token_pass_type = auth_response['login_token_pass_type']
        login_token_type = auth_response['login_token_type']
        login_token_deploy = auth_response['login_token_sso_deploy']
        session_uuid = auth_response['session']
        login_user_uuid = auth_response['login_user_uuid']
        login_user_site_uuid = auth_response['login_user_site_uuid']
        sso_jwt = auth_response['sso_jwt']
        slp = auth_response['slp']
    except KeyError as e:
        log_msg = _("Invalid auth response: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Get users site public key to verify the JWT.
    user_site = backend.get_object(object_type="site",
                                uuid=login_user_site_uuid)
    # Not synced to this host (yet): nothing to verify the JWT with.
    if user_site is None:
        log_msg = _("Unknown site of login user: {site_uuid}", log=True)[1]
        log_msg = log_msg.format(site_uuid=login_user_site_uuid)
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    site_jwt_key = user_site._cert_public_key
    try:
        jwt.decode(jwt=sso_jwt, key=site_jwt_key, algorithm='RS256')
    except Exception as e:
        log_msg = _("JWT verification failed: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Check if token requires SSO deploy (enrollment).
    if login_token_deploy:
        # Forced enrollment beats the stashed next= -- complete deploy
        # first, deploy_verify can later look at flask_session.
        redirect_target = url_for('deploy', _external=True, _scheme='https')
    else:
        # Honor next= if it survived from the GET stash.
        next_url = _safe_next_url(flask_session.pop('next_after_login', None))
        if next_url:
            redirect_target = next_url
        else:
            redirect_target = url_for('index', _external=True, _scheme='https')
    # Store user data in Flask session for load_user.
    flask_session['otpme_username'] = username
    flask_session['sso_deploy'] = login_token_deploy
    flask_session['login_token_pass_type'] = login_token_pass_type
    flask_session['login_token_type'] = login_token_type
    _stash_user_language(auth_response.get('login_user_language'))
    web_user = WebUser(uuid=login_user_uuid, name=username)
    resp = make_response(redirect(redirect_target))
    resp.set_cookie('otpme_slp', slp,
                    httponly=True, secure=True, samesite='Lax')
    resp.set_cookie('otpme_jwt', sso_jwt,
                    httponly=True, secure=True, samesite='Lax')
    resp.set_cookie('otpme_user_uuid', login_user_uuid,
                    httponly=True, secure=True, samesite='Lax')
    resp.set_cookie('otpme_sso_session', session_uuid,
                    httponly=True, secure=True, samesite='Lax')
    login_user(web_user)
    _refresh_admin_access_state_post_login(username, sso_jwt, session_uuid)
    return resp

def _do_sso_logout(response, skip_backchannel_client=None,
                   skip_backchannel=False):
    """ Terminate the user's SSO session on authd and clear local state.

    ``skip_backchannel_client``: OIDC client UUID to skip when the
    SLP cascade fires back-channel logout notifications. Set by the
    /end_session flow so the initiating RP isn't notified about a
    logout it just triggered itself.

    ``skip_backchannel``: when True, suppress back-channel logout for
    ALL attached OIDC sessions. Used for hintless /end_session calls
    where we can't reliably identify an initiator -- killing the SSO
    session is correct, but unsolicited backchannel POSTs to every
    attached RP are unnecessary and trip OIDC conformance tests.
    """
    slp = request.cookies.get('otpme_slp')
    username = flask_session.get('otpme_username')
    response.set_cookie('otpme_slp', '', expires=0)
    response.set_cookie('otpme_jwt', '', expires=0)
    response.set_cookie('otpme_user_uuid', '', expires=0)
    response.set_cookie('otpme_sso_session', '', expires=0)
    # Drop the cached language pref so the next anonymous visit to
    # /login follows Accept-Language again instead of sticking to the
    # previous user's profile language.
    flask_session.pop('user_language', None)
    # Drop the cached admin-access flag so it doesn't survive into the
    # next login (a different user, or the same user after an external
    # toggle).
    flask_session.pop('admin_access_enabled', None)
    # Drop step-up reauth markers so a stale flag from an aborted /reauth
    # doesn't turn the next fresh /login POST into a session_uuid-less
    # reauth attempt (would trip the authd reauth branch's session_uuid
    # required guard and break the login).
    flask_session.pop('reauth_mode', None)
    flask_session.pop('reauth_next', None)
    # Drop the per-user /get_apps cache so a re-login (possibly with a
    # different token / different access-group membership) doesn't
    # briefly see the previous session's app tiles.
    _apps_cache_invalidate(username)
    if username:
        try:
            authd_conn = get_authd_conn(username, slp)
        except Exception as e:
            log_msg = _("Failed to logout user: {user_name}", log=True)[1]
            log_msg = log_msg.format(user_name=username)
            log_msg = f"{log_msg}: {e}"
            logger.warning(log_msg)
        else:
            client_ip = check_forwarded_for()[0]
            verify_args = {
                            'username'      : username,
                            'password'      : slp,
                            'client'        : config.sso_client_name,
                            'client_ip'     : client_ip,
                            'sso_logout'    : True,
                            'session_logout': True,
                            'realm_login'   : False,
                            'realm_logout'  : False,
                        }
            if skip_backchannel_client:
                verify_args['oidc_skip_backchannel_client'] = skip_backchannel_client
            if skip_backchannel:
                verify_args['oidc_skip_backchannel'] = True
            try:
                authd_conn.send(command="verify", command_args=verify_args)
            except Exception as e:
                log_msg = _("Failed to logout user: {user_name}", log=True)[1]
                log_msg = log_msg.format(user_name=username)
                log_msg = f"{log_msg}: {e}"
                logger.warning(log_msg)
            finally:
                try:
                    authd_conn.close()
                except Exception as e:
                    log_msg = _("Logout: authd_conn.close failed: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    logger.debug(log_msg)
    logout_user()
    return response

@app.route('/reauth', methods=['GET'])
@login_required
def reauth():
    """ Step-up re-authentication endpoint.

    Re-verifies the current user via FIDO2 without touching the
    existing SSO session: no new cookies, no peer-RP-session disruption.
    On success the SSO session's reauth_time is bumped so subsequent
    OIDC ID Tokens carry a fresh auth_time.

    Driven by OIDC ``prompt=login`` / ``max_age`` -- the /oidc/authorize
    handler redirects here with a ``next=<authorize-URL>`` (with
    ``prompt=login`` stripped) so the user lands back at /authorize
    once the step-up is done.
    """
    next_url = _safe_next_url(request.args.get('next'))
    if next_url:
        flask_session['reauth_next'] = next_url
    # Marker the /fido2/auth/complete handler reads to branch into the
    # step-up code path on the authd side.
    flask_session['reauth_mode'] = True
    username = flask_session.get('otpme_username') or ''
    log_msg = _("/reauth GET: user={u} next_stashed={n}", log=True)[1]
    log_msg = log_msg.format(u=username, n=bool(flask_session.get('reauth_next')))
    logger.info(log_msg)
    form = LoginForm()
    form.username.data = username
    return render_template('login.html',
                           title=gettext('Re-authenticate'),
                           form=form,
                           show_fido2_button=_show_login_button("sso_show_fido2_button"),
                           show_tiqr_button=_show_login_button("sso_show_tiqr_button"),
                           reauth=True,
                           reauth_username=username,
                           reauth_token_pass_type=flask_session.get('login_token_pass_type') or '',
                           reauth_token_type=flask_session.get('login_token_type') or '')

def _logout_origin_ok():
    # Logout is CSRF-exempt (see csrf.exempt(logout) below) so a stale
    # CSRF token on a long-open tab doesn't lock the user out. Cross-
    # origin CSRF defence for this endpoint is the Origin/Referer check
    # instead: browsers set one of them on every POST and neither can
    # be spoofed from an attacker's page (OWASP CSRF prevention cheat
    # sheet, "Verifying Origin With Standard Headers"). A missing
    # Origin/Referer is rejected -- same-origin form posts always carry
    # at least one.
    expected_host = request.host
    origin = request.headers.get('Origin')
    if origin:
        try:
            return urlparse(origin).netloc == expected_host
        except Exception:
            return False
    referer = request.headers.get('Referer')
    if referer:
        try:
            return urlparse(referer).netloc == expected_host
        except Exception:
            return False
    return False

@app.route('/logout', methods=['POST'])
def logout():
    # POST-only: a GET /logout (e.g. via <img src> on a third-party
    # site) would log the user out without their consent. The navbar
    # template renders Logout as a POST form; the endpoint is CSRF-
    # exempt because Flask-WTF's synchronizer token expires after
    # WTF_CSRF_TIME_LIMIT (default 1h) and a user who leaves the tab
    # open past that gets "The CSRF token has expired" when they click
    # Logout. We defend against cross-origin logout-CSRF via the
    # Origin/Referer header check in _logout_origin_ok() instead.
    if not _logout_origin_ok():
        return "Bad request", 400
    next_url = _safe_next_url(request.form.get('next'))
    if not g.user:
        return redirect(url_for('login', next=next_url, _external=True, _scheme='https'))
    resp = make_response(redirect(url_for('login', next=next_url, _external=True, _scheme='https')))
    return _do_sso_logout(resp)

csrf.exempt(logout)


def _send_ssod_command_unauth(command, extra_args, default_error=None,
                              mgmt=False):
    """ Unauth companion to ``_send_ssod_command`` for endpoints
    with no active SSO session (SSO-token recovery flow). Skips
    JWT / session_uuid / g.user handling; the server-side handler
    validates the raw recovery token itself. ``extra_args`` MUST
    include ``username`` -- it is required at the ssod dispatch
    layer and is also used for the ssod connection context. """
    args = dict(extra_args or {})
    username = args.get('username') or ''
    ssod_conn = get_ssod_conn(username or 'recover', mgmt=mgmt)
    try:
        status, \
        status_code, \
        response, \
        binary_data = ssod_conn.send(command=command, command_args=args)
    except Exception as e:
        log_msg = _("ssod unauth command '{command}' failed: {e}", log=True)[1]
        log_msg = log_msg.format(command=command, e=e)
        logger.critical(log_msg)
        return None, (jsonify({"error": default_error}), 500)
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(response, default_error)
        return None, (jsonify({"error": error_msg}), 400)
    return response, None


# ---- SSO-token recovery (unauth "forgot my token" flow) ---------------
#
# /recover              GET  -> username form
#                       POST -> ssod request_sso_token_recovery, always
#                                renders the generic 'if account exists,
#                                mail is on the way' page (enum-safe)
# /recover/complete     GET  -> validate ?t=&u= via get_sso_token_recovery_info,
#                                render the deploy form for the sso-token
# /recover/complete/begin           POST -> recovery_deploy_begin
# /recover/complete/fido2/begin     POST -> recovery_fido2_register_begin
# /recover/complete/fido2/complete  POST -> recovery_fido2_register_complete
# /recover/complete/verify          POST -> recovery_deploy_verify

def _recover_rate_limit():
    return _site_rate_limit("sso_rate_limit_recover") or "20/minute"


def _recover_username_key():
    """ Prefer keying rate limits on the submitted username so a
    single account cannot be spammed with recovery mails from a
    shared IP pool. Falls back to remote IP when no username was
    submitted (GET requests, malformed POSTs). """
    if request.method == 'POST':
        try:
            data = request.get_json(silent=True) or {}
        except Exception:
            data = {}
        username = (data.get('username') or '').strip().lower()
        if username:
            return f"recover-user:{username}"
    from otpme.web.app import _ratelimit_key
    return _ratelimit_key()


@app.route('/recover', methods=['GET'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover():
    """ Username form for the SSO-token recovery flow. """
    if not _show_recover_link():
        return redirect(url_for('login', _external=True, _scheme='https'))
    return render_template('recover.html',
                           title=gettext('Recover Your Account'))


@app.route('/recover', methods=['POST'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover_request():
    """ Fire off a recovery request via ssod. Response shape is
    identical for every input (unknown user, no recovery mail,
    disallowed token type, SMTP failure) so the client cannot
    enumerate accounts or infer recovery state. """
    if not _show_recover_link():
        return jsonify({"status": "ok"})
    data = request.json or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"status": "ok"})
    response, error = _send_ssod_command_unauth(
            command="request_sso_token_recovery",
            extra_args={'username': username},
            default_error=gettext("Recovery request failed."))
    if error:
        # ssod returns generic-OK for all logic-level failures, so an
        # error here is a real infrastructure fault (cluster down,
        # etc.). Surface it so the user knows to retry -- but do NOT
        # leak whether the account exists.
        return error
    return jsonify({"status": "ok"})


@app.route('/recover/complete', methods=['GET'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover_complete():
    """ Validate the recovery-mail link and render the deploy form.
    Both parameters (?t=raw_token, ?u=username) come from the mail
    body; server re-verifies via ssod (hash + TTL) before rendering
    the form so an expired/bogus link lands on a plain 'invalid or
    expired' page instead of the deploy UI. """
    if not _show_recover_link():
        return redirect(url_for('login', _external=True, _scheme='https'))
    raw_token = (request.args.get('t') or '').strip()
    username = (request.args.get('u') or '').strip()
    if not raw_token or not username:
        return render_template('recover_invalid.html',
                               title=gettext('Recovery link invalid'))
    response, error = _send_ssod_command_unauth(
            command="get_sso_token_recovery_info",
            extra_args={'username':       username,
                        'recovery_token': raw_token},
            default_error=gettext("Recovery link invalid or expired."))
    if error or not isinstance(response, dict) or not response.get('valid'):
        return render_template('recover_invalid.html',
                               title=gettext('Recovery link invalid'))
    return render_template('recover_complete.html',
                           title=gettext('Recover Your Account'),
                           recovery_username=username,
                           recovery_token=raw_token,
                           sso_token_name=response.get('sso_token_name') or '',
                           sso_token_type=response.get('sso_token_type') or '',
                           deploy_token_types=response.get('allowed_deploy_types') or [])


@app.route('/recover/complete/begin', methods=['POST'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover_complete_begin():
    """ Proxy for recovery_deploy_begin. The server enforces that
    token_type matches the user's actual SSO token type -- we just
    forward whatever the client sent. """
    if not _show_recover_link():
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    data = request.json or {}
    username = (data.get('username') or '').strip()
    raw_token = (data.get('recovery_token') or '').strip()
    token_type = (data.get('token_type') or '').strip()
    if not username or not raw_token or not token_type:
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    extra_args = {'username':       username,
                'recovery_token': raw_token,
                'token_type':     token_type}
    # tiqr, fido2 and totp use it; the server rejects those without one.
    device_name = (data.get('device_name') or '').strip()
    if device_name:
        extra_args['device_name'] = device_name
    response, error = _send_ssod_command_unauth(
            command="recovery_deploy_begin",
            extra_args=extra_args,
            default_error=gettext("Recovery deployment failed."),
            mgmt=True)
    if error:
        return error
    return jsonify(response or {})


@app.route('/recover/complete/fido2/begin', methods=['POST'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover_complete_fido2_begin():
    if not _show_recover_link():
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    data = request.json or {}
    username = (data.get('username') or '').strip()
    raw_token = (data.get('recovery_token') or '').strip()
    if not username or not raw_token:
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    response, error = _send_ssod_command_unauth(
            command="recovery_fido2_register_begin",
            extra_args={'username':       username,
                        'recovery_token': raw_token,
                        'rp_id':          _get_fido2_rp_id()},
            default_error=gettext("Security key registration failed."),
            mgmt=True)
    if error:
        return error
    return jsonify(response or {})


@app.route('/recover/complete/fido2/complete', methods=['POST'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover_complete_fido2_complete():
    if not _show_recover_link():
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    data = request.json or {}
    username = (data.get('username') or '').strip()
    raw_token = (data.get('recovery_token') or '').strip()
    fido2_state_id = data.get('fido2_state_id')
    registration_data = data.get('registration_data')
    if not username or not raw_token or not fido2_state_id or not registration_data:
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    response, error = _send_ssod_command_unauth(
            command="recovery_fido2_register_complete",
            extra_args={'username':          username,
                        'recovery_token':    raw_token,
                        'rp_id':             _get_fido2_rp_id(),
                        'fido2_state_id':    fido2_state_id,
                        'registration_data': registration_data},
            default_error=gettext("Security key registration failed."),
            mgmt=True)
    if error:
        return error
    return jsonify(response or {})


@app.route('/recover/complete/verify', methods=['POST'])
@limiter.limit(_recover_rate_limit, key_func=_recover_username_key)
def recover_complete_verify():
    """ Proxy for recovery_deploy_verify. Server clears the recovery
    token slot on success. Client redirects to /login. """
    if not _show_recover_link():
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    data = request.json or {}
    username = (data.get('username') or '').strip()
    raw_token = (data.get('recovery_token') or '').strip()
    token_data = data.get('token_data') or {}
    if not username or not raw_token:
        return jsonify({"error": gettext("Recovery link invalid.")}), 400
    response, error = _send_ssod_command_unauth(
            command="recovery_deploy_verify",
            extra_args={'username':       username,
                        'recovery_token': raw_token,
                        'token_data':     token_data},
            default_error=gettext("Recovery deployment failed."),
            mgmt=True)
    if error:
        return error
    login_url = url_for('login', _external=True, _scheme='https')
    return jsonify({
                "status":   "ok",
                "message":  gettext("Done. Please sign in with your new credentials."),
                "redirect": login_url,
            })


# Short-lived per-worker cache for the /get_apps result. The portal
# hits this endpoint on every reload of the SSO landing page; without
# a cache each hit fans out to ssod (+ backend reads for every SSO-
# enabled client on the site). A 30s TTL is short enough that a
# freshly toggled access-group maintenance flag or a newly added
# client shows up quickly, and long enough to absorb quick reloads.
#
# Scope: per gunicorn worker process. Deliberately not shared across
# workers -- a Redis / multiprocessing.shared cache would be overkill
# for a 30s TTL on a low-cardinality endpoint, and the worst case
# (N workers -> N misses per user per TTL window) is fine.
_APPS_CACHE = {}
_APPS_CACHE_LOCK = threading.Lock()
_APPS_CACHE_TTL = 30  # seconds
_APPS_CACHE_MAX = 1024  # prune threshold

def _apps_cache_get(username):
    """ Return cached app_data for ``username`` or ``None`` when
    no entry exists or the entry has expired. """
    with _APPS_CACHE_LOCK:
        entry = _APPS_CACHE.get(username)
        if not entry:
            return None
        expires_at, data = entry
        if expires_at < time.monotonic():
            _APPS_CACHE.pop(username, None)
            return None
        return data

def _apps_cache_set(username, data):
    """ Store ``data`` under ``username`` with the module's TTL.
    Opportunistically prunes expired entries when the dict grows
    past ``_APPS_CACHE_MAX`` so idle workers don't accumulate
    unbounded state for logged-out users. """
    with _APPS_CACHE_LOCK:
        _APPS_CACHE[username] = (time.monotonic() + _APPS_CACHE_TTL, data)
        if len(_APPS_CACHE) > _APPS_CACHE_MAX:
            now = time.monotonic()
            for k, (exp, _) in list(_APPS_CACHE.items()):
                if exp < now:
                    _APPS_CACHE.pop(k, None)

def _apps_cache_invalidate(username):
    """ Drop ``username``'s cached entry. Called on logout so the
    next login sees fresh data instead of the previous session's
    tail-end cache. """
    if not username:
        return
    with _APPS_CACHE_LOCK:
        _APPS_CACHE.pop(username, None)

@app.route('/get_apps')
@login_required
def get_apps():
    username = g.user.name
    cached = _apps_cache_get(username)
    if cached is not None:
        return jsonify(cached)
    response, error = _send_ssod_command(command="get_apps",
                        default_error=gettext("Failed to get app list."))
    if error:
        return error
    app_data = []
    if isinstance(response, dict):
        app_data = response.get('app_data', [])
    _apps_cache_set(username, app_data)
    return jsonify(app_data)

@app.route('/get_sotp', methods=['POST'])
@login_required
def get_sotp():
    # POST + JSON body (was GET + ?access_group=...): keeps the
    # access-group name out of access logs / browser history / Referer
    # headers. Response is no_store()'d so the one-shot SOTP can't be
    # served from cache later.
    sotp_data = None
    data = request.json or {}
    access_group = data.get('access_group')
    if not access_group:
        return no_store(jsonify(sotp_data))
    sso_jwt = request.cookies.get('otpme_jwt')
    session_uuid = request.cookies.get('otpme_sso_session')
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                    'access_group'  : access_group,
                    'session_uuid'  : session_uuid,
                }

    ssod_conn = get_ssod_conn(g.user.name)
    try:
        status, \
        status_code, \
        sotp_data, \
        binary_data = ssod_conn.send(command="get_sotp",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to get SOTP: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return no_store(make_response(
                jsonify({"error": gettext("Failed to get SOTP.")}), 500))
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(sotp_data, "Failed to get SOTP.")
        # Invalid/expired JWT: force logout so the user re-authenticates.
        do_logout = False
        if isinstance(sotp_data, dict) and sotp_data.get('message') == 'JWT_INVALID':
            do_logout = True
        if isinstance(sotp_data, dict) and sotp_data.get('message') == 'UNKNOWN_SESSION':
            do_logout = True
        if do_logout:
            log_msg = _("SSO JWT invalid for user '{user_name}', logging out.", log=True)[1]
            log_msg = log_msg.format(user_name=g.user.name)
            logger.warning(log_msg)
            resp = make_response(jsonify({
                    "error": gettext("Session expired. Please log in again."),
                    "redirect": url_for('login', _external=True, _scheme='https'),
                }), 401)
            return no_store(_do_sso_logout(resp))
        return no_store(make_response(
                jsonify({"error": error_msg}), 400))
    return no_store(jsonify(sotp_data))

# ---- FIDO2 Registration (logged-in user registers a security key) ----

@app.route('/fido2/register/begin', methods=['POST'])
@login_required
def fido2_register_begin():
    rp_id = _get_fido2_rp_id()
    sso_jwt = request.cookies.get('otpme_jwt')
    is_deploy = flask_session.get('deploy_token_name') is not None
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                    'rp_id'         : rp_id,
                    'is_deploy'     : is_deploy,
                }
    ssod_conn = get_ssod_conn(g.user.name, mgmt=True)
    try:
        status, \
        status_code, \
        fido2_reg_data, \
        binary_data = ssod_conn.send(command="fido2_register_begin",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to start fido2 registration: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to start fido2 registration.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(fido2_reg_data, "Failed to start fido2 registration.")
        return jsonify({"error": error_msg}), 400
    create_options = fido2_reg_data['create_options']
    # State lives on the ssod-side master node in
    # multiprocessing.fido2_reg_states keyed by an opaque state-id.
    # Registration always routes through the master (mgmt=True; no
    # multi-master in OTPme), so the Flask session only carries the
    # state-id -- no WebAuthn challenge / token-uuid leak via cookie.
    flask_session['fido2_state_id'] = fido2_reg_data['fido2_state_id']
    return json.dumps(create_options), 200, {'Content-Type': 'application/json'}

@app.route('/fido2/register/complete', methods=['POST'])
@login_required
def fido2_register_complete():
    fido2_state_id = flask_session.pop('fido2_state_id', None)
    if not fido2_state_id:
        return jsonify({"error": gettext("No registration in progress")}), 400
    registration_data = request.json
    if not registration_data:
        return jsonify({"error": gettext("Missing registration data")}), 400
    rp_id = _get_fido2_rp_id()
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'rp_id'             : rp_id,
                    'fido2_state_id'    : fido2_state_id,
                    'registration_data' : registration_data,
                }
    ssod_conn = get_ssod_conn(g.user.name, mgmt=True)
    try:
        status, \
        status_code, \
        registration_response, \
        binary_data = ssod_conn.send(command="fido2_register_complete",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to complete fido2 registration: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=g.user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to complete fido2 registration.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(registration_response, "Failed to complete fido2 registration.")
        return jsonify({"error": error_msg}), 400
    deploy_token_name = flask_session.get('deploy_token_name')
    log_msg = _("FIDO2 token '{deploy_token_name}' registered for user '{user_name}'.", log=True)[1]
    log_msg = log_msg.format(deploy_token_name=deploy_token_name, user_name=g.user.name)
    logger.info(log_msg)
    return jsonify({"status": "ok", "message": "FIDO2 key registered successfully."})

# ---- FIDO2 Authentication (login with security key) ----

@app.route('/login/tiqr/begin', methods=['POST'])
# Same stacked limits as /login and /fido2/auth/begin: per-username
# against brute force from large NAT pools, per-IP against
# username-rotation. Nothing is stored server-side by this call, but it
# is still an enumeration surface worth rate limiting.
@limiter.limit(_rate_limit_login_user, key_func=_tiqr_begin_username_key)
@limiter.limit(_rate_limit_login)
def tiqr_auth_begin():
    """ Start a tiqr login. Hands the browser a challenge.

    Nothing is written: the session key, the challenge and the poll id
    are all derived, so an unauthenticated caller leaves no trace. The
    poll id goes into the browser's own session and never into the QR
    -- the session key is printed there and is therefore public, while
    only the poll id can collect the result.
    """
    data = request.json or {}
    username = str(data.get('username') or '').strip()
    if not username:
        return jsonify({"error": gettext("Username required")}), 400
    client_ip = check_forwarded_for()[0]
    begin_args = {
                    'username'      : username,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                }
    authd_conn = None
    try:
        authd_conn = get_authd_conn(username)
        status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="tiqr_auth_begin",
                                    command_args=begin_args)
    except Exception as e:
        log_msg = _("Failed to start tiqr authentication: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to start tiqr authentication.")}), 500
    finally:
        if authd_conn is not None:
            authd_conn.close()
    if not status or not isinstance(auth_response, dict):
        error_msg = _ssod_error_message(auth_response,
                                    "Failed to start tiqr authentication.")
        return jsonify({"error": error_msg}), 400
    # Held server-side in the signed session cookie. The poll takes the
    # id from here and never as a parameter: whoever photographed the
    # QR knows the session key, and must not be able to ask for the
    # result with it.
    flask_session['tiqr_poll_id'] = auth_response.get('poll_id')
    flask_session['tiqr_session_key'] = auth_response.get('session_key')
    flask_session['tiqr_username'] = username
    _tiqr_begin_reauth()
    return jsonify({
                "status"        : "ok",
                "auth_url"      : auth_response.get('auth_url'),
                "qrcode_img"    : auth_response.get('qrcode_img'),
            })


@app.route('/login/tiqr/status', methods=['GET'])
@limiter.limit(_rate_limit_login)
def tiqr_auth_status():
    """ Has the phone answered?

    Short poll: authd looks up the result and answers immediately. A
    long poll would tie up a gunicorn worker per waiting browser.
    """
    poll_id = flask_session.get('tiqr_poll_id')
    username = flask_session.get('tiqr_username')
    if not poll_id or not username:
        return jsonify({"status": "none"})
    client_ip = check_forwarded_for()[0]
    reauth_mode, reauth_args = _tiqr_reauth_args()
    status_args = {
                    'username'      : username,
                    'poll_id'       : poll_id,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                }
    status_args.update(reauth_args)
    authd_conn = None
    try:
        authd_conn = get_authd_conn(username)
        status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="tiqr_auth_status",
                                    command_args=status_args)
    except Exception as e:
        log_msg = _("Failed to poll tiqr authentication: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to complete tiqr authentication.")}), 500
    finally:
        if authd_conn is not None:
            authd_conn.close()
    if not status:
        _clear_tiqr_session()
        error_msg = _ssod_error_message(auth_response,
                                    "Failed to complete tiqr authentication.")
        return jsonify({"error": error_msg}), 400
    if not isinstance(auth_response, dict):
        return jsonify({"status": "pending"})
    tiqr_status = auth_response.get('tiqr_status')
    if tiqr_status == "pending":
        return jsonify({"status": "pending"})
    if tiqr_status == "challenge-expired":
        _clear_tiqr_session()
        return jsonify({"status": "challenge-expired"})
    _clear_tiqr_session()
    if reauth_mode:
        return _finish_tiqr_reauth()
    return _finish_sso_login(username, auth_response)


@app.route('/login/tiqr/otp', methods=['POST'])
@limiter.limit(_rate_limit_login_user, key_func=_tiqr_otp_username_key)
@limiter.limit(_rate_limit_login)
def tiqr_auth_otp():
    """ The fallback where the user types the six digits.

    The tiqr apps show the response when they cannot reach us. The
    session key is still in the browser's session, so this needs no
    result object -- it goes straight into the login.
    """
    data = request.json or {}
    response = str(data.get('response') or '').strip()
    session_key = flask_session.get('tiqr_session_key')
    username = flask_session.get('tiqr_username')
    if not response:
        return jsonify({"error": gettext("Response required")}), 400
    if not session_key or not username:
        return jsonify({"error": gettext("No authentication in progress")}), 400
    client_ip = check_forwarded_for()[0]
    reauth_mode, reauth_args = _tiqr_reauth_args()
    otp_args = {
                    'username'      : username,
                    'session_key'   : session_key,
                    'response'      : response,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                }
    otp_args.update(reauth_args)
    authd_conn = None
    try:
        authd_conn = get_authd_conn(username)
        status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="tiqr_auth_otp",
                                    command_args=otp_args)
    except Exception as e:
        log_msg = _("Failed to verify tiqr response: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to complete tiqr authentication.")}), 500
    finally:
        if authd_conn is not None:
            authd_conn.close()
    if not status or not isinstance(auth_response, dict):
        error_msg = _ssod_error_message(auth_response,
                                    "Failed to complete tiqr authentication.")
        return jsonify({"error": error_msg}), 400
    _clear_tiqr_session()
    if reauth_mode:
        return _finish_tiqr_reauth()
    return _finish_sso_login(username, auth_response)


def _clear_tiqr_session():
    """ Drop what a finished or abandoned tiqr login left behind. """
    flask_session.pop('tiqr_poll_id', None)
    flask_session.pop('tiqr_session_key', None)
    flask_session.pop('tiqr_username', None)
    flask_session.pop('tiqr_reauth', None)


def _tiqr_begin_reauth():
    """ Decide once, where the tiqr flow starts, whether it is a step-up.

    Not on every poll. The poll runs every two seconds, and a marker
    judged again on each of them can be dropped halfway through -- the
    flow then finishes as an ordinary login, which creates a second
    session and lands the user on the portal instead of wherever the
    step-up came from. Deciding here also means the answer cannot
    change between the QR code being shown and the phone answering it.

    The /reauth marker is honoured only while a session actually
    exists. One left over from an abandoned /reauth would otherwise
    turn this login into a step-up against a session that is gone, and
    the user could not log in at all. Dropping it is safe at this
    point, and only at this point: nothing is in flight yet.
    """
    reauth_mode = bool(flask_session.get('reauth_mode'))
    if reauth_mode and not (g.user and g.user.is_authenticated):
        flask_session.pop('reauth_mode', None)
        flask_session.pop('reauth_next', None)
        reauth_mode = False
    if reauth_mode:
        flask_session['tiqr_reauth'] = True
    log_msg = _("/login/tiqr/begin: reauth={r} next_stashed={n}", log=True)[1]
    log_msg = log_msg.format(r=reauth_mode,
                            n=bool(flask_session.get('reauth_next')))
    logger.info(log_msg)


def _tiqr_reauth_args():
    """ Is this tiqr login a step-up, and what does authd need for it?

    Returns ``(reauth_mode, extra_args)``. Reads only what
    _tiqr_begin_reauth() decided, so every poll of one flow answers
    the same.
    """
    if not flask_session.get('tiqr_reauth'):
        return False, {}
    return True, {
                'reauth'        : True,
                'session_uuid'  : request.cookies.get('otpme_sso_session'),
            }


def _finish_tiqr_reauth():
    """ A step-up that worked out.

    No session was created and no cookie changed -- authd only bumped
    reauth_time. Send the user back to whatever asked for the step-up:
    the settings card that needed a fresh reauth, or the RP's
    /authorize URL with prompt=login stripped.
    """
    flask_session.pop('reauth_mode', None)
    reauth_next = _safe_next_url(flask_session.pop('reauth_next', None))
    redirect_target = (reauth_next
                       or url_for('index', _external=True, _scheme='https'))
    # The fallback means the target was never stashed or no longer
    # passes the same-origin check, and the user silently ends up
    # somewhere other than where they started. Worth a line.
    if not reauth_next:
        log_msg = _("tiqr reauth: no next URL stashed, falling back to index.", log=True)[1]
        logger.warning(log_msg)
    return jsonify({"status": "ok", "redirect": redirect_target})


def _finish_sso_login(username, auth_response):
    """ Turn a successful authd reply into a logged-in browser.

    Shared by every credential that logs in over JSON rather than the
    login form: verify the JWT, put the user into the Flask session,
    work out where to send them, and hand back the response with the
    four cookies on it.

    Used by /fido2/auth/complete and by the tiqr poll -- for tiqr the
    credential was checked several requests ago, on the phone's own
    connection, but from here on it is the same login as any other.
    """
    try:
        login_token_pass_type = auth_response['login_token_pass_type']
        login_token_type = auth_response['login_token_type']
        login_token_deploy = auth_response['login_token_sso_deploy']
        session_uuid = auth_response['session']
        login_user_uuid = auth_response['login_user_uuid']
        login_user_site_uuid = auth_response['login_user_site_uuid']
        sso_jwt = auth_response['sso_jwt']
        slp = auth_response['slp']
    except KeyError as e:
        log_msg = _("Invalid auth response: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Get users site public key to verify the JWT.
    user_site = backend.get_object(object_type="site",
                                uuid=login_user_site_uuid)
    # Not synced to this host (yet): nothing to verify the JWT with.
    if user_site is None:
        log_msg = _("Unknown site of login user: {site_uuid}", log=True)[1]
        log_msg = log_msg.format(site_uuid=login_user_site_uuid)
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    site_jwt_key = user_site._cert_public_key
    try:
        jwt.decode(jwt=sso_jwt, key=site_jwt_key, algorithm='RS256')
    except Exception as e:
        log_msg = _("JWT verification failed: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Store user data in Flask session for load_user.
    flask_session['otpme_username'] = username
    flask_session['sso_deploy'] = login_token_deploy
    flask_session['login_token_pass_type'] = login_token_pass_type
    flask_session['login_token_type'] = login_token_type
    _stash_user_language(auth_response.get('login_user_language'))
    # Same redirect-priority as the form-based login flow: forced
    # enrollment beats next=, otherwise honor a stashed next= URL,
    # otherwise default to /index.
    if login_token_deploy:
        redirect_target = url_for('deploy', _external=True, _scheme='https')
    else:
        next_after = _safe_next_url(flask_session.pop('next_after_login', None))
        if next_after:
            redirect_target = next_after
        else:
            redirect_target = url_for('index', _external=True, _scheme='https')
    web_user = WebUser(uuid=login_user_uuid, name=username)
    resp = make_response(jsonify({
        "status": "ok",
        "redirect": redirect_target,
    }))
    resp.set_cookie('otpme_slp', slp,
                    httponly=True, secure=True, samesite='Lax')
    resp.set_cookie('otpme_jwt', sso_jwt,
                    httponly=True, secure=True, samesite='Lax')
    resp.set_cookie('otpme_user_uuid', login_user_uuid,
                    httponly=True, secure=True, samesite='Lax')
    resp.set_cookie('otpme_sso_session', session_uuid,
                    httponly=True, secure=True, samesite='Lax')
    login_user(web_user)
    _refresh_admin_access_state_post_login(username, sso_jwt, session_uuid)
    return resp


@app.route('/fido2/auth/begin', methods=['POST'])
# Stacked per-username + per-IP limits, sharing the site-level
# sso_rate_limit_login_user / sso_rate_limit_login configs with the
# /login route. FIDO2 is cryptographically bruteforce-resistant; the
# limits here primarily address enumeration (timing differences leak
# user existence) and DoS.
@limiter.limit(_rate_limit_login_user, key_func=_fido2_auth_username_key)
@limiter.limit(_rate_limit_login)
def fido2_auth_begin():
    data = request.json
    if not data or 'username' not in data:
        return jsonify({"error": gettext("Username required")}), 400
    username = str(data['username'])
    rp_id = _get_fido2_rp_id()
    client_ip = check_forwarded_for()[0]
    verify_args = {
                    'username'          : username,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'rp_id'             : rp_id,
                }
    authd_conn = None
    try:
        authd_conn = get_authd_conn(username)
        status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="fido2_auth_begin",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to start fido2 authentication: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to start fido2 authentication.")}), 500
    finally:
        if authd_conn is not None:
            authd_conn.close()
    if not status:
        error_msg = _ssod_error_message(auth_response, "Failed to start fido2 authentication.")
        return jsonify({"error": error_msg}), 400
    request_options = auth_response['request_options']
    # Store state in Flask session. The credential->token_name map
    # is intentionally NOT stashed here -- it now lives server-side in
    # authd's fido2_auth_states shared dict, so the synthetic
    # "decoy-N" names for unknown users never leak via the (signed
    # but unencrypted) Flask session cookie.
    flask_session['fido2_auth_username'] = str(username)
    flask_session['fido2_state_id'] = auth_response['fido2_state_id']
    return json.dumps(dict(request_options)), 200, {'Content-Type': 'application/json'}

@app.route('/fido2/auth/complete', methods=['POST'])
def fido2_auth_complete():
    fido2_state_id = flask_session.pop('fido2_state_id', None)
    username = flask_session.pop('fido2_auth_username', None)
    if not fido2_state_id or not username:
        return jsonify({"error": gettext("No authentication in progress")}), 400
    auth_response = request.json
    if not auth_response:
        return jsonify({"error": gettext("Missing auth response")}), 400
    # The credential -> token_name lookup now happens in authd, against
    # the server-side fido2_auth_states map cached at begin time. Web
    # layer just forwards the assertion -- no early "no matching
    # token" 401 here, which would itself be a side-channel against
    # decoy credential_ids returned for unknown users.
    rp_id = _get_fido2_rp_id()
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    # Step-up reauth marker set by /reauth. Tell authd to verify FIDO2
    # against the existing SSO session (no new session/cookies, just
    # a reauth_time bump). The current session_uuid comes from the
    # SSO cookie -- authd cross-checks it against the user.
    reauth_mode = bool(flask_session.pop('reauth_mode', False))
    reauth_next = _safe_next_url(flask_session.pop('reauth_next', None))
    verify_args = {
                    'username'          : username,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'rp_id'             : rp_id,
                    'fido2_state_id'    : fido2_state_id,
                    'auth_response'     : auth_response,
                }
    if reauth_mode:
        verify_args['reauth'] = True
        verify_args['session_uuid'] = request.cookies.get('otpme_sso_session')
    log_msg = _("/fido2/auth/complete: reauth_mode={r} session_uuid_set={s}", log=True)[1]
    log_msg = log_msg.format(r=reauth_mode, s=bool(request.cookies.get('otpme_sso_session')))
    logger.info(log_msg)
    # Any node will do: the auth state is synced across the cluster,
    # so the browser no longer has to come back to the one that
    # started the assertion.
    authd_conn = None
    try:
        authd_conn = get_authd_conn(username)
        status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="fido2_auth_complete",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to complete fido2 authentication: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        return jsonify({"error": gettext("Failed to complete fido2 authentication.")}), 500
    finally:
        if authd_conn is not None:
            authd_conn.close()
    if not status:
        error_msg = _ssod_error_message(auth_response, "Failed to complete fido2 authentication.")
        return jsonify({"error": error_msg}), 400
    if reauth_mode:
        # No new login session was created. Send the user back to
        # whatever triggered the step-up (typically the OIDC RP's
        # /authorize URL with prompt=login stripped).
        redirect_target = (reauth_next
                           or url_for('index', _external=True,
                                      _scheme='https'))
        return jsonify({"status": "ok", "redirect": redirect_target})
    return _finish_sso_login(username, auth_response)
