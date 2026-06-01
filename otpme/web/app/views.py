# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import json

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

def get_ssod_conn(username, mgmt=False):
    if config.host_data['type'] == "node":
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
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
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

@app.route('/settings')
@login_required
def settings():
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
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

def _send_ssod_command(command, extra_args=None, default_error=None, mgmt=False):
    """ Send a command to ssod using the current user's JWT.

    Returns a Flask response on error, otherwise the response payload dict. """
    if extra_args is None:
        extra_args = {}
    sso_jwt = request.cookies.get('otpme_jwt')
    client_ip = check_forwarded_for()[0]
    command_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
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
        if isinstance(response, dict) and response.get('message') == 'JWT_INVALID':
            log_msg = _("SSO JWT invalid for user '{user_name}', logging out.", log=True)[1]
            log_msg = log_msg.format(user_name=g.user.name)
            logger.warning(log_msg)
            resp = make_response(jsonify({
                    "error": gettext("Session expired. Please log in again."),
                    "redirect": url_for('login', _external=True, _scheme='https'),
                }), 401)
            return None, _do_sso_logout(resp)
        error_msg = _ssod_error_message(response, default_error)
        return None, (jsonify({"error": error_msg}), 400)
    return response, None

@app.route('/settings/device_tokens', methods=['GET'])
@login_required
def list_device_tokens():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
def add_device_token():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
    data = request.json or {}
    device_name = data.get('device_name', '').strip()
    role_uuid = (data.get('role_uuid') or '').strip()
    if not device_name:
        return jsonify({"error": gettext("Device name is required.")}), 400
    if not role_uuid:
        return jsonify({"error": gettext("Role is required.")}), 400
    response, error = _send_ssod_command(command="add_device_token",
                                        extra_args={'device_name': device_name,
                                                    'role_uuid':   role_uuid},
                                        default_error=gettext("Failed to add device token."),
                                        mgmt=True)
    if error:
        return error
    return jsonify({
                "status"        : "ok",
                "name"          : response.get('name'),
                "device_name"   : response.get('device_name'),
                "password"      : response.get('password'),
            })

@app.route('/settings/device_tokens/delete', methods=['POST'])
@login_required
def del_device_token():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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

@app.route('/settings/passkeys', methods=['GET'])
@login_required
def list_passkeys():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
    if isinstance(response, dict):
        passkeys = response.get('passkeys', []) or []
    return jsonify({"passkeys": passkeys})

@app.route('/settings/passkeys/register/begin', methods=['POST'])
@login_required
def passkey_register_begin():
    """ Start passkey enrollment.

    Returns the WebAuthn ``create_options`` for the browser, and stashes
    the reg_state + sanitized token_name + display name in the Flask
    session so ``complete`` can verify them server-side without
    trusting client-supplied values. """
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
    flask_session['passkey_reg_state'] = response.get('passkey_reg_state')
    flask_session['passkey_reg_device_name'] = response.get('device_name')
    flask_session['passkey_reg_token_name'] = response.get('token_name')
    return jsonify(response.get('create_options', {}))

@app.route('/settings/passkeys/register/complete', methods=['POST'])
@login_required
def passkey_register_complete():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
    reg_state = flask_session.pop('passkey_reg_state', None)
    device_name = flask_session.pop('passkey_reg_device_name', None)
    token_name = flask_session.pop('passkey_reg_token_name', None)
    if not reg_state or not device_name or not token_name:
        return jsonify({"error": gettext("No passkey registration in progress")}), 400
    registration_data = request.json
    if not registration_data:
        return jsonify({"error": gettext("Missing registration data")}), 400
    rp_id = _get_fido2_rp_id()
    response, error = _send_ssod_command(
            command="passkey_register_complete",
            extra_args={
                'rp_id'             : rp_id,
                'passkey_reg_state' : reg_state,
                'registration_data' : registration_data,
                'device_name'       : device_name,
                'token_name'        : token_name,
            },
            default_error=gettext("Failed to complete passkey registration."),
            mgmt=True)
    if error:
        return error
    return jsonify({
                "status"        : "ok",
                "name"          : response.get('name'),
                "device_name"   : response.get('device_name'),
            })

@app.route('/settings/passkeys/delete', methods=['POST'])
@login_required
def del_passkey():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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

@app.route('/settings/oidc_consents', methods=['GET'])
@login_required
def list_oidc_consents():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
def revoke_oidc_consent():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
def settings_redeploy():
    """ Trigger re-deploy of the login token via the normal deploy flow. """
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    flask_session['sso_deploy'] = True
    flask_session['sso_deploy_optional'] = True
    return redirect(url_for('deploy', _external=True, _scheme='https'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
    if len(new_password) < 1:
        return jsonify({"error": gettext("Password must not be empty.")}), 400
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
def change_pin():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
    if len(new_pin) < 1:
        return jsonify({"error": gettext("PIN must not be empty.")}), 400
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
def change_language():
    """ Persist the user's language preference. Accepts the literal
    "default" to clear the pref (revert to Accept-Language). """
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    sso_deploy = flask_session.get('sso_deploy')
    if not sso_deploy:
        return redirect(url_for('index', _external=True, _scheme='https'))
    # Determine allowed token types.
    if isinstance(sso_deploy, str) and sso_deploy is not True:
        deploy_token_types = [sso_deploy]
    else:
        deploy_token_types = ["totp", "fido2"]
        # Filter by per-user/unit/site config (sso_allow_totp_deploy,
        # sso_allow_fido2_deploy). Best-effort: if the query fails, fall
        # back to the full list — deploy_begin enforces the same gate
        # authoritatively, so the worst case is a button that errors out.
        response, _err = _send_ssod_command(
                command="get_allowed_deploy_token_types",
                default_error=None, mgmt=True)
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
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
        if token_type not in ('totp', 'fido2'):
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
                }
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
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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

def _safe_next_url(next_url):
    """ Validate a ``next=`` redirect target. Only same-app local
    paths are accepted: must start with '/' and must NOT start with
    '//' or 'http(s)://' (open-redirect defense). Returns the URL
    if safe, else None.
    """
    if not next_url:
        return None
    if not next_url.startswith('/'):
        return None
    # '//foo' is an interpretable scheme-relative URL; reject.
    if next_url.startswith('//'):
        return None
    return next_url


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Stash the optional ``next=`` target in the flask session so it
    # survives the form-submission roundtrip (the POST won't carry
    # the original GET query string).
    next_url = _safe_next_url(request.args.get('next'))
    if next_url:
        flask_session['next_after_login'] = next_url

    if g.user and g.user.is_authenticated:
        # Already logged in -- honor next= if it's there, else /index.
        target = (_safe_next_url(flask_session.pop('next_after_login', None))
                  or url_for('index', _external=True, _scheme='https'))
        return redirect(target)
    form = LoginForm()
    if not form.validate_on_submit():
        return render_template('login.html',
                               title=gettext('Sign In'),
                               user=None,
                               form=form)
    # Get client IP.
    client_ip = check_forwarded_for()[0]
    # Get username/password.
    username = request.form['username']
    password = request.form['password']
    # Get JWT from authd.
    sso_challenge = stuff.gen_secret(len=32)
    verify_args = {
                    'username'          : username,
                    'password'          : password,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'sso_challenge'     : sso_challenge,
                }

    # Get authd connection.
    authd_conn = get_authd_conn(username, password)
    try:
        auth_status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="verify",
                                    command_args=verify_args)
    except Exception as e:
        log_msg = _("Failed to authenticate user: {user_name}", log=True)[1]
        log_msg = log_msg.format(user_name=username)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    finally:
        authd_conn.close()
    if not auth_status:
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
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
        log_msg = _("Invalid auth response.", log=True)[1]
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Get users site public key to verify the JWT.
    user_site = backend.get_object(object_type="site",
                                uuid=login_user_site_uuid)
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
                except Exception:
                    pass
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
    form = LoginForm()
    form.username.data = username
    return render_template('login.html',
                           title=gettext('Re-authenticate'),
                           user=None,
                           form=form,
                           reauth=True,
                           reauth_username=username)

@app.route('/logout')
def logout():
    next_url = _safe_next_url(request.args.get('next'))
    if not g.user:
        return redirect(url_for('login', next=next_url, _external=True, _scheme='https'))
    resp = make_response(redirect(url_for('login', next=next_url, _external=True, _scheme='https')))
    return _do_sso_logout(resp)

@app.route('/get_apps')
@login_required
def get_apps():
    if not g.user.is_authenticated:
        return jsonify([])
    response, error = _send_ssod_command(command="get_apps",
                        default_error=gettext("Failed to get app list."))
    if error:
        return error
    app_data = []
    if isinstance(response, dict):
        app_data = response.get('app_data', [])
    return jsonify(app_data)

@app.route('/get_sotp')
@login_required
def get_sotp():
    sotp_data = None
    if not g.user.is_authenticated:
        return jsonify(sotp_data)
    try:
        access_group = request.args['access_group']
    except KeyError:
        return jsonify(sotp_data)
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
        return jsonify({"error": gettext("Failed to get SOTP.")}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(sotp_data, "Failed to get SOTP.")
        # Invalid/expired JWT: force logout so the user re-authenticates.
        if isinstance(sotp_data, dict) and sotp_data.get('message') == 'JWT_INVALID':
            log_msg = _("SSO JWT invalid for user '{user_name}', logging out.", log=True)[1]
            log_msg = log_msg.format(user_name=g.user.name)
            logger.warning(log_msg)
            resp = make_response(jsonify({
                    "error": gettext("Session expired. Please log in again."),
                    "redirect": url_for('login', _external=True, _scheme='https'),
                }), 401)
            return _do_sso_logout(resp)
        return jsonify({"error": error_msg}), 400
    return jsonify(sotp_data)

# ---- FIDO2 Registration (logged-in user registers a security key) ----

@app.route('/fido2/register/begin', methods=['POST'])
@login_required
def fido2_register_begin():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
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
    fido2_reg_state = fido2_reg_data['fido2_reg_state']
    fido2_reg_token_uuid = fido2_reg_data['fido2_reg_token_uuid']
    # Store state in Flask session.
    flask_session['fido2_reg_state'] = fido2_reg_state
    flask_session['fido2_reg_token_uuid'] = fido2_reg_token_uuid
    return json.dumps(create_options), 200, {'Content-Type': 'application/json'}

@app.route('/fido2/register/complete', methods=['POST'])
@login_required
def fido2_register_complete():
    if not g.user.is_authenticated:
        return jsonify({"error": gettext("Not authenticated")}), 401
    reg_state = flask_session.pop('fido2_reg_state', None)
    token_uuid = flask_session.pop('fido2_reg_token_uuid', None)
    if not reg_state or not token_uuid:
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
                    'reg_state'         : reg_state,
                    'token_uuid'        : token_uuid,
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

@app.route('/fido2/auth/begin', methods=['POST'])
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
    authd_conn = get_authd_conn(username)
    try:
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
        authd_conn.close()
    if not status:
        error_msg = _ssod_error_message(auth_response, "Failed to start fido2 authentication.")
        return jsonify({"error": error_msg}), 400
    request_options = auth_response['request_options']
    # Store state in Flask session.
    flask_session['fido2_auth_username'] = str(username)
    flask_session['fido2_state_id'] = auth_response['fido2_state_id']
    flask_session['fido2_auth_node'] = auth_response['fido2_auth_node']
    flask_session['fido2_credential_token_map'] = auth_response['fido2_credential_token_map']
    return json.dumps(dict(request_options)), 200, {'Content-Type': 'application/json'}

@app.route('/fido2/auth/complete', methods=['POST'])
def fido2_auth_complete():
    fido2_state_id = flask_session.pop('fido2_state_id', None)
    fido2_auth_node = flask_session.pop('fido2_auth_node', None)
    username = flask_session.pop('fido2_auth_username', None)
    credential_token_map = flask_session.pop('fido2_credential_token_map', {})
    if not fido2_state_id or not fido2_auth_node or not username:
        return jsonify({"error": gettext("No authentication in progress")}), 400
    auth_response = request.json
    if not auth_response:
        return jsonify({"error": gettext("Missing auth response")}), 400
    # Find the matching token by credential ID from the response.
    response_cred_id = auth_response.get('id', '')
    matched_token_name = credential_token_map.get(response_cred_id)
    if not matched_token_name:
        logger.warning(f"FIDO2 auth: no token found for credential ID: {response_cred_id}")
        return jsonify({"error": gettext("Login failed")}), 401
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
                    'matched_token_name': matched_token_name,
                }
    if reauth_mode:
        verify_args['reauth'] = True
        verify_args['session_uuid'] = request.cookies.get('otpme_sso_session')
    authd_conn = get_authd_conn(username, node=fido2_auth_node)
    try:
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
        log_msg = _("Invalid auth response.", log=True)[1]
        logger.warning(log_msg)
        flash(gettext("Login failed."))
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Get users site public key to verify the JWT.
    user_site = backend.get_object(object_type="site",
                                uuid=login_user_site_uuid)
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
    return resp
