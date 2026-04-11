# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import json
import base64

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

def get_authd_conn(username,  password=None):
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
                                    realm=config.realm,
                                    site=config.site,
                                    username=username,
                                    password=password,
                                    auto_preauth=True,
                                    follow_redirect=False,
                                    request_token=False,
                                    auto_auth=False)
    return authd_conn

def get_ssod_conn(username):
    if config.host_data['type'] == "node":
        ssod_conn = connections.get("ssod",
                                    realm=config.realm,
                                    site=config.site,
                                    username=username,
                                    #auto_preauth=True,
                                    auto_auth=False,
                                    socket_uri=config.ssod_socket_path,
                                    local_socket=True,
                                    use_ssl=False,
                                    handle_host_auth=False,
                                    handle_user_auth=False,
                                    encrypt_session=False)
    else:
        ssod_conn = connections.get("ssod",
                                    realm=config.realm,
                                    site=config.site,
                                    username=username,
                                    follow_redirect=False,
                                    request_token=False,
                                    auto_preauth=True,
                                    auto_auth=False)
    return ssod_conn

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
    forwarded_host = request.headers.get('X-Forwarded-Host')
    if forwarded_host:
        rp_id = forwarded_host.split(',')[0].strip().split(':')[0]
    else:
        rp_id = request.host.split(':')[0]
    return rp_id

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
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
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
        return redirect(url_for('deploy', _external=True, _scheme='https'))
    return render_template("index.html", title='SSO Portal')

@app.route('/settings')
@login_required
def settings():
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    login_token_pass_type = flask_session.get('login_token_pass_type')
    show_password_change = (login_token_pass_type == "static")
    show_pin_change = (login_token_pass_type == "otp")
    return render_template("settings.html", title='Settings',
                           show_password_change=show_password_change,
                           show_pin_change=show_pin_change)

def _send_ssod_command(command, extra_args, default_error):
    """ Send a command to ssod using the current user's JWT.

    Returns a Flask response on error, otherwise the response payload dict. """
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    command_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                }
    command_args.update(extra_args)
    ssod_conn = get_ssod_conn(g.user.name)
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
        error_msg = _ssod_error_message(response, default_error)
        return None, (jsonify({"error": error_msg}), 400)
    return response, None

@app.route('/settings/device_tokens', methods=['GET'])
@login_required
def list_device_tokens():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    response, error = _send_ssod_command("list_device_tokens", {},
                                        "Failed to list device tokens.")
    if error:
        return error
    device_tokens = []
    role_info = ""
    role_configured = False
    if isinstance(response, dict):
        device_tokens = response.get('device_tokens', [])
        role_info = response.get('role_info', "") or ""
        role_configured = bool(response.get('role_configured', False))
    return jsonify({
                "device_tokens"     : device_tokens,
                "role_info"         : role_info,
                "role_configured"   : role_configured,
            })

@app.route('/settings/device_tokens', methods=['POST'])
@login_required
def add_device_token():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json or {}
    device_name = data.get('device_name', '').strip()
    if not device_name:
        return jsonify({"error": "Device name is required."}), 400
    response, error = _send_ssod_command("add_device_token",
                                        {'device_name': device_name},
                                        "Failed to add device token.")
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
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json or {}
    token_name = data.get('name', '').strip()
    if not token_name:
        return jsonify({"error": "Token name is required."}), 400
    response, error = _send_ssod_command("del_device_token",
                                        {'token_name': token_name},
                                        "Failed to delete device token.")
    if error:
        return error
    return jsonify({"status": "ok", "message": "Device token deleted."})

@app.route('/settings/redeploy')
@login_required
def settings_redeploy():
    """ Trigger re-deploy of the login token via the normal deploy flow. """
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    flask_session['sso_deploy'] = True
    return redirect(url_for('deploy', _external=True, _scheme='https'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json
    if not data:
        return jsonify({"error": "Missing data"}), 400
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All fields are required."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match."}), 400
    if len(new_password) < 1:
        return jsonify({"error": "Password must not be empty."}), 400
    login_token = flask_session.get("login_token")
    if not login_token:
        return jsonify({"error": "No login token."}), 400
    login_token_pass_type = flask_session.get("login_token_pass_type")
    if login_token_pass_type != "static":
        return jsonify({"error": "Token does not support password change."}), 400
    # Send request to authd.
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'token_path'        : login_token,
                    'current_password'  : current_password,
                    'new_password'      : new_password,
                }
    ssod_conn = get_ssod_conn(g.user.name)
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
        return jsonify({"error": "Failed to change password."}), 500
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
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json
    if not data:
        return jsonify({"error": "Missing data"}), 400
    current_pin = data.get('current_pin', '')
    new_pin = data.get('new_pin', '')
    confirm_pin = data.get('confirm_pin', '')
    if not current_pin or not new_pin or not confirm_pin:
        return jsonify({"error": "All fields are required."}), 400
    if new_pin != confirm_pin:
        return jsonify({"error": "New PINs do not match."}), 400
    if len(new_pin) < 1:
        return jsonify({"error": "PIN must not be empty."}), 400
    login_token = flask_session.get("login_token")
    if not login_token:
        return jsonify({"error": "No login token."}), 400
    login_token_pass_type = flask_session.get("login_token_pass_type")
    if login_token_pass_type != "otp":
        return jsonify({"error": "Token does not support PIN change."}), 400
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    verify_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                    'token_path'    : login_token,
                    'current_pin'   : current_pin,
                    'new_pin'       : new_pin,
                }
    ssod_conn = get_ssod_conn(g.user.name)
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
        return jsonify({"error": "Failed to change PIN."}), 500
    finally:
        ssod_conn.close()
    if not status:
        error_msg = _ssod_error_message(response, "PIN change failed.")
        return jsonify({"error": error_msg}), 400
    log_msg = _("PIN changed for user '{user_name}' via SSO portal.", log=True)[1]
    log_msg = log_msg.format(user_name=g.user.name)
    logger.info(log_msg)
    return jsonify({"status": "ok", "message": "PIN changed successfully."})

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
    return render_template("deploy.html",
                           title='Token Enrollment',
                           deploy_token_types=deploy_token_types)

@app.route('/deploy/begin', methods=['POST'])
@login_required
def deploy_begin():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    sso_deploy = flask_session.get('sso_deploy')
    if not sso_deploy:
        return jsonify({"error": "Deployment not required"}), 400
    login_token_uuid = flask_session.get('login_token_uuid')
    if not login_token_uuid:
        return jsonify({"error": "Deployment failed: No login token UUID"}), 400
    # Get token type from request (user choice) or sso_deploy setting.
    data = request.json or {}
    if isinstance(sso_deploy, str) and sso_deploy is not True:
        # Fixed token type - ignore user choice.
        token_type = sso_deploy
    else:
        # User can choose.
        token_type = data.get('token_type', 'totp')
        if token_type not in ('totp', 'fido2'):
            return jsonify({"error": "Invalid token type."}), 400
    # Send request to authd.
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'token_type'        : token_type,
                    'login_token_uuid'  : login_token_uuid,
                }
    ssod_conn = get_ssod_conn(g.user.name)
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
        return jsonify({"error": "Failed to start token deploy."}), 500
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
        return jsonify({"error": "Not authenticated"}), 401
    token_data = request.json or {}
    deploy_name = flask_session.get('deploy_token_name')
    login_token_name = flask_session.get('deploy_login_token_name')
    if not deploy_name or not login_token_name:
        return jsonify({"error": "No deployment in progress."}), 400
    # Send request to authd.
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    verify_args = {
                    'username'          : g.user.name,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'token_data'        : token_data,
                    'login_token_name'  : login_token_name,
                }
    ssod_conn = get_ssod_conn(g.user.name)
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
        return jsonify({"error": "Failed to verify token deploy."}), 500
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user and g.user.is_authenticated:
        return redirect(url_for('index', _external=True, _scheme='https'))
    form = LoginForm()
    if not form.validate_on_submit():
        return render_template('login.html',
                               title='Sign In',
                               user=None,
                               form=form)
    # Get client IP.
    if request.headers.get('X-Forwarded-For'):
      client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
      client_ip = request.remote_addr
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

    # Check if we have users secrets.
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
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    finally:
        authd_conn.close()
    if not auth_status:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    try:
        login_token = auth_response['login_token']
        login_token_uuid = auth_response['login_token_uuid']
        login_token_pass_type = auth_response['login_token_pass_type']
        login_token_deploy = auth_response['login_token_sso_deploy']
        session_uuid = auth_response['session']
        login_user_uuid = auth_response['login_user_uuid']
        login_user_site_uuid = auth_response['login_user_site_uuid']
        sso_jwt = auth_response['sso_jwt']
        slp = auth_response['slp']
    except KeyError as e:
        log_msg = _("Invalid auth response.", log=True)[1]
        logger.warning(log_msg)
        flash("Login failed.")
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
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Check if token requires SSO deploy (enrollment).
    if login_token_deploy:
        redirect_target = url_for('deploy', _external=True, _scheme='https')
    else:
        redirect_target = url_for('index', _external=True, _scheme='https')
    # Store user data in Flask session for load_user.
    flask_session['otpme_username'] = username
    flask_session['login_token'] = login_token
    flask_session['sso_deploy'] = login_token_deploy
    flask_session['login_token_uuid'] = login_token_uuid
    flask_session['login_token_pass_type'] = login_token_pass_type
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

def _do_sso_logout(response):
    """ Terminate the user's SSO session on authd and clear local state. """
    slp = request.cookies.get('otpme_slp')
    username = flask_session.get('otpme_username')
    response.set_cookie('otpme_slp', '', expires=0)
    response.set_cookie('otpme_jwt', '', expires=0)
    response.set_cookie('otpme_user_uuid', '', expires=0)
    response.set_cookie('otpme_sso_session', '', expires=0)
    if username:
        try:
            authd_conn = get_authd_conn(username, slp)
        except Exception as e:
            log_msg = _("Failed to logout user: {user_name}", log=True)[1]
            log_msg = log_msg.format(user_name=username)
            log_msg = f"{log_msg}: {e}"
            logger.warning(log_msg)
        else:
            if request.headers.get('X-Forwarded-For'):
                client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            else:
                client_ip = request.remote_addr
            verify_args = {
                            'username'      : username,
                            'password'      : slp,
                            'client'        : config.sso_client_name,
                            'client_ip'     : client_ip,
                            'sso_logout'    : True,
                            'realm_login'   : False,
                            'realm_logout'  : False,
                        }
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

@app.route('/logout')
def logout():
    if not g.user:
        return redirect(url_for('login', _external=True, _scheme='https'))
    resp = make_response(redirect(url_for('login', _external=True, _scheme='https')))
    return _do_sso_logout(resp)

@app.route('/get_apps')
@login_required
def get_apps():
    if not g.user.is_authenticated:
        return jsonify([])
    response, error = _send_ssod_command("get_apps", {},
                                        "Failed to get app list.")
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
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
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
        return jsonify({"error": "Failed to get SOTP."}), 500
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
                    "error": "Session expired. Please log in again.",
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
        return jsonify({"error": "Not authenticated"}), 401
    rp_id = _get_fido2_rp_id()
    sso_jwt = request.cookies.get('otpme_jwt')
    is_deploy = flask_session.get('deploy_token_name') is not None
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    verify_args = {
                    'username'      : g.user.name,
                    'sso_jwt'       : sso_jwt,
                    'client'        : config.sso_client_name,
                    'client_ip'     : client_ip,
                    'rp_id'         : rp_id,
                    'is_deploy'     : is_deploy,
                }
    ssod_conn = get_ssod_conn(g.user.name)
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
        return jsonify({"error": "Failed to start fido2 registration."}), 500
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
        return jsonify({"error": "Not authenticated"}), 401
    reg_state = flask_session.pop('fido2_reg_state', None)
    token_uuid = flask_session.pop('fido2_reg_token_uuid', None)
    if not reg_state or not token_uuid:
        return jsonify({"error": "No registration in progress"}), 400
    registration_data = request.json
    if not registration_data:
        return jsonify({"error": "Missing registration data"}), 400
    rp_id = _get_fido2_rp_id()
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
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
    ssod_conn = get_ssod_conn(g.user.name)
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
        return jsonify({"error": "Failed to complete fido2 registration."}), 500
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
        return jsonify({"error": "Username required"}), 400
    username = str(data['username'])
    rp_id = _get_fido2_rp_id()
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
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
        return jsonify({"error": "Failed to start fido2 authentication."}), 500
    finally:
        authd_conn.close()
    if not status:
        error_msg = _ssod_error_message(auth_response, "Failed to start fido2 authentication.")
        return jsonify({"error": error_msg}), 400
    request_options = auth_response['request_options']
    # Store state in Flask session.
    flask_session['fido2_auth_username'] = str(username)
    flask_session['fido2_auth_state'] = auth_response['fido2_auth_state']
    flask_session['fido2_credential_token_map'] = auth_response['fido2_credential_token_map']
    return json.dumps(dict(request_options)), 200, {'Content-Type': 'application/json'}

@app.route('/fido2/auth/complete', methods=['POST'])
def fido2_auth_complete():
    auth_state = flask_session.pop('fido2_auth_state', None)
    username = flask_session.pop('fido2_auth_username', None)
    credential_token_map = flask_session.pop('fido2_credential_token_map', {})
    if not auth_state or not username:
        return jsonify({"error": "No authentication in progress"}), 400
    auth_state = _deserialize_fido2_state(auth_state)
    auth_response = request.json
    if not auth_response:
        return jsonify({"error": "Missing auth response"}), 400
    # Find the matching token by credential ID from the response.
    response_cred_id = auth_response.get('id', '')
    matched_token_name = credential_token_map.get(response_cred_id)
    if not matched_token_name:
        logger.warning(f"FIDO2 auth: no token found for credential ID: {response_cred_id}")
        return jsonify({"error": "Login failed"}), 401
    rp_id = _get_fido2_rp_id()
    sso_jwt = request.cookies.get('otpme_jwt')
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    verify_args = {
                    'username'          : username,
                    'sso_jwt'           : sso_jwt,
                    'client'            : config.sso_client_name,
                    'client_ip'         : client_ip,
                    'rp_id'             : rp_id,
                    'auth_state'        : auth_state,
                    'auth_response'     : auth_response,
                    'matched_token_name': matched_token_name,
                }
    authd_conn = get_authd_conn(username)
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
        return jsonify({"error": "Failed to complete fido2 authentication."}), 500
    finally:
        authd_conn.close()
    if not status:
        error_msg = _ssod_error_message(auth_response, "Failed to complete fido2 authentication.")
        return jsonify({"error": error_msg}), 400
    try:
        login_token = auth_response['login_token']
        login_token_uuid = auth_response['login_token_uuid']
        login_token_pass_type = auth_response['login_token_pass_type']
        login_token_deploy = auth_response['login_token_sso_deploy']
        session_uuid = auth_response['session']
        login_user_uuid = auth_response['login_user_uuid']
        login_user_site_uuid = auth_response['login_user_site_uuid']
        sso_jwt = auth_response['sso_jwt']
        slp = auth_response['slp']
    except KeyError as e:
        log_msg = _("Invalid auth response.", log=True)[1]
        logger.warning(log_msg)
        flash("Login failed.")
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
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Store user data in Flask session for load_user.
    flask_session['otpme_username'] = username
    flask_session['login_token'] = login_token
    flask_session['sso_deploy'] = login_token_deploy
    flask_session['login_token_uuid'] = login_token_uuid
    flask_session['login_token_pass_type'] = login_token_pass_type
    web_user = WebUser(uuid=login_user_uuid, name=username)
    resp = make_response(jsonify({
        "status": "ok",
        "redirect": url_for('index', _external=True, _scheme='https'),
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
