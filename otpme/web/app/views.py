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
from flask import session as flask_session
from flask_login import login_user
from flask_login import logout_user
from flask_login import current_user
from flask_login import login_required

from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData

#from markupsafe import escape

from otpme.web.app import lm
from otpme.web.app import app
from otpme.web.app.forms import LoginForm

from otpme.lib import jwt
from otpme.lib import sotp
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib.encoding.base import encode as otpme_encode
from otpme.lib.encoding.base import decode as otpme_decode

from otpme.lib.exceptions import *

logger = config.logger

def _get_fido2_rp_id():
    """ Get RP ID from request host for WebAuthn browser compatibility.
        Checks X-Forwarded-Host for reverse proxy setups. """
    forwarded_host = request.headers.get('X-Forwarded-Host')
    if forwarded_host:
        rp_id = forwarded_host.split(',')[0].strip().split(':')[0]
    else:
        rp_id = request.host.split(':')[0]
    return rp_id

def _get_fido2_server():
    """ Get FIDO2 server instance for web portal. """
    rp_id = _get_fido2_rp_id()
    rp_data = {"id": rp_id, "name": "OTPme RP"}
    return Fido2Server(rp_data, attestation="direct")

def _serialize_fido2_state(state):
    """ Serialize fido2 state dict for Flask session storage. """
    serialized = {}
    for k, v in state.items():
        if isinstance(v, bytes):
            serialized[k] = base64.b64encode(v).decode('ascii')
            serialized['_b_' + k] = True
        else:
            serialized[k] = v
    return serialized

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
    # Load user.
    result = backend.search(object_type="user",
                            attribute="uuid",
                            value=id,
                            return_type="instance")
    if not result:
        return None
    user = result[0]
    # Get session UUID.
    session_uuid = request.cookies.get('otpme_sso_session')
    # Get session data.
    session = backend.get_object(uuid=session_uuid)
    if not session:
        return user
    # Verify session belongs to the authenticated user.
    if session.user_uuid != user.uuid:
        return user
    result = backend.search(object_type="token",
                            attribute="uuid",
                            value=session.auth_token,
                            return_type="instance")
    if not result:
        return user
    config.auth_token = result[0]
    return user

@app.before_request
def before_request():
    config.proc_mode = "threading"
    config.auth_token = None
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
    if config.auth_token and config.auth_token.sso_deploy:
        return redirect(url_for('deploy', _external=True, _scheme='https'))
    return render_template("index.html", title='SSO Portal')

@app.route('/settings')
@login_required
def settings():
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    show_password_change = (config.auth_token
                            and config.auth_token.pass_type == "static")
    return render_template("settings.html", title='Settings',
                           show_password_change=show_password_change)

@app.route('/settings/fido2/begin', methods=['POST'])
@login_required
def settings_fido2_begin():
    """ Create sso-deploy FIDO2 token to replace the login token. """
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    if not config.auth_token:
        return jsonify({"error": "No login token."}), 400
    deploy_name = "sso-deploy"
    # Remove old sso-deploy token if it exists.
    old_deploy = g.user.token(deploy_name)
    if old_deploy:
        g.user.del_token(token_name=deploy_name,
                        force=True,
                        verify_acls=False,
                        run_policies=False,
                        callback=config.get_callback())
    try:
        g.user.add_token(token_name=deploy_name,
                        token_type="fido2",
                        force=True,
                        verify_acls=False,
                        run_policies=False,
                        callback=config.get_callback())
    except Exception as e:
        log_msg = f"Settings FIDO2 deploy failed for user '{g.user.name}': {e}"
        logger.warning(log_msg)
        return jsonify({"error": "Token creation failed."}), 500
    flask_session['deploy_token_name'] = deploy_name
    flask_session['deploy_login_token_name'] = config.auth_token.name
    return jsonify({"status": "ok"})

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
    # Use the login token.
    token = config.auth_token
    if not token or token.pass_type != "static":
        return jsonify({"error": "Token does not support password change."}), 400
    # Verify current password against the token.
    verify_result = token.verify_static(password=current_password,
                                        ignore_2f_token=True)
    if not verify_result:
        return jsonify({"error": "Current password is incorrect."}), 401
    # Change password.
    callback = config.get_callback()
    callback.raise_exception = True
    try:
        token.change_password(password=new_password,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
    except Exception as e:
        log_msg = f"Password change failed for user '{g.user.name}': {e}"
        logger.warning(log_msg)
        return jsonify({"error": str(e)}), 400
    token._write(callback=callback)
    log_msg = f"Password changed for user '{g.user.name}' via SSO portal."
    logger.info(log_msg)
    return jsonify({"status": "ok", "message": "Password changed successfully."})

# ---- SSO Token Deploy (enrollment) ----

@app.route('/deploy')
@login_required
def deploy():
    if not g.user.is_authenticated:
        return redirect(url_for('login', _external=True, _scheme='https'))
    if not config.auth_token or not config.auth_token.sso_deploy:
        return redirect(url_for('index', _external=True, _scheme='https'))
    sso_deploy = config.auth_token.sso_deploy
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
    if not config.auth_token or not config.auth_token.sso_deploy:
        return jsonify({"error": "Deployment not required"}), 400
    sso_deploy = config.auth_token.sso_deploy
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
    login_token = config.auth_token
    deploy_name = "sso-deploy"
    login_token_name = login_token.name
    # Remove old sso-deploy token if it exists (e.g. from a previous attempt).
    old_deploy = g.user.token(deploy_name)
    if old_deploy:
        g.user.del_token(token_name=deploy_name,
                        force=True,
                        verify_acls=False,
                        run_policies=False,
                        callback=config.get_callback())
    # Create sso-deploy token under the user.
    try:
        g.user.add_token(token_name=deploy_name,
                        token_type=token_type,
                        no_token_infos=True,
                        gen_qrcode=False,
                        force=True,
                        verify_acls=False,
                        run_policies=False,
                        callback=config.get_callback())
    except Exception as e:
        log_msg = f"SSO deploy failed for user '{g.user.name}': {e}"
        logger.critical(log_msg)
        return jsonify({"error": "Token creation failed."}), 500
    deploy_token = g.user.token(deploy_name)
    if not deploy_token:
        return jsonify({"error": "Token creation failed."}), 500
    # Store info in session for verification step.
    flask_session['deploy_token_name'] = deploy_name
    flask_session['deploy_login_token_name'] = login_token_name
    # For FIDO2 tokens, use the WebAuthn registration flow.
    if token_type == "fido2":
        return jsonify({"status": "ok", "token_type": "fido2"})
    # For OATH tokens (TOTP/HOTP): generate QR code.
    secret = deploy_token.get_secret(pin=deploy_token.pin, encoding="base32")
    try:
        qrcode_data = deploy_token.gen_qrcode(pin=deploy_token.pin,
                                              fmt="svg",
                                              run_policies=False,
                                              verify_acls=False)
        if isinstance(qrcode_data, bytes):
            qrcode_data = qrcode_data.decode('utf-8')
        qrcode_data_uri = "data:image/svg+xml;base64," + base64.b64encode(qrcode_data.encode()).decode()
    except Exception as e:
        log_msg = f"QR code generation failed: {e}"
        logger.warning(log_msg)
        return jsonify({"error": "QR code generation failed."}), 500
    response_data = {
        "status": "ok",
        "qrcode_img": qrcode_data_uri,
        "pin": deploy_token.pin,
        "secret": secret,
        "token_type": token_type,
    }
    log_msg = f"SSO deploy started for user '{g.user.name}', token type '{token_type}'."
    logger.info(log_msg)
    return jsonify(response_data)

@app.route('/deploy/verify', methods=['POST'])
@login_required
def deploy_verify():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    deploy_name = flask_session.get('deploy_token_name')
    login_token_name = flask_session.get('deploy_login_token_name')
    if not deploy_name or not login_token_name:
        return jsonify({"error": "No deployment in progress."}), 400
    # Load the sso-deploy token.
    deploy_token = g.user.token(deploy_name)
    if not deploy_token:
        return jsonify({"error": "Deploy token not found."}), 400
    # FIDO2 tokens are verified by the WebAuthn registration itself.
    # OATH tokens need OTP verification.
    if deploy_token.token_type == "fido2":
        if not deploy_token.credential_data:
            return jsonify({"error": "Security key not registered yet."}), 400
    else:
        data = request.json or {}
        otp = str(data.get('otp', ''))
        if not otp:
            return jsonify({"error": "OTP required."}), 400
        try:
            pin = deploy_token.pin or ""
            verify_result = deploy_token.verify_otp(otp=f"{pin}{otp}")
        except Exception as e:
            log_msg = f"SSO deploy OTP verification failed for user '{g.user.name}': {e}"
            logger.warning(log_msg)
            return jsonify({"error": "Verification failed."}), 401
        if not verify_result:
            return jsonify({"error": "Invalid OTP. Please try again."}), 401
    # OTP verified - move sso-deploy token to replace the login token.
    target_path = f"{g.user.name}/{login_token_name}"
    try:
        deploy_token.move(target_path,
                        replace=True,
                        force=True,
                        run_policies=False,
                        callback=config.get_callback())
    except Exception as e:
        log_msg = f"SSO deploy token move failed for user '{g.user.name}': {e}"
        logger.critical(log_msg)
        return jsonify({"error": "Token deployment failed."}), 500
    # Clean up session.
    flask_session.pop('deploy_token_name', None)
    flask_session.pop('deploy_login_token_name', None)
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

    result = backend.search(object_type="user",
                            attribute="name",
                            value=username,
                            return_type="instance")
    if not result:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    user = result[0]
    # Check if we have users secrets.
    try:
        stuff.get_site_trust_status(user.realm, user.site)
    except SiteNotTrusted:
        try:
            auth_status, \
            auth_token, \
            session_uuid = do_jwt_auth(user, password, client_ip)
        except Exception as e:
            log_msg = _("Redirected authentication failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.critical(log_msg)
            flash("Internal error while authenticating user.")
            return redirect(url_for('login', _external=True, _scheme='https'))
    else:
        try:
            auth_response = user.authenticate(auth_type="clear-text",
                                        client=config.sso_client_name,
                                        client_ip=client_ip,
                                        realm_login=False,
                                        realm_logout=False,
                                        password=password)
            auth_status = auth_response['status']
        except Exception as e:
            log_msg = _("Authentication failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.critical(log_msg)
            flash("Internal error while authenticating user.")
            return redirect(url_for('login', _external=True, _scheme='https'))
        if auth_status:
            try:
                auth_token = auth_response['token']
                session_uuid = auth_response['session']
            except KeyError:
                log_msg = _("Invalid auth response.", log=True)[1]
                logger.warning(log_msg)
                flash("Login failed.")
                return redirect(url_for('login', _external=True, _scheme='https'))
    if not auth_status:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    config.auth_token = auth_token
    # Check if token requires SSO deploy (enrollment).
    if auth_token.sso_deploy:
        redirect_target = url_for('deploy', _external=True, _scheme='https')
    else:
        redirect_target = url_for('index', _external=True, _scheme='https')
    resp = make_response(redirect(redirect_target))
    resp.set_cookie('otpme_sso_session', session_uuid,
                    httponly=True, secure=True, samesite='Lax')
    login_user(user)
    return resp

@app.route('/logout')
def logout():
    if not g.user:
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Get session UUID.
    session_uuid = request.cookies.get('otpme_sso_session')
    # Get session.
    session = backend.get_object(uuid=session_uuid)
    # Remove session cookie on logout.
    resp = make_response(redirect(url_for('login', _external=True, _scheme='https')))
    resp.set_cookie('otpme_sso_session', '', expires=0)
    # Verify session belongs to the authenticated user.
    if session and session.user_uuid != g.user.uuid:
        session = None
    # Without session we cannot logout user from otpme.
    if not session:
        logout_user()
        return resp
    # Logout user from otpme.
    try:
        g.user.authenticate(auth_type="clear-text",
                        client=config.sso_client_name,
                        realm_login=False,
                        realm_logout=False,
                        password=session.slp)
    except OTPmeException:
        flash("Failed to logout user session.")
    except Exception as e:
        flash("Internal error while logging out user.")
    # Do flask logout.
    logout_user()
    return resp

@app.route('/get_apps')
@login_required
def get_apps():
    app_data = []
    if not g.user.is_authenticated:
        return jsonify(app_data)
    result = backend.search(object_type="client",
                            attribute="sso_enabled",
                            value=True,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    if not result:
        return jsonify(app_data)
    user_ags = g.user.get_access_groups(return_type="uuid")
    for client in result:
        if not client.enabled:
            continue
        client_ag = backend.get_object(uuid=client.access_group_uuid)
        if client_ag.uuid not in user_ags:
            continue
        client_data = {
                    'app_ag'    : client_ag.name,
                    'app_name'  : client.sso_name,
                    'login_url' : client.login_url,
                    'helper_url': client.helper_url,
                    'sso_popup' : client.sso_popup,
                    }
        if client.sso_logo:
            client_data['logo_type'] = client.sso_logo['image_type']
            client_data['logo_data'] = client.sso_logo['image_data']
        app_data.append(client_data)
    return jsonify(app_data)

@app.route('/get_sotp')
@login_required
def get_sotp():
    sotp_data = None
    if not g.user.is_authenticated:
        return jsonify(sotp_data)
    try:
        auth_ag = request.args['access_group']
    except KeyError:
        return jsonify(sotp_data)
    # Get session UUID.
    session_uuid = request.cookies.get('otpme_sso_session')
    session = backend.get_object(uuid=session_uuid)
    if not session:
        return jsonify(sotp_data)
    # Verify session belongs to the authenticated user.
    if session.user_uuid != g.user.uuid:
        return jsonify(sotp_data)
    # Gen SOTP.
    result = backend.search(object_type="accessgroup",
                            attribute="name",
                            value=auth_ag,
                            return_type="uuid")
    if not result:
        return jsonify(sotp_data)
    auth_ag_uuid = result[0]
    sotp_data = sotp.gen(password_hash=session.pass_hash,
                        access_group=auth_ag_uuid)
    return jsonify(sotp_data)

def do_jwt_auth(user, password, client_ip):
    # Get authd connection.
    authd_conn = connections.get("authd",
                                realm=user.realm,
                                site=user.site,
                                username=user.name,
                                allow_untrusted=True,
                                auto_preauth=True,
                                auto_auth=False)

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
            }
    redirect_challenge = jwt.encode(payload=jwt_data,
                                    key=site_key,
                                    algorithm='RS256')
    # Get JWT from other site.
    verify_args = {
                    'username'          : user.name,
                    'password'          : password,
                    'host'              : config.host_data['name'],
                    'jwt_reason'        : jwt_reason,
                    'jwt_challenge'     : redirect_challenge,
                }
    # Send verify request.
    try:
        auth_status, \
        status_code, \
        auth_response, \
        binary_data = authd_conn.send(command="token_verify",
                                    command_args=verify_args)
    except Exception as e:
        message, log_msg = _("Failed to authenticate user: {user_name}", log=True)
        log_msg = log_msg.format(user_name=user.name)
        log_msg = f"{log_msg}: {e}"
        logger.critical(log_msg)
        message = message.format(user_name=user.name)
        raise AuthFailed(message)
    finally:
        authd_conn.close()

    if not auth_status:
        message, log_msg = _("Remote authentication failed: {user}", log=True)
        log_msg = log_msg.format(user=user.name)
        message = message.format(user=user.name)
        logger.warning(log_msg)
        raise AuthFailed(message)

    try:
        redirect_response = auth_response['jwt']
    except KeyError:
        message = _("Auth response misses JWT.")
        raise AuthFailed(message)

    # Try local JWT auth.
    auth_response = user.authenticate(auth_type="jwt",
                                client=config.sso_client_name,
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
        msg = "JWT authentication failed."
        raise AuthFailed(msg)
    sesssion_uuid = auth_response['session']
    login_token_uuid = auth_response['login_token_uuid']
    auth_token = backend.get_object(uuid=login_token_uuid)
    return auth_status, auth_token, sesssion_uuid

# ---- FIDO2 Registration (logged-in user registers a security key) ----

@app.route('/fido2/register/begin', methods=['POST'])
@login_required
def fido2_register_begin():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    # Find user's undeployed FIDO2 tokens (credential_data not set).
    user_tokens = backend.search(object_type="token",
                                attribute="owner_uuid",
                                value=g.user.uuid,
                                return_type="instance")
    fido2_token = None
    existing_credentials = []
    # Skip excludeCredentials when replacing a token (sso-deploy flow),
    # so the user can re-use the same authenticator.
    is_deploy = flask_session.get('deploy_token_name') is not None
    for token in user_tokens:
        if token.token_type != "fido2":
            continue
        if token.credential_data:
            if not is_deploy:
                cred_data = otpme_decode(token.credential_data, "hex")
                existing_credentials.append(AttestedCredentialData(cred_data))
        elif fido2_token is None:
            fido2_token = token
    if not fido2_token:
        return jsonify({"error": "No undeployed FIDO2 token found. "
                        "Create one first: otpme-token add <name> fido2"}), 400
    fido2_server = _get_fido2_server()
    user_data = {"id": g.user.name.encode(),
                "name": g.user.name,
                "displayName": g.user.name}
    create_options, reg_state = fido2_server.register_begin(
        user_data,
        credentials=existing_credentials,
        user_verification=fido2_token.uv or "discouraged",
        authenticator_attachment="cross-platform",
    )
    # Store state in Flask session.
    flask_session['fido2_reg_state'] = _serialize_fido2_state(reg_state)
    flask_session['fido2_reg_token_uuid'] = fido2_token.uuid
    return json.dumps(dict(create_options)), 200, {'Content-Type': 'application/json'}

@app.route('/fido2/register/complete', methods=['POST'])
@login_required
def fido2_register_complete():
    if not g.user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    reg_state = flask_session.pop('fido2_reg_state', None)
    token_uuid = flask_session.pop('fido2_reg_token_uuid', None)
    if not reg_state or not token_uuid:
        return jsonify({"error": "No registration in progress"}), 400
    reg_state = _deserialize_fido2_state(reg_state)
    fido2_token = backend.get_object(uuid=token_uuid)
    if not fido2_token:
        return jsonify({"error": "Token not found"}), 400
    # Verify token belongs to user.
    if fido2_token.owner_uuid != g.user.uuid:
        return jsonify({"error": "Token not found"}), 400
    registration_data = request.json
    if not registration_data:
        return jsonify({"error": "Missing registration data"}), 400
    fido2_server = _get_fido2_server()
    try:
        auth_data = fido2_server.register_complete(reg_state, registration_data)
    except Exception as e:
        log_msg = f"FIDO2 registration failed: {e}"
        logger.warning(log_msg)
        return jsonify({"error": "Registration failed"}), 400
    # Store credential data on token.
    fido2_token.credential_data = otpme_encode(auth_data.credential_data, "hex")
    fido2_token._write(callback=config.get_callback())
    log_msg = f"FIDO2 token '{fido2_token.rel_path}' registered for user '{g.user.name}'."
    logger.info(log_msg)
    return jsonify({"status": "ok", "message": "FIDO2 key registered successfully."})

# ---- FIDO2 Authentication (login with security key) ----

@app.route('/fido2/auth/begin', methods=['POST'])
def fido2_auth_begin():
    data = request.json
    if not data or 'username' not in data:
        return jsonify({"error": "Username required"}), 400
    username = str(data['username'])
    # Find user.
    result = backend.search(object_type="user",
                            attribute="name",
                            value=username,
                            return_type="instance")
    if not result:
        return jsonify({"error": "Login failed"}), 401
    user = result[0]
    # Find user's deployed FIDO2 tokens.
    user_tokens = backend.search(object_type="token",
                                attribute="owner_uuid",
                                value=user.uuid,
                                return_type="instance")
    credentials = []
    credential_token_map = {}
    for token in user_tokens:
        if token.token_type == "fido2" and token.credential_data:
            cred_data = otpme_decode(token.credential_data, "hex")
            acd = AttestedCredentialData(cred_data)
            credentials.append(acd)
            # Map base64url credential ID to token name for lookup in complete.
            cred_id_b64 = base64.urlsafe_b64encode(acd.credential_id).rstrip(b'=').decode()
            credential_token_map[cred_id_b64] = token.name
    if not credentials:
        return jsonify({"error": "Login failed"}), 401
    fido2_server = _get_fido2_server()
    request_options, auth_state = fido2_server.authenticate_begin(
        credentials,
        user_verification="preferred",
    )
    # Store state in Flask session.
    flask_session['fido2_auth_state'] = _serialize_fido2_state(auth_state)
    flask_session['fido2_auth_username'] = str(username)
    flask_session['fido2_credential_token_map'] = credential_token_map
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
    # Find user.
    result = backend.search(object_type="user",
                            attribute="name",
                            value=username,
                            return_type="instance")
    if not result:
        return jsonify({"error": "Login failed"}), 401
    user = result[0]
    # Get client IP.
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    # Build smartcard_data for auth_handler.
    rp_id = _get_fido2_rp_id()
    smartcard_data = {
        'auth_state': auth_state,
        'auth_response': json.dumps(auth_response),
        'rp_id': rp_id,
    }
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
        log_msg = f"FIDO2 authentication failed: {e}"
        logger.critical(log_msg)
        return jsonify({"error": "Login failed"}), 401
    if not auth_status:
        return jsonify({"error": "Login failed"}), 401
    try:
        auth_token_obj = auth_result['token']
        session_uuid = auth_result['session']
    except KeyError:
        return jsonify({"error": "Login failed"}), 401
    config.auth_token = auth_token_obj
    login_user(user)
    resp = make_response(jsonify({
        "status": "ok",
        "redirect": url_for('index', _external=True, _scheme='https'),
    }))
    resp.set_cookie('otpme_sso_session', session_uuid,
                    httponly=True, secure=True, samesite='Lax')
    return resp
