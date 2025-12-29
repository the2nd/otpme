# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from flask import g
from flask import flash
from flask import jsonify
#from flask import abort
from flask import url_for
from flask import request
from flask import redirect
from flask import make_response
from flask import render_template
from flask_login import login_user
from flask_login import logout_user
from flask_login import current_user
from flask_login import login_required

from markupsafe import escape

from otpme.web.app import lm
from otpme.web.app import app
from otpme.web.app.forms import LoginForm

from otpme.lib import jwt
from otpme.lib import sotp
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections

from otpme.lib.exceptions import *

logger = config.logger

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
    g.user = current_user

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
    return render_template("index.html", title='SSO Portal')

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
    username = escape(request.form['username'])
    password = escape(request.form['password'])

    result = backend.search(object_type="user",
                            attribute="name",
                            value=username,
                            return_type="instance")
    if not result:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    user = result[0]
    if not user:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
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
    if not auth_status:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    try:
        auth_token = auth_response['token']
        session_uuid = auth_response['session']
    except KeyError:
        log_msg = _("Invalid auth response.", log=True)[1]
        logger.warning(log_msg)
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    config.auth_token = auth_token
    resp = make_response(redirect(url_for('index', _external=True, _scheme='https')))
    resp.set_cookie('otpme_sso_session', session_uuid)
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
