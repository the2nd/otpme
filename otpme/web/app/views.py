# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import time
import socket

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

from otpme.lib import sotp
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend

from otpme.lib.exceptions import *

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
    # Get session ID.
    session_id = request.cookies.get('otpme_sso_session')
    # Get session data.
    try:
        session_data = user.sso_session_data[session_id]
    except KeyError:
        return user
    try:
        auth_token_uuid = session_data['auth_token']
    except KeyError:
        return user
    result = backend.search(object_type="token",
                            attribute="uuid",
                            value=auth_token_uuid,
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
    host_ip = socket.gethostbyname(socket.gethostname())
    try:
        auth_reply = user.authenticate(auth_type="clear-text",
                                    client=config.sso_client_name,
                                    client_ip=host_ip,
                                    realm_login=False,
                                    realm_logout=False,
                                    password=password)
    except OTPmeException:
        raise
    except Exception as e:
        flash("Internal error while authenticating user.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    auth_status = auth_reply['status']
    if not auth_status:
        flash("Login failed.")
        return redirect(url_for('login', _external=True, _scheme='https'))
    config.auth_token = auth_reply['token']
    session_id = stuff.gen_secret(len=64, encoding="hex")
    user.sso_session_data[session_id] = {'slp':auth_reply['slp']}
    user.sso_session_data[session_id]['sotp_secret'] = auth_reply['session_hash']
    user.sso_session_data[session_id]['auth_token'] = config.auth_token.uuid
    user._write()
    resp = make_response(redirect(url_for('index', _external=True, _scheme='https')))
    resp.set_cookie('otpme_sso_session', session_id)
    login_user(user)
    return resp

@app.route('/logout')
def logout():
    if not g.user:
        return redirect(url_for('login', _external=True, _scheme='https'))
    # Get session ID.
    session_id = request.cookies.get('otpme_sso_session')
    # Get session data.
    try:
        session_data = g.user.sso_session_data[session_id]
    except KeyError:
        session_data = None
    # Get SLP.
    slp = None
    if session_data:
        try:
            slp = session_data['slp']
        except KeyError:
            slp = None
    # Remove session cookie on logout.
    resp = make_response(redirect(url_for('login', _external=True, _scheme='https')))
    resp.set_cookie('otpme_sso_session', '', expires=0)
    # Without SLP we cannot logout user from otpme.
    if not slp:
        logout_user()
        return resp
    # Logout user from otpme.
    try:
        g.user.authenticate(auth_type="clear-text",
                        client=config.sso_client_name,
                        realm_login=False,
                        realm_logout=False,
                        password=slp)
    except OTPmeException:
        flash("Failed to logout user session.")
    except Exception as e:
        flash("Internal error while logging out user.")
    # Remove SSO session data from user.
    g.user.sso_session_data.pop(session_id)
    g.user._write()
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
                    'app_ag':client_ag.name,
                    'app_name':client.sso_name,
                    'login_url':client.login_url,
                    'helper_url':client.helper_url,
                    'sso_popup':client.sso_popup,
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
    # Get session ID.
    session_id = request.cookies.get('otpme_sso_session')
    # Get session data.
    try:
        session_data = g.user.sso_session_data[session_id]
    except KeyError:
        session_data = None
    # Get SOTP secret.
    sotp_secret = None
    if session_data:
        try:
            sotp_secret = session_data['sotp_secret']
        except KeyError:
            sotp_secret = None

    if not sotp_secret:
        return jsonify(sotp_data)

    # Gen SOTP.
    result = backend.search(object_type="accessgroup",
                            attribute="name",
                            value=auth_ag,
                            return_type="uuid")
    if not result:
        return jsonify(sotp_data)
    auth_ag_uuid = result[0]
    epoch_time = int(str(int(time.time()))[:-1])
    sotp_data = sotp.gen(epoch_time=epoch_time,
                        password_hash=sotp_secret,
                        access_group=auth_ag_uuid)
    return jsonify(sotp_data)
