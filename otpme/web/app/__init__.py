# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from flask import Flask
from flask import request
from flask import session as flask_session
from flask_babel import Babel, get_locale
from flask_login import LoginManager
#from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__,
        static_url_path='/static')
        #static_folder='app/static',
        #template_folder='otpme/web/app/templates')

#app.wsgi_app = ProxyFix(
#    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
#)

# "en" is the source language and always available without a catalog.
# All other locales are discovered at startup from
#   otpme/web/app/translations/<code>/LC_MESSAGES/messages.mo
# Drop a compiled .mo into a new <code>/ directory (via `pybabel init`
# + `pybabel compile`) and the next gunicorn reload picks it up; no
# code edits required.
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

def _discover_supported_locales():
    """ Build the supported-locales list by walking the translations
    directory. We require a *compiled* messages.mo (not just .po) so a
    half-edited catalog without `pybabel compile` doesn't get exposed
    with mostly-empty strings. "en" is prepended unconditionally as the
    source language. """
    locales = ['en']
    base = os.path.join(app.root_path,
                        app.config['BABEL_TRANSLATION_DIRECTORIES'])
    try:
        for entry in sorted(os.listdir(base)):
            if entry == 'en':
                continue
            mo = os.path.join(base, entry, 'LC_MESSAGES', 'messages.mo')
            if os.path.isfile(mo):
                locales.append(entry)
    except FileNotFoundError:
        pass
    return locales

SUPPORTED_LOCALES = _discover_supported_locales()

def _select_locale():
    """ Pick the locale for the current request. Priority: the logged-in
    user's persisted language pref (stashed in the Flask session at
    login by views._stash_user_language, since the web layer can run
    on an SSO host without direct backend access), then the browser's
    Accept-Language best match against SUPPORTED_LOCALES, else the
    Babel default. The user-pref always wins so an explicit choice in
    the OTPme profile is honored regardless of which browser the user
    happens to be on. We only honor the stashed pref while the user
    is *currently* authenticated, because the Flask session cookie can
    survive past logout and would otherwise pin /login to the previous
    user's language. """
    try:
        from flask_login import current_user
        if getattr(current_user, 'is_authenticated', False):
            lang = flask_session.get('user_language')
            if lang and lang in SUPPORTED_LOCALES:
                return lang
    except Exception:
        pass
    try:
        match = request.accept_languages.best_match(SUPPORTED_LOCALES)
        if match:
            return match
    except Exception:
        pass
    return app.config['BABEL_DEFAULT_LOCALE']

babel = Babel(app, locale_selector=_select_locale)

# Flask-Babel auto-exposes `gettext`/`ngettext` as Jinja globals but
# NOT `get_locale`. Templates use it to set `<html lang="...">`, so
# expose it explicitly here. Wrapped in `str(...)` because get_locale()
# returns a Babel `Locale` object whose default __str__ is the BCP-47
# tag we want.
@app.context_processor
def _inject_get_locale():
    return {'get_locale': lambda: str(get_locale() or app.config['BABEL_DEFAULT_LOCALE'])}

lm = LoginManager()
lm.init_app(app)

from otpme.web.app import views

from otpme.web.app.oidc import oidc_bp
app.register_blueprint(oidc_bp, url_prefix='/oidc')
