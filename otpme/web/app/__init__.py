# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from flask import Flask
from flask import jsonify
from flask import request
from flask import session as flask_session
from flask_babel import Babel, get_locale, gettext as _gettext
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
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
    except Exception as e:
        from otpme.lib import config
        log_msg = _("Locale selector: user-pref lookup failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.debug(log_msg)
    try:
        match = request.accept_languages.best_match(SUPPORTED_LOCALES)
        if match:
            return match
    except Exception as e:
        from otpme.lib import config
        log_msg = _("Locale selector: accept-language parse failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.debug(log_msg)
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

# CSRF protection covers every state-mutating method (POST/PUT/PATCH/
# DELETE) on every route by default. HTML forms keep working via
# `form.hidden_tag()` (renders the synchronizer token as a hidden
# field); JSON-fetch callers send the same token via the
# `X-CSRFToken` header -- see static/csrf.js / fetchJSON().
csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def _handle_csrf_error(e):
    """ CSRF synchronizer-token mismatch / expiry handler.

    The default Flask-WTF response is a 400 HTML page, which
    ``fetchJSON()`` callers try to ``resp.json()`` -- producing the
    unhelpful "JSON.parse: unexpected character at line 1 column 1"
    in the browser when the user leaves a page (login, settings) open
    long enough for the CSRF token bound to their Flask session to
    expire. We sniff the ``X-CSRFToken`` request header -- always
    attached by ``fetchJSON`` for state-mutating requests -- and serve
    a JSON body the frontend's ``readJsonResponse`` helper can
    surface as a readable message ("Your session expired..."). HTML
    form posts (no ``X-CSRFToken`` header, just a hidden field) keep
    the original 400 HTML behaviour. """
    if request.headers.get('X-CSRFToken') is not None \
            or 'application/json' in request.headers.get('Accept', ''):
        payload = {
            'error': _gettext(
                "Your session expired. Please reload the page "
                "and try again."),
            'session_expired': True,
        }
        return jsonify(payload), 400
    return e.description, 400


def _ratelimit_key():
    """ Per-request IP for Flask-Limiter buckets. Uses
    views.check_forwarded_for() so X-Forwarded-For is honoured ONLY for
    requests coming from a trusted reverse-proxy IP -- spoofing the
    header from outside the proxy doesn't break the rate-limit. Lazy
    import: views is loaded after this module body so a top-level
    import would deadlock. """
    from otpme.web.app.views import check_forwarded_for
    return check_forwarded_for()[0]


def _build_limiter_storage_uri():
    """ Build a Flask-Limiter storage URI from OTPme's configured cache
    backend (redis or memcachedb on a Unix socket). Sharing storage with
    the cache keeps counters consistent across gunicorn workers; in-
    memory (per-worker buckets) loosens the effective limit by the
    worker count.

    Falls back to ``memory://`` if detection fails -- the limit then
    becomes per-worker but the Flask-Limiter "production warning"
    is silenced (we've explicitly opted in). """
    try:
        from otpme.lib import config
        cache_module = config.get_cache_module()
        socket = cache_module.get_socket()
        if config.cache_type == 'redis':
            return f"redis+unix://{socket}"
        if config.cache_type == 'memcachedb':
            return f"memcached://{socket}"
    except Exception as e:
        try:
            from otpme.lib import config
            log_msg = _("Rate-limiter: could not build cache storage URI: {error}",
                        log=True)[1]
            log_msg = log_msg.format(error=e)
            config.logger.debug(log_msg)
        except Exception:
            pass
    return "memory://"


# Rate-limiter: protects credential-bearing endpoints (login,
# fido2_auth_begin) from brute-force and DoS. Per-IP keys via
# _ratelimit_key. Storage URI is built from OTPme's cache backend so
# counters are shared across gunicorn workers (and across SSO hosts
# if they target the same cache).
limiter = Limiter(
    key_func=_ratelimit_key,
    app=app,
    # No global default -- per-route decorators express intent. Keeps
    # static / GET-only endpoints unrestricted.
    default_limits=[],
    headers_enabled=True,
    strategy='fixed-window',
    storage_uri=_build_limiter_storage_uri(),
)

from otpme.web.app import views

from otpme.web.app.oidc import oidc_bp
app.register_blueprint(oidc_bp, url_prefix='/oidc')

# OIDC endpoints are API/spec-driven: RPs authenticate via client
# credentials (/token, /introspect, /revoke) or bearer tokens
# (/userinfo); /authorize uses the OAuth `state` parameter as its CSRF
# defense; /end_session uses `id_token_hint`. Requiring a Flask session
# CSRF token would break standards-compliant clients. The one browser-
# driven form (consent) ships with its own per-render nonce stored
# server-side in flask_session (see oidc/views.py _oidc_consent_nonce).
csrf.exempt(oidc_bp)
