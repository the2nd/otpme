# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
OIDC OpenID Connect Provider for OTPme.

Layout:
    views.py  - Flask routes for all OIDC endpoints (discovery,
                jwks, authorize, token, userinfo, end_session,
                introspect, revoke). The web layer is a thin
                HTTP-to-protocol adapter; all OIDC logic lives
                in ssod (otpme.lib.protocols.server.sso1).

JWK / signing key helpers live in otpme.lib.encryption.jwk so the Site
class can use them without crossing into the web layer.

The blueprint is mounted at /oidc by default. Discovery URL becomes:
    https://<issuer>/oidc/.well-known/openid-configuration

To activate, register the blueprint in otpme/web/app/__init__.py:
    from otpme.web.app.oidc import oidc_bp
    app.register_blueprint(oidc_bp, url_prefix='/oidc')
"""
from flask import Blueprint

oidc_bp = Blueprint('oidc', __name__)

# Imported for side-effects (route registration).
from otpme.web.app.oidc import views  # noqa: E402,F401
