# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
The endpoints a tiqr phone talks to.

Three routes, all of them reached by the app rather than by a browser:

    GET  /tiqr/metadata  -- what the app needs to enroll an account
    POST /tiqr/enroll    -- the app delivering the secret it generated
    POST /tiqr/auth      -- the app answering an authentication challenge

Thin adapter only, the same shape as the OIDC blueprint: each route
parses the HTTP request, hands the fields to the matching ssod or authd
command, and turns the answer back into what the tiqr apps expect. All
of the logic lives in otpme.lib.protocols.server.{sso1,auth1}, because
the web layer can run on hosts that hold no OTPme objects.

None of these carry a session, so the blueprint is exempt from CSRF (see
otpme/web/app/__init__.py). What authorises them is the signed grant in
the URL for the enrollment pair, and the OCRA response itself for the
authentication one.

/tiqr is the phone and nothing else. Add browser-facing routes to
views.py, never here: the exemption covers this whole blueprint, so a
route added in the wrong place loses its CSRF protection with nothing
in its URL to show it. The browser halves of these flows live under
/login/tiqr (starting a login, polling for its result, typing the
response) and /settings/tiqr (managing enrolled phones).

These three URLs are also the ones that cannot change later: they
travel into the app inside the enrollment metadata and are what every
already-enrolled phone keeps talking to.

Protocol: https://tiqr.org/technical/protocol/
"""
from flask import Blueprint

tiqr_bp = Blueprint('tiqr', __name__)

# Imported for side-effects (route registration).
from otpme.web.app.tiqr import views  # noqa: E402,F401
