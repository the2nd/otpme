# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
HTTP routes for the tiqr apps. See otpme/web/app/tiqr/__init__.py.
"""
from flask import jsonify, request

from otpme.lib import config

from otpme.web.app import limiter
from otpme.web.app.tiqr import tiqr_bp
from otpme.web.app.views import get_authd_conn
from otpme.web.app.views import get_ssod_conn
from otpme.web.app.views import check_forwarded_for

logger = config.logger

# The apps announce which answer format they understand. Version 1 is
# plain text, version 2 is JSON; the header is absent on old clients.
PROTOCOL_HEADER = "X-TIQR-Protocol-Version"

# Result codes of protocol version 2, from the tiqr protocol docs. The
# version 1 wording is what the same outcome used to be called.
TIQR_RESULT_CODES = {
        "OK"                    : (1, "OK"),
        "INVALID_RESPONSE"      : (201, "INVALID_RESPONSE"),
        "INVALID_REQUEST"       : (202, "INVALID_REQUEST"),
        "INVALID_CHALLENGE"     : (203, "INVALID_CHALLENGE"),
        "ACCOUNT_BLOCKED"       : (204, "ACCOUNT_BLOCKED"),
        "INVALID_USERID"        : (205, "INVALID_USERID"),
        }
TIQR_ENROLL_OK = 1
TIQR_ENROLL_ERROR = 101

# Rate limits. The enrollment routes are reached with a signed grant
# that expires in minutes, the auth route with a six digit response --
# tiqr's own SECURITY.md puts the burden of limiting guesses on the
# server, and this is where the guesses arrive.
#
# This limit is the whole of that burden: there is no per-challenge
# attempt counter, because counting would mean writing cluster-visible
# state from an unauthenticated endpoint (see the note in
# otpme/lib/token/tiqr/tiqr.py). What it leaves an attacker is 30
# tries a minute against a six digit response, for the
# tiqr_challenge_expiry seconds a challenge lives -- 90 guesses per
# challenge at the three minute default, each worth one in a million.
# Lower it, or shorten the expiry, if that is not the margin you want.
_RATE_LIMIT_TIQR = "30 per minute"


def _protocol_version():
    """ Which answer format this app understands. """
    try:
        return int(request.headers.get(PROTOCOL_HEADER, 1))
    except (TypeError, ValueError):
        return 1


def _auth_reply(result, attempts_left=None, duration=None):
    """ Turn one outcome into what the app on the other end expects.

    Version 1 answers in plain text, version 2 in JSON. Both are always
    HTTP 200: the tiqr apps read the body, not the status code, and a
    4xx would just show them a network error instead of the reason.
    """
    code, text = TIQR_RESULT_CODES.get(result,
                                    TIQR_RESULT_CODES["INVALID_REQUEST"])
    if _protocol_version() >= 2:
        body = {'responseCode': code}
        if attempts_left is not None:
            body['attemptsLeft'] = attempts_left
        if duration is not None:
            body['duration'] = duration
        return jsonify(body), 200
    if result == "OK":
        return "OK", 200, {'Content-Type': 'text/plain'}
    if result == "INVALID_RESPONSE" and attempts_left is not None:
        text = f"{text}:{attempts_left}"
    # A duration is passed on in the JSON form only. Appending it to the
    # plain-text word the way attemptsLeft is appended would be a guess
    # about what version 1 apps parse, and an app that does not expect
    # the suffix would stop recognising the word itself. Without it it
    # still says the account is blocked, just not for how long.
    return text, 200, {'Content-Type': 'text/plain'}


def _normalize_auth_result(response):
    """ What authd said, as (result, duration).

    A plain string is the outcome on its own; a dict carries something
    extra with it, currently only how long a block lasts. Anything we
    do not recognise becomes the generic outcome, and its duration is
    dropped with it -- a number without a result it belongs to would
    only confuse the app.
    """
    duration = None
    if isinstance(response, dict):
        result = response.get('result')
        duration = response.get('duration')
    else:
        result = response
    if not isinstance(result, str) or result not in TIQR_RESULT_CODES:
        return "INVALID_REQUEST", None
    return result, duration


def _enroll_reply(ok):
    """ Same for the enrollment routes, which have their own codes. """
    if _protocol_version() >= 2:
        code = TIQR_ENROLL_OK if ok else TIQR_ENROLL_ERROR
        return jsonify({'responseCode': code}), 200
    body = "OK" if ok else "ERROR"
    return body, 200, {'Content-Type': 'text/plain'}


@tiqr_bp.route('/metadata', methods=['GET'])
@limiter.limit(_RATE_LIMIT_TIQR)
def metadata():
    """ The app fetching what it needs to enroll an account. """
    enrollment_key = request.args.get('enrollment_key')
    if not enrollment_key:
        return jsonify({'error': 'invalid_request'}), 400
    command_args = {'enrollment_key': enrollment_key}
    # No user to name yet: which user this is for is inside the signed
    # grant, and ssod resolves it there.
    ssod_conn = get_ssod_conn(username=None)
    try:
        status, \
        status_code, \
        response, \
        binary_data = ssod_conn.send(command="tiqr_enroll_metadata",
                                    command_args=command_args)
    except Exception as e:
        log_msg = _("tiqr metadata request failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.critical(log_msg)
        return jsonify({'error': 'server_error'}), 500
    finally:
        try:
            ssod_conn.close()
        except Exception as e:
            log_msg = _("tiqr: ssod_conn.close failed: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.debug(log_msg)
    if not status or not isinstance(response, dict):
        return jsonify({'error': 'invalid_request'}), 400
    metadata_doc = response.get('metadata')
    if not metadata_doc:
        return jsonify({'error': 'invalid_request'}), 400
    return jsonify(metadata_doc), 200


@tiqr_bp.route('/enroll', methods=['POST'])
@limiter.limit(_RATE_LIMIT_TIQR)
def enroll():
    """ The app delivering the secret it generated. """
    enrollment_secret = request.args.get('enrollment_secret')
    if not enrollment_secret:
        enrollment_secret = request.form.get('enrollment_secret')
    command_args = {
                'enrollment_secret'     : enrollment_secret,
                'secret'                : request.form.get('secret'),
                'notification_type'     : request.form.get('notificationType'),
                'notification_address'  : request.form.get('notificationAddress'),
            }
    if not command_args['enrollment_secret'] or not command_args['secret']:
        return _enroll_reply(False)
    # Creates a token, so it has to reach the master.
    ssod_conn = get_ssod_conn(username=None, mgmt=True)
    try:
        status, \
        status_code, \
        response, \
        binary_data = ssod_conn.send(command="tiqr_enroll_finish",
                                    command_args=command_args)
    except Exception as e:
        log_msg = _("tiqr enrollment failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.critical(log_msg)
        return _enroll_reply(False)
    finally:
        try:
            ssod_conn.close()
        except Exception as e:
            log_msg = _("tiqr: ssod_conn.close failed: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.debug(log_msg)
    return _enroll_reply(bool(status))


@tiqr_bp.route('/auth', methods=['POST'])
@limiter.limit(_RATE_LIMIT_TIQR)
def auth():
    """ The app answering an authentication challenge.

    The reply says only whether the response was accepted. Turning that
    into a session is the browser's poll at /login/tiqr/status, which
    runs the answer through the normal authentication path -- see
    tiqr_auth_status in auth1.py.
    """
    command_args = {
                'session_key'   : request.form.get('sessionKey'),
                'identity_id'   : request.form.get('userId'),
                'response'      : request.form.get('response'),
            }
    if not command_args['session_key'] or not command_args['response']:
        return _auth_reply("INVALID_REQUEST")
    client_ip = check_forwarded_for()[0]
    command_args['client_ip'] = client_ip
    # The identity in the request is the tiqr identity, not a name we
    # have authenticated: authd checks it against the challenge.
    authd_conn = get_authd_conn(username=command_args['identity_id'])
    try:
        status, \
        status_code, \
        response, \
        binary_data = authd_conn.send(command="tiqr_auth_response",
                                    command_args=command_args)
    except Exception as e:
        log_msg = _("tiqr authentication request failed: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.critical(log_msg)
        return _auth_reply("INVALID_REQUEST")
    finally:
        try:
            authd_conn.close()
        except Exception as e:
            log_msg = _("tiqr: authd_conn.close failed: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.debug(log_msg)
    if status:
        return _auth_reply("OK")
    result, duration = _normalize_auth_result(response)
    return _auth_reply(result, duration=duration)
