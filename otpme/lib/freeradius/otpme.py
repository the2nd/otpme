# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import sys
# freeradius module copied from freeradius source tgz.
# This should only be used when testing modules. Inside freeradius, the
# 'radiusd' Python module is created by the C module and the definitions are
# automatically created.
#from otpme.lib.freeradius import radiusd

# Import radius module that is created by rlm_python when loading the otpme
# module.
import radiusd

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

otpme_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
otpme_dir = os.path.dirname(otpme_dir)
otpme_dir = os.path.dirname(otpme_dir)
sys.path.insert(0, otpme_dir)

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import mschap
from otpme.lib.classes.user import User
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

# Get logger.
logger = config.logger

def log(level, s):
  """Log function."""
  radiusd.radlog(level, 'otpme.py: %s' % s)

def instantiate(p):
    """ Module Instantiation.  0 for success, -1 for failure. """
    try:
        config.verify()
        log(radiusd.L_DBG, 'OTPme config verfied successful.')
    except Exception as e:
        log(radiusd.L_ERR, 'ERROR verifying OTPme config: %s' % e)
        return -1

    log(radiusd.L_INFO, "Instantiated OTPme module.")
    logger.info("Instantiated freeradius module.")
    return 0


def authorize(authData):
    """ Authorization """
    #log(radiusd.L_INFO, str(authData))
    #logger.info("authorize: %s" % str(authDatab))
    return radiusd.RLM_MODULE_OK


def authenticate(authData):
    """ Authentication """
    # Only for debugging.
    #log(radiusd.L_INFO, str(authData))
    #logger.info(authData)

    # Reload OTPme config if needed.
    if stuff.check_config_reload():
        config.reload()

    # Helper variables that will be used to build final log entry.
    log_username = ""
    log_token_name = ""
    log_access_group = ""
    log_client = ""
    log_client_ip = ""
    log_session_id = ""
    log_auth_type = ""
    log_auth_mode = ""
    log_auth_message = ""

    # Variables for stuff we get from rlm_python (e.g. via authData).
    username = None
    password = None
    nasid = None
    client_ip = None
    eap_type = None
    auth_type = None
    eap_message = None
    auth_challenge = None
    mschapv2_response = None

    # Indicates that request is (already) failed
    request_failed = False

    # Default return code should be reject.
    return_code = radiusd.RLM_MODULE_REJECT

    # Set empty reply_tuple and config_tuple. Both will be filled in while
    # processing the request.
    reply_tuple = ()
    config_tuple = ()

    # Get request parameters.
    for t in authData:
        if t[0] == 'User-Name':
            username = t[1]
        elif t[0] == 'MS-CHAP-User-Name':
            username = t[1]
        elif t[0] == 'User-Password':
            password = t[1]
        elif t[0] == 'NAS-Identifier':
            nasid = t[1]
        elif t[0] == 'Tmp-Octets-0':
            client_ip = re.sub('^0x', '', t[1])
            client_ip = decode(client_ip, "hex")
        elif t[0] == 'EAP-Message':
            eap_message = re.sub('^0x', '', t[1])
            logger.debug("Got EAP-Message: %s" % eap_message)
        elif t[0] == 'EAP-Type':
                if t[1] == "MS-CHAP-V2":
                    eap_type = t[1]
        elif t[0] == 'MS-CHAP-Challenge':
            # Workaround for newer freeradius versions: no EAP-Type attribute anymore??
            if not eap_type:
                eap_type = "MS-CHAP-V2"
            if t[1].startswith("0x"):
                auth_challenge = re.sub('^0x', '', t[1])
        elif t[0] == 'MS-CHAP2-Response':
            # Workaround for newer freeradius versions: no EAP-Type attribute anymore??
            if not eap_type:
                eap_type = "MS-CHAP-V2"
            if t[1].startswith("0x"):
                mschapv2_response = re.sub('^0x', '', t[1])

    if username:
        # Remove surrounding " from username.
        username = re.sub('^"', '', username)
        username = re.sub('"$', '', username)
        # Set log variable.
        log_username = username

    if password:
        # Remove surrounding " from password.
        password = re.sub('^"', '', password)
        password = re.sub('"$', '', password)

    if nasid:
        # Remove surrounding " from nasid.
        nasid = re.sub('^"', '', nasid)
        nasid = re.sub('"$', '', nasid)
        # Set log variable.
        log_client = nasid

    if client_ip:
        # Remove surrounding " from client_ip.
        client_ip = re.sub('^"', '', client_ip)
        client_ip = re.sub('"$', '', client_ip)
        # Set log variable.
        log_client_ip = client_ip


    # FIXME: clear-text requests do not have eap_type set nor do they have any
    #        other value we can get the request type from.
    # Check auth type of request and make sure we have all required parameters.
    if eap_type == "MS-CHAP-V2":
        if username and mschapv2_response and auth_challenge:
            # Set auth type.
            auth_type = "mschap"
            # Set log variable.
            log_auth_type = auth_type
        else:
            if not username:
                logger.warning("Invalid request. Request is missing "
                                "'MS-CHAP-User-Name'.")
            if not mschapv2_response:
                logger.warning("Invalid request. Request is missing "
                                "'MS-CHAP2-Response'.")
            if not auth_challenge:
                logger.warning("Invalid request. Request is missing "
                                "'MS-CHAP-Challenge'.")

            log_auth_message = "AUTH_INVALID_REQUEST"

            # Set request failed.
            request_failed = True
            # Set return code.
            return_code = radiusd.RLM_MODULE_FAIL

    # FIXME: We only support eap_type mschapv2. So we have to fail for any other request?
    elif auth_type:
        log_auth_message = "AUTH_TYPE_UNKNOWN"
        # Set request_failed.
        request_failed = True
        # Set return code.
        return_code = radiusd.RLM_MODULE_NOOP

    # If eap_type is not set we assume a clear-text request.
    else:
        # Check if we at least have username and password.
        if username and password:
            # Set auth type.
            auth_type = "clear-text"
            # Set log variable.
            log_auth_type = auth_type
        else:
            if not username:
                logger.warning("Invalid request. Request is missing 'User-Name'.")
            if not password:
                logger.warning("Invalid request. Request is missing 'User-Password'.")

            log_auth_message = "AUTH_INVALID_REQUEST"
            # Set request_failed.
            request_failed = True
            # Set return code.
            return_code = radiusd.RLM_MODULE_NOOP

    # If this is a valid request try to authenticate the user.
    if not request_failed:
        # Check if user exists.
        user = User(name=username)
        if user.exists():
            # Try to authenticate the user using clear-text password.
            if auth_type == "clear-text":
                # Try to authenticate user.
                auth_status, \
                auth_message = user.authenticate(auth_mode="auto",
                                                auth_type=auth_type,
                                                password=password,
                                                client=nasid,
                                                client_ip=client_ip)

                # Check if user was authenticated successful.
                if auth_status:
                    # Build replyTuple for rlm_python.
                    reply_tuple = (
                                ('Reply-Message', "Authentication successful"),
                                #('Session-Timeout', "30"),
                                #('Idle-Timeout', "15"),
                                #('Tunnel-Password', "otp"),
                                )

                    # Build configTuple for rlm_python.
                    config_tuple = (
                                    ('Auth-Type', 'OTPme'),
                                )

                    # Set return code.
                    return_code = radiusd.RLM_MODULE_OK
                else:
                    # Build replyTuple for rlm_python.
                    reply_tuple = (
                                    ('Reply-Message', "Authentication failed"),
                                )

                    # Build configTuple for rlm_python.
                    config_tuple = (
                                    ('Auth-Type', 'OTPme'),
                                )

                    # Set return code.
                    return_code = radiusd.RLM_MODULE_REJECT

            # Try to authenticate the user using MSCHAPv2 response from the
            # request.
            elif auth_type == "mschap":
                # Decode auth_challenge we got from MS-CHAP-Challenge attribute.
                auth_challenge_bin = decode(auth_challenge, "hex")

                # Get peer challenge from MSCHAPv2 response.
                peer_challenge = mschapv2_response[4:36]
                peer_challenge_bin = decode(peer_challenge, "hex")

                # Get peer nt response from MSCHAPv2 response.
                peer_nt_response = mschapv2_response[52:100]
                peer_nt_response_bin = decode(peer_nt_response, "hex")

                # Generate MSCHAPv1 challenge from auth_challenge and peer_challenge.
                mschapv1_challenge_bin = mschap.challenge_hash(peer_challenge_bin,
                                                                auth_challenge_bin,
                                                                username)
                mschapv1_challenge = encode(mschapv1_challenge_bin, "hex")

                # Try to authenticate the user.
                # Verify peer's nt_response with the generated mschapv1_challenge.
                auth_status, password_hash, \
                nt_key, \
                auth_message = user.authenticate(auth_mode="auto",
                                                auth_type=auth_type,
                                                challenge=mschapv1_challenge,
                                                response=peer_nt_response,
                                                client=nasid,
                                                client_ip=client_ip)

                # Check if user authenticated successful.
                if auth_status:
                    # Encode password_hash we got from User().authenticate()
                    password_hash_bin = decode(password_hash, "hex")

                    # Generate authenticator response.
                    auth_response = mschap.generate_authenticator_response(peer_nt_response_bin,
                                                                            peer_challenge_bin,
                                                                            auth_challenge_bin,
                                                                            username,
                                                                            password_hash=password_hash_bin)
                    # Generate mppe send and receive keys.
                    master_key = mschap.get_master_key(password_hash_bin,
                                                        peer_nt_response_bin)
                    master_send_key_bin = mschap.get_asymetric_start_key(master_key=master_key,
                                                                        session_key_len=16,
                                                                        is_send=False,
                                                                        is_server=True)
                    master_recv_key_bin = mschap.get_asymetric_start_key(master_key=master_key,
                                                                        session_key_len=16,
                                                                        is_send=True,
                                                                        is_server=True)

                    # Encode master send key.
                    master_send_key = encode(master_send_key_bin, "hex")
                    # Encode master recv key
                    master_recv_key = encode(master_recv_key_bin, "hex")

                    # Create success packet.
                    # http://tools.ietf.org/html/rfc2759#section-5
                    # https://www.ietf.org/rfc/rfc1994.txt
                    #  If the Value received in a Response is equal to the expected
                    #  value, then the implementation MUST transmit a CHAP packet with
                    #  the Code field set to 3 (Success).
                    success_response = "3%s" % auth_response
                    success_response_hex = encode(success_response, "hex")

                    # Debug output.
                    log(radiusd.L_DBG, "adding MS-CHAP2-Success: '%s'" % success_response)
                    log(radiusd.L_DBG, "adding MS-MPPE-Send-Key: '%s'" % master_send_key)
                    log(radiusd.L_DBG, "adding MS-MPPE-Recv-Key: '%s'" % master_recv_key)
                    log(radiusd.L_DBG, "adding MS-MPPE-Encryption-Policy: '0x00000001'")
                    log(radiusd.L_DBG, "adding MS-MPPE-Encryption-Types: '0x00000006'")

                    # Build replyTuple for rlm_python.
                    reply_tuple = (
                                    ('Reply-Message', "Authentication successful"),
                                    #('Tunnel-Password', "otp"),
                                    ('MS-CHAP2-Success', "0x%s" % success_response_hex),
                                    ('MS-MPPE-Encryption-Policy', "0x00000001"),
                                    ('MS-MPPE-Encryption-Types', "0x00000006"),
                                    ('MS-MPPE-Send-Key', "0x%s" % master_send_key),
                                    ('MS-MPPE-Recv-Key', "0x%s" % master_recv_key),
                                )

                    log(radiusd.L_DBG, "adding Auth-Type: 'MS-CHAP'")

                    # Build configTuple for rlm_python.
                    config_tuple =  (
                                        ('Auth-Type', 'MS-CHAP'),
                                    )

                    # Set return code.
                    return_code = radiusd.RLM_MODULE_OK

                # Below is, when authentication has failed.
                else:
                    # Create failure packet.
                    # http://tools.ietf.org/html/rfc2759#section-6
                    # https://www.ietf.org/rfc/rfc1994.txt
                    failure_response = str("E=691 R=0")

                    log(radiusd.L_DBG, "adding MS-CHAP-Error: '%s'"
                        % failure_response)

                    # Build replyTuple for rlm_python.
                    reply_tuple = (
                                    ('Reply-Message', "Authentication failed"),
                                    ('MS-CHAP-Error', failure_response),
                                )

                    log(radiusd.L_DBG, "adding Auth-Type: 'MS-CHAP'")

                    # Build configTuple for rlm_python.
                    config_tuple =  (
                                        ('Auth-Type', 'MS-CHAP'),
                                    )

                    # Set return code.
                    return_code = radiusd.RLM_MODULE_REJECT

        # Below is when user does not exists.
        else:
            if auth_type == "mschap":
                # Create failure packet.
                # http://tools.ietf.org/html/rfc2759#section-6
                # https://www.ietf.org/rfc/rfc1994.txt
                failure_response = str("E=691 R=0")

                # Set request failed.
                request_failed = True

                log(radiusd.L_DBG, "adding MS-CHAP-Error: '%s'"
                    % failure_response)

                # Build replyTuple for rlm_python.
                reply_tuple = (
                                ('Reply-Message', "Unknown user"),
                                ('MS-CHAP-Error', failure_response),
                            )

                log(radiusd.L_DBG, "adding Auth-Type: 'MS-CHAP'")

                # Build configTuple for rlm_python.
                config_tuple = (
                                ('Auth-Type', 'MS-CHAP'),
                            )

                # Set return code.
                return_code = radiusd.RLM_MODULE_REJECT

            else:
                # Set log message.
                log_auth_message = "AUTH_USER_UNKNOWN"
                # Set request failed.
                request_failed = True

                # Build replyTuple for rlm_python.
                reply_tuple = (
                                ('Reply-Message', "Unknown user"),
                            )

                # Build configTuple for rlm_python.
                config_tuple = (
                                ('Auth-Type', 'OTPme'),
                            )

                # Set return code.
                return_code = radiusd.RLM_MODULE_NOTFOUND


    # We only need to log a message if there was an error within this module.
    # All other errors are logged by User().authenticate().
    if request_failed:
        logger.error("%s: user=%s token=%s access_group=%s client=%s "
                    "client_ip=%s auth_mode=%s auth_type=%s session=%s"
                    % (log_auth_message,
                    log_username,
                    log_token_name,
                    log_access_group,
                    log_client,
                    log_client_ip,
                    log_auth_mode,
                    log_auth_type,
                    log_session_id))

    # Finally return from authenticate().
    return (return_code, reply_tuple, config_tuple)


def detach():
    """ Detach and clean up."""
    # TODO: May be used when daemon mode is implemented and we can cluster OTPme.
    #log(radiusd.L_DBG, 'closing cluster connnection.')
    return radiusd.RLM_MODULE_OK


# Test the module.
if __name__ == '__main__':
    instantiate(None)
    print(authenticate((('User-Name', '"testuser1"'), ('User-Password', '"test"'))))
