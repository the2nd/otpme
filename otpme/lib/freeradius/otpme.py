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

import otpme.lib
from otpme.lib import init_otpme
from otpme.lib.otpme_config import OTPmeConfig
config = OTPmeConfig(tool_name="radius_module")
otpme.lib.config = config
# Init OTPme.
init_otpme()

from otpme.lib import backend
from otpme.lib import auth_cache
from otpme.lib.audit import get_audit_logger

from otpme.lib.exceptions import *

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

otpme_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
otpme_dir = os.path.dirname(otpme_dir)
otpme_dir = os.path.dirname(otpme_dir)
sys.path.insert(0, otpme_dir)

from otpme.lib import mschap
from otpme.lib import connections
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.register import register_module

# Get logger.
logger = config.logger

register_module("otpme.lib.protocols.otpme_client")

def log(level, s):
  """Log function."""
  radiusd.radlog(level, f'otpme.py: {s}')

def instantiate(p):
    """ Module Instantiation.  0 for success, -1 for failure. """
    try:
        config.verify()
        log_msg = _('OTPme config verfied successful.', log=True)[1]
        log(radiusd.L_DBG, log_msg)
    except Exception as e:
        log_msg = _('ERROR verifying OTPme config: {e}', log=True)[1]
        log_msg = log_msg.format(e=e)
        log(radiusd.L_ERR, log_msg)
        return -1

    log_msg = _("Instantiated OTPme module.", log=True)[1]
    log(radiusd.L_INFO, log_msg)
    log_msg = _("Instantiated freeradius module.", log=True)[1]
    logger.info(log_msg)
    return 0


def authorize(authData):
    """ Authorization """
    #log(radiusd.L_INFO, str(authData))
    #logger.info("authorize: {authData}"
    return radiusd.RLM_MODULE_OK


def authenticate(authData):
    """ Authentication """
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
        elif t[0] == 'NAS-IP-Address':
            client_ip = t[1]
        elif t[0] == 'Client-IP-Address':
            client_ip = t[1]
        elif t[0] == 'Tmp-Octets-0':
            client_ip = re.sub('^0x', '', t[1])
            client_ip = decode(client_ip, "hex")
        elif t[0] == 'EAP-Message':
            eap_message = re.sub('^0x', '', t[1])
            log_msg = _("Got EAP-Message: {eap_message}", log=True)[1]
            log_msg = log_msg.format(eap_message=eap_message)
            logger.debug(log_msg)
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

    if password:
        # Remove surrounding " from password.
        password = re.sub('^"', '', password)
        password = re.sub('"$', '', password)

    if nasid:
        # Remove surrounding " from nasid.
        nasid = re.sub('^"', '', nasid)
        nasid = re.sub('"$', '', nasid)

    if client_ip:
        # Remove surrounding " from client_ip.
        client_ip = re.sub('^"', '', client_ip)
        client_ip = re.sub('"$', '', client_ip)

    # FIXME: clear-text requests do not have eap_type set nor do they have any
    #        other value we can get the request type from.
    # Check auth type of request and make sure we have all required parameters.
    if eap_type == "MS-CHAP-V2":
        if username and mschapv2_response and auth_challenge:
            # Set auth type.
            auth_type = "mschap"
        else:
            if not username:
                log_msg = _("Invalid request. Request is missing 'MS-CHAP-User-Name'.", log=True)[1]
                logger.warning(log_msg)
            if not mschapv2_response:
                log_msg = _("Invalid request. Request is missing 'MS-CHAP2-Response'.", log=True)[1]
                logger.warning(log_msg)
            if not auth_challenge:
                log_msg = _("Invalid request. Request is missing 'MS-CHAP-Challenge'.", log=True)[1]
                logger.warning(log_msg)

            # Set request failed.
            request_failed = True
            # Set return code.
            return_code = radiusd.RLM_MODULE_FAIL

    # FIXME: We only support eap_type mschapv2. So we have to fail for any other request?
    elif auth_type:
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
        else:
            if not username:
                log_msg = _("Invalid request. Request is missing 'User-Name'.", log=True)[1]
                logger.warning(log_msg)
            if not password:
                log_msg = _("Invalid request. Request is missing 'User-Password'.", log=True)[1]
                logger.warning(log_msg)
            if not nasid and not client_ip:
                log_msg = _("Invalid request. Request is missing NAS-Identifier and NAS-IP-Address.", log=True)[1]
                logger.warning(log_msg)

            # Set request_failed.
            request_failed = True
            # Set return code.
            return_code = radiusd.RLM_MODULE_NOOP

    # If this is a valid request try to authenticate the user.
    if not request_failed:
        log_msg = _("Got valid {auth_type} radius request: user={username},client={nasid},client_ip={client_ip}", log=True)[1]
        log_msg = log_msg.format(auth_type=auth_type, username=username, nasid=nasid, client_ip=client_ip)
        logger.info(log_msg)

        # Command args for authd request.
        command_args = {
                        'username': username,
                        'password': password,
                        }

        if nasid:
            command_args['client'] = nasid
        if client_ip:
            command_args['client_ip'] = client_ip

        # Connection kwargs.
        socket_uri = config.authd_socket_path
        conn_kwargs = {}
        conn_kwargs['use_ssl'] = False
        conn_kwargs['auto_auth'] = False
        conn_kwargs['auto_preauth'] = False
        conn_kwargs['local_socket'] = True
        conn_kwargs['handle_host_auth'] = False
        conn_kwargs['handle_user_auth'] = False
        conn_kwargs['encrypt_session'] = False
        conn_kwargs['timeout'] = 60

        # Try to authenticate the user using clear-text password.
        if auth_type == "clear-text":
            if nasid:
                result = backend.search(object_type="client",
                                        attribute="name",
                                        value=nasid,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
            elif client_ip:
                result = backend.search(object_type="client",
                                        attribute="address",
                                        value=client_ip,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
            do_auth = True
            cache_auth = False
            if result:
                auth_client = result[0]
                if auth_client.auth_cache_enabled:
                    cache_auth = True
                    try:
                        auth_cache_timeout = auth_client.auth_cache_timeout
                        auth_cache.verify(auth_client.name,
                                        username,
                                        password,
                                        auth_cache_timeout)
                        auth_message, log_msg = _("User authenticated for {client} (radius) by cache: {username}", log=True)
                        auth_message = auth_message.format(client=auth_client.name, username=username)
                        log_msg = auth_message.format(username=username)
                        logger.info(log_msg)
                        # Get audit logger.
                        try:
                            audit_logger = get_audit_logger()
                        except Exception as e:
                            log_msg = _("Failed to get audit logger: {error}", log=True)[1]
                            log_msg = log_msg.format(error=e)
                            logger.warning(log_msg)
                        else:
                            if audit_logger:
                                audit_msg = f"{config.daemon_name}: {log_msg}"
                                audit_logger.info(audit_msg)
                                for x in audit_logger.handlers:
                                    x.close()
                        do_auth = False
                        auth_status = True
                    except AuthFailed:
                        do_auth = True
                    except Exception as e:
                        do_auth = True
                        log_msg = _("Auth cache failed: {error}", log=True)[1]
                        log_msg = log_msg.format(error=e)
                        logger.warning(log_msg)

            if do_auth:
                # Try to authenticate user.
                daemon_conn = connections.get("authd",
                                            realm=config.realm,
                                            site=config.site,
                                            socket_uri=socket_uri,
                                            interactive=False,
                                            **conn_kwargs)
                # Send auth request.
                log_msg = _("Sending authentication request...", log=True)[1]
                logger.debug(log_msg)
                auth_status, \
                status_code, \
                auth_reply, \
                binary_data = daemon_conn.send("verify", command_args)
                auth_message = auth_reply['message']

            # Check if user was authenticated successful.
            if auth_status:
                # Build replyTuple for rlm_python.
                reply_tuple = (
                            ('Reply-Message', _("Authentication successful")),
                            #('Session-Timeout', "30"),
                            #('Idle-Timeout', "15"),
                            #('Tunnel-Password', "otp"),
                            )

                # Build configTuple for rlm_python.
                config_tuple = (
                                ('Auth-Type', 'python_otpme'),
                            )

                log_msg = _("Radius {auth_type} request successful: user={username},client={nasid},client_ip={client_ip}", log=True)[1]
                log_msg = log_msg.format(auth_type=auth_type, username=username, nasid=nasid, client_ip=client_ip)
                logger.info(log_msg)

                # Cache auth request.
                if cache_auth:
                    auth_cache.add(auth_client.name, username, password)

                # Set return code.
                return_code = radiusd.RLM_MODULE_OK
            else:
                # Build replyTuple for rlm_python.
                reply_tuple = (
                                ('Reply-Message', _("Authentication failed")),
                            )

                # Build configTuple for rlm_python.
                config_tuple = (
                                ('Auth-Type', 'python_otpme'),
                            )

                log_msg = _("Radius {auth_type} request failed: user={username},client={nasid},client_ip={client_ip}: {auth_message}", log=True)[1]
                log_msg = log_msg.format(auth_type=auth_type, username=username, nasid=nasid, client_ip=client_ip, auth_message=auth_message)
                logger.info(log_msg)

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

            command_args['mschap_response'] = peer_nt_response
            command_args['mschap_challenge'] = mschapv1_challenge

            daemon_conn = connections.get("authd",
                                        realm=config.realm,
                                        site=config.site,
                                        socket_uri=socket_uri,
                                        interactive=False,
                                        **conn_kwargs)
            # Send auth request.
            log_msg = _("Sending MSCHAP authentication request...", log=True)[1]
            logger.debug(log_msg)
            auth_status, \
            status_code, \
            auth_reply, \
            binary_data = daemon_conn.send("verify_mschap", command_args)
            auth_message = auth_reply['message']

            # Get password hash.
            password_hash = auth_reply['password_hash']

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
                success_response = f"3{auth_response}"
                success_response_hex = encode(success_response, "hex")

                # Debug output.
                log_msg = _("adding MS-CHAP2-Success: '{success_response}'", log=True)[1]
                log_msg = log_msg.format(success_response=success_response)
                log(radiusd.L_DBG, log_msg)
                log_msg = _("adding MS-MPPE-Send-Key: '{master_send_key}'", log=True)[1]
                log_msg = log_msg.format(master_send_key=master_send_key)
                log(radiusd.L_DBG, log_msg)
                log_msg = _("adding MS-MPPE-Recv-Key: '{master_recv_key}'", log=True)[1]
                log_msg = log_msg.format(master_recv_key=master_recv_key)
                log(radiusd.L_DBG, log_msg)
                log_msg = _("adding MS-MPPE-Encryption-Policy: '0x00000001'", log=True)[1]
                log(radiusd.L_DBG, log_msg)
                log_msg = _("adding MS-MPPE-Encryption-Types: '0x00000006'", log=True)[1]
                log(radiusd.L_DBG, log_msg)

                # Build replyTuple for rlm_python.
                reply_tuple = (
                                ('Reply-Message', _("Authentication successful")),
                                #('Tunnel-Password', "otp"),
                                ('MS-CHAP2-Success', f"0x{success_response_hex}"),
                                ('MS-MPPE-Encryption-Policy', "0x00000001"),
                                ('MS-MPPE-Encryption-Types', "0x00000006"),
                                ('MS-MPPE-Send-Key', f"0x{master_send_key}"),
                                ('MS-MPPE-Recv-Key', f"0x{master_recv_key}"),
                            )

                log_msg = _("adding Auth-Type: 'MS-CHAP'", log=True)[1]
                log(radiusd.L_DBG, log_msg)

                # Build configTuple for rlm_python.
                config_tuple =  (
                                    ('Auth-Type', 'MS-CHAP'),
                                )

                log_msg = _("Radius {auth_type} request successful: user={username},client={nasid},client_ip={client_ip}", log=True)[1]
                log_msg = log_msg.format(auth_type=auth_type, username=username, nasid=nasid, client_ip=client_ip)
                logger.info(log_msg)

                # Set return code.
                return_code = radiusd.RLM_MODULE_OK

            # Below is, when authentication has failed.
            else:
                # Create failure packet.
                # http://tools.ietf.org/html/rfc2759#section-6
                # https://www.ietf.org/rfc/rfc1994.txt
                failure_response = str("E=691 R=0")

                log_msg = _("adding MS-CHAP-Error: '{failure_response}'", log=True)[1]
                log_msg = log_msg.format(failure_response=failure_response)
                log(radiusd.L_DBG, log_msg)

                # Build replyTuple for rlm_python.
                reply_tuple = (
                                ('Reply-Message', _("Authentication failed")),
                                ('MS-CHAP-Error', failure_response),
                            )

                log_msg = _("adding Auth-Type: 'MS-CHAP'", log=True)[1]
                log(radiusd.L_DBG, log_msg)

                # Build configTuple for rlm_python.
                config_tuple =  (
                                    ('Auth-Type', 'MS-CHAP'),
                                )

                log_msg = _("Radius {auth_type} request failed: user={username},client={nasid},client_ip={client_ip}: {auth_message}", log=True)[1]
                log_msg = log_msg.format(auth_type=auth_type, username=username, nasid=nasid, client_ip=client_ip, auth_message=auth_message)
                logger.info(log_msg)

                # Set return code.
                return_code = radiusd.RLM_MODULE_REJECT

    # Finally return from authenticate().
    return (return_code, reply_tuple, config_tuple)


def detach():
    """ Detach and clean up."""
    #log(radiusd.L_DBG, 'Closing authd connections...')
    return radiusd.RLM_MODULE_OK


# Test the module.
if __name__ == '__main__':
    instantiate(None)
    print(authenticate((('User-Name', '"testuser1"'), ('User-Password', '"test"'))))
