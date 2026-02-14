# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
from getpass import getpass
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.client import UserInteraction
from fido2.webauthn import AttestedCredentialData
from fido2.client import DefaultClientDataCollector

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import cli
from otpme.lib import config
from otpme.lib.help import command_map
#from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib. exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_smartcard_type("fido2", Fido2ClientHandler, Fido2ServerHandler)

class CliInteraction(UserInteraction):
    def __init__(self, pin=None):
        self._pin = pin

    def prompt_up(self):
        print("Touch your authenticator device now...")

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

class Fido2ClientHandler(object):
    def __init__(self, sc_type, token_rel_path, token_options=None,
        message_method=print, error_message_method=print):
        # The token type used on server side.
        self.token_type = "fido2"
        self.smartcard_type = sc_type
        self.token_rel_path = token_rel_path
        self.token_options = token_options
        self.fido2_token = None
        self.message_method = message_method
        self.error_message_method = error_message_method
        # FIXME: pam message methods from pam.py does not work with sddm
        #       and adds some strange delay.
        self.message_method = print
        self.error_message_method = print
        self.logger = config.logger

    def get_pre_deploy_args(self):
        self.detect_fido2_sc()
        pre_deploy_args = {'uv':self.fido2_token.uv}
        return pre_deploy_args

    def detect_fido2_sc(self):
        if self.fido2_token:
            return
        log_msg = _("Trying to detect connected fido2 token...", log=True)[1]
        self.logger.debug(log_msg)
        try:
            self.fido2_token = Fido2()
        except Exception as e:
            msg = str(e)
            raise OTPmeException(msg)

    def handle_deploy(self, command_handler, no_token_write=False, pre_deploy_result=None):
        # Get command syntax.
        try:
            command_syntax = command_map['token']['fido2']['deploy']['cmd']
        except:
            msg = _("Unknown token type: {type}")
            msg = msg.format(type=self.smartcard_type)
            raise OTPmeException(msg)

        # Parse command line.
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_handler.command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                exception = command_handler.get_help()
                raise ShowHelp(exception)
            elif str(e) != "":
                msg = str(e)
                exception = command_handler.get_help(message=msg)
                raise ShowHelp(exception)

        # Try to find a locally connected U2F token.
        self.detect_fido2_sc()

        create_options_json = pre_deploy_result['create_options']
        create_options = json.loads(create_options_json)
        try:
            registration_data = self.fido2_token.register(create_options)
        except Exception as e:
            msg = _("Failed to register fido2 token: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)

        # Send registration data to server.
        deploy_args = {}
        deploy_args['registration_data'] = registration_data
        return deploy_args

    def handle_preauth(self, smartcard, **kwargs):
        rp = self.token_options['rp']
        request_options = self.token_options['request_options']
        is_2f_token = self.token_options['is_2f_token']
        pass_required = self.token_options['pass_required']
        try:
            auth_response = smartcard.authenticate(rp=rp,
                                request_options=request_options)
        except Exception as e:
            msg = _("Failed to authenticate with fido2 token: {error}")
            msg = msg.format(error=e)
            raise AuthFailed(msg)
        auth_response_json = json.dumps(dict(auth_response))
        smartcard_data = {
                            'token_rel_path'    : self.token_rel_path,
                            'smartcard_type'    : self.smartcard_type,
                            'auth_response'     : auth_response_json,
                            'pass_required'     : pass_required,
                            'is_2f_token'       : is_2f_token,
                        }
        return smartcard_data

    def handle_authentication(self, smartcard, smartcard_data, **kwargs):
        rp = smartcard_data['rp']
        request_options = smartcard_data['request_options']
        try:
            auth_response = smartcard.authenticate(rp=rp,
                                request_options=request_options)
        except Exception as e:
            msg = _("Failed to authenticate with fido2 token: {error}")
            msg = msg.format(error=e)
            raise AuthFailed(msg)
        auth_response_json = json.dumps(dict(auth_response))
        return auth_response_json

    def handle_offline_token_challenge(self, **kwargs):
        return None

    def handle_offline_challenge(self, **kwargs):
        return None

    def get_smartcard_data(self, smartcard, token, password, **kwargs):
        credential_data = decode(token.credential_data, "hex")
        credentials = [AttestedCredentialData(credential_data)]
        fido2_server = token.get_fido2_server()
        request_options, \
        auth_state = fido2_server.authenticate_begin(credentials,
                                                    user_verification=token.uv)
        request_options = json.dumps(dict(request_options))
        try:
            auth_response = smartcard.authenticate(rp=token.rp,
                                request_options=request_options)
        except Exception as e:
            msg = _("Failed to authenticate with fido2 token: {error}")
            msg = msg.format(error=e)
            raise AuthFailed(msg)
        auth_response_json = json.dumps(dict(auth_response))
        smartcard_data = {
                            'auth_state'    : auth_state,
                            'auth_response' : auth_response_json,
                        }
        return smartcard_data


class Fido2ServerHandler(object):
    def __init__(self):
        self.auth_state = None
        self.token_type = None

    def handle_preauth(self, token, **kwargs):
        credential_data = decode(token.credential_data, "hex")
        credentials = [AttestedCredentialData(credential_data)]
        fido2_server = token.get_fido2_server()
        request_options, \
        self.auth_state = fido2_server.authenticate_begin(credentials,
                                                    user_verification=token.uv)
        request_options = json.dumps(dict(request_options))
        self.token_type = token.token_type
        token_options = {
                    'rp'                : token.rp,
                    'token_type'        : self.token_type,
                    'request_options'   : request_options,
                    }
        return token_options

    def prepare_authentication(self, smartcard_data):
        smartcard_data['auth_state'] = self.auth_state
        return smartcard_data

class Fido2(object):
    """ Class for fido2 tokens. """
    def __init__(self, autodetect=True, debug=False):
        # Set supported auth types
        self.otpme_auth_types = [ "fido2" ]
        # Set smartcard type
        self.type = "fido2"
        # Will be set by OTPmeClient() when doing preauth_check
        self.options = {}
        self.ctap = None
        self.dev = None
        self.pin = None
        self.uv = None
        if autodetect:
            self.detect()

    def detect(self, debug=False, print_devices=False):
        """ Try to find fido2 token """
        dev = None
        for x_dev in CtapHidDevice.list_devices():
            if dev is None:
                dev = x_dev
            if not print_devices:
                break
            msg = _("Detected fido2 smartcard: {device}")
            msg = msg.format(device=x_dev)
            print(msg)

        if dev is None and CtapPcscDevice:
            for dev in CtapPcscDevice.list_devices():
                if dev is None:
                    dev = x_dev
                if not print_devices:
                    break
                msg = _("Detected fido2 smartcard: {device}")
                msg = msg.format(device=x_dev)
                print(msg)

        if dev is None:
            raise ValueError("No suitable fido2 smartcard found!")

        self.dev = dev
        self.ctap = Ctap2(self.dev)
        info = self.ctap.info

        pin_set = info.options.get("clientPin")
        if pin_set is None:
            # Authenticator does not support PIN.
            self.pin = None
        elif pin_set:
            # Authenticator has a PIN set.
            self.pin = True
        else:
            # Authenticator supports PIN but none is set.
            self.pin = False

        # Prefer UV if supported and configured.
        if info.options.get("uv") or info.options.get("bioEnroll"):
            self.uv = "preferred"
        else:
            self.uv = "discouraged"

    def get_fido2_client(self, rp, pin=None):
        rp = f"https://{rp}"
        client_data_collector = DefaultClientDataCollector(rp)
        client = Fido2Client(self.dev,
                            client_data_collector=client_data_collector,
                            user_interaction=CliInteraction(pin=pin))
        return client

    def register(self, create_options):
        rp = create_options['publicKey']['rp']['id']
        pin = None
        if self.pin:
            pin = getpass("Enter PIN: ")
        client = self.get_fido2_client(rp, pin=pin)
        result = client.make_credential(create_options["publicKey"])
        result = json.dumps(dict(result))
        return result

    def authenticate(self, rp, request_options):
        client = self.get_fido2_client(rp)
        request_options = json.loads(request_options)
        results = client.get_assertion(request_options["publicKey"])
        auth_response = results.get_response(0)
        return auth_response
