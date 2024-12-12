# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from fido2.utils import sha256
from fido2.ctap1 import ApduError
from fido2.hid import CtapHidDevice
#from fido2.ctap1 import SignatureData
#from fido2.ctap1 import RegistrationData

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
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

class Fido2ClientHandler(object):
    def __init__(self, sc_type, token_rel_path, token_options=None,
        message_method=print, error_message_method=print):
        # The token type used on server side.
        self.token_type = "fido2"
        self.smartcard_type = sc_type
        self.token_rel_path = token_rel_path
        self.token_options = token_options
        self.message_method = message_method
        self.error_message_method = error_message_method
        # FIXME: pam message methods from pam.py does not work with sddm
        #       and adds some strange delay.
        self.message_method = print
        self.error_message_method = print
        self.logger = config.logger

    def handle_deploy(self, command_handler, no_token_write=False, pre_deploy_result=None):
        # Get command syntax.
        try:
            command_syntax = command_map['token']['fido2']['deploy']['cmd']
        except:
            msg = (_("Unknown token type: %s") % self.smartcard_type)
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
        self.logger.debug("Trying to detect connected fido2 token...")
        try:
            fido2_token = Fido2()
        except Exception as e:
            msg = str(e)
            raise OTPmeException(msg)

        app_id = pre_deploy_result['app_id']
        app_id = app_id.encode()
        app_param = sha256(app_id)
        challenge = pre_deploy_result['challenge']
        client_param = decode(challenge, "hex")
        try:
            registration_data = fido2_token.register(client_param, app_param)
        except Exception as e:
            msg = "Failed to register fido2 token: %s" % e
            raise OTPmeException(msg)

        # Send registration data to server.
        deploy_args = {}
        deploy_args['registration_data'] = registration_data.b64
        return deploy_args

    def handle_preauth(self, smartcard, **kwargs):
        app_id = self.token_options['app_id']
        app_id = app_id.encode()
        app_id_hash = sha256(app_id)
        challenge_hash = self.token_options['challenge']
        challenge_hash = decode(challenge_hash, "hex")
        key_handle = self.token_options['key_handle']
        key_handle = decode(key_handle, "hex")
        is_2f_token = self.token_options['is_2f_token']
        pass_required = self.token_options['pass_required']
        msg = "Please press fido2 token button."
        self.message_method(msg)
        try:
            signature_data = smartcard.authenticate(client_param=challenge_hash,
                                                    app_param=app_id_hash,
                                                    key_handle=key_handle)
                                                    #check_only=False)
        except Exception as e:
            msg = "Failed to authenticate with fido2 token: %s" % e
            raise AuthFailed(_("Error authenticating fido2 token: %s") % e)
        smartcard_data = {
                            'token_rel_path'    : self.token_rel_path,
                            'smartcard_type'    : self.smartcard_type,
                            'signature_data'    : signature_data.b64,
                            'pass_required'     : pass_required,
                            'is_2f_token'       : is_2f_token,
                        }
        return smartcard_data

    def handle_authentication(self, smartcard, smartcard_data, **kwargs):
        app_id = smartcard_data['app_id']
        app_id = app_id.encode()
        app_id_hash = sha256(app_id)
        challenge_hash = smartcard_data['challenge']
        challenge_hash = decode(challenge_hash, "hex")
        key_handle = smartcard_data['key_handle']
        key_handle = decode(key_handle, "hex")
        msg = "Please press fido2 token button to test."
        self.message_method(msg)
        try:
            signature_data = smartcard.authenticate(client_param=challenge_hash,
                                                    app_param=app_id_hash,
                                                    key_handle=key_handle)
                                                    #check_only=False)
        except Exception as e:
            msg = "Failed to authenticate with fido2 token: %s" % e
            raise AuthFailed(_("Error authenticating fido2 token: %s") % e)
        return signature_data.b64

    def handle_offline_token_challenge(self, **kwargs):
        return None

    def handle_offline_challenge(self, **kwargs):
        return None

    def get_smartcard_data(self, smartcard, token, password, **kwargs):
        app_id = token.reg_app_id
        app_id = app_id.encode()
        app_id_hash = sha256(app_id)
        challenge, \
        challenge_hash, \
        challenge_hash_hex = token.gen_challenge()
        key_handle = decode(token.key_handle, "hex")
        msg = "Please press fido2 token button."
        self.message_method(msg)
        try:
            signature_data = smartcard.authenticate(client_param=challenge_hash,
                                                    app_param=app_id_hash,
                                                    key_handle=key_handle)
                                                    #check_only=False)
        except Exception as e:
            msg = "Failed to authenticate with fido2 token: %s" % e
            raise AuthFailed(_("Error authenticating fido2 token: %s") % e)
        smartcard_data = {
                            'challenge'         : challenge_hash_hex,
                            'signature_data'    : signature_data.b64,
                        }
        return smartcard_data


class Fido2ServerHandler(object):
    def __init__(self):
        self.app_id = None
        self.key_handle = None
        self.token_type = None
        self.challenge = None

    def handle_preauth(self, token, **kwargs):
        challenge = token.gen_challenge()[2]
        self.app_id = token.reg_app_id
        self.key_handle = token.key_handle
        self.token_type = token.token_type
        self.challenge = challenge
        token_options = {
                    'token_type'        : self.token_type,
                    'app_id'            : self.app_id,
                    'key_handle'        : self.key_handle,
                    'challenge'         : self.challenge,
                    }
        return token_options

    def prepare_authentication(self, smartcard_data):
        smartcard_data['challenge'] = self.challenge
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
        self.dev = None
        if autodetect:
            self.detect()

    def detect(self, debug=False, print_devices=False):
        """ Try to find fido2 token """
        from fido2.ctap1 import Ctap1
        from fido2.pcsc import CtapPcscDevice
        # Locate a device
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            logger.debug("Fido2 smartcard: Use USB HID channel.")
        else:
            try:
                dev = next(CtapPcscDevice.list_devices(), None)
            except Exception as e:
                dev = None
                msg = "Fido2 smartcard: pcscd search error: %s" % e
                logger.warning(msg)
            if dev:
                logger.debug("Fido2 smartcard: Use pcscd channel.")
        if not dev:
            raise NoSmartcardFound("No FIDO device found")
        self.dev = Ctap1(dev)
        if print_devices:
            for x in dev.list_devices():
                msg = "Detected fido2 smartcard: %s" % x
                print(msg)

    def register(self, client_param, app_param):
        msg = "Please press the token you want to register..."
        print(msg)
        while True:
            try:
                registration_data = self.dev.register(client_param, app_param)
                return registration_data
            except ApduError:
                time.sleep(0.5)
                continue
            break

    def authenticate(self, client_param, app_param, key_handle, check_only=False):
        while True:
            try:
                auth_response = self.dev.authenticate(client_param,
                                                    app_param,
                                                    key_handle)
                                                    #check_only=check_only)
                return auth_response
            except ApduError as e:
                time.sleep(0.5)
                continue
            break
