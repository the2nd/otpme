# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.otp.otpme import otpme
from otpme.lib.messages import message
from otpme.lib.help import command_map
#from otpme.lib.messages import error_message
from otpme.lib.smartcard.yubikey.yubikey import Yubikey

from otpme.lib. exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_smartcard_type("yubikey_hmac", YubikeyHmacClientHandler, YubikeyHmacServerHandler)

class YubikeyHmacClientHandler(object):
    def __init__(self, sc_type, token_rel_path, token_options=None,
        message_method=print, error_message_method=print):
        # The token type used on server side.
        self.token_type = "yubikey_hmac"
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

    def handle_deploy(self, command_handler, no_token_write=False, **kwargs):
        # Get command syntax.
        try:
            command_syntax = command_map['token']['yubikey_hmac']['deploy']['cmd']
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

        # Try to find yubikey
        try:
            yk = Yubikey()
        except Exception as e:
            raise OTPmeException(_("Error detecting yubikey: %s") % e)

        try:
            slot = local_command_args['slot']
        except:
            # Set default slot=2 if we got no slot from user
            slot = 2
            local_command_args['slot'] = slot

        if not no_token_write:
            if not config.force:
                message(_("WARNING!!!!!!! You will lose any key/password "
                        "configured for the given slot!!!"))
                ask = cli.user_input(_("Write HMAC-SHA1 secret to slot '%s'?: ") % slot)
                if str(ask).lower() != "y":
                    return

            # Try to write new config to yubikey
            try:
                hmac_secret = yk.add_hmac_sha1(**local_command_args)
            except Exception as e:
                raise OTPmeException(str(e))

            message(_("Configuration successfully written to slot %s") % slot)

        # FIXME: make password format check a function and use in token.py and here!!
        # Get token password from user.
        token_pass = None
        token_pass1 = "x"
        token_pass2 = "y"
        while True:
            token_pass1 = cli.read_pass(prompt="Token password: ")
            token_pass2 = cli.read_pass(prompt="Repeat password: ")
            if token_pass1 != token_pass2:
                message("Sorry passwords do not match!")
            else:
                token_pass = token_pass1
                break

        # Get token serial number as smartcard ID.
        try:
            smartcard_id = yk.get_serial()
        except Exception as e:
            msg = (_("Unable to get serial number: %s") % e)
            raise OTPmeException(msg)

        # Generate challenge used to generate token secret on client site.
        hmac_challenge = stuff.gen_secret(len=32)

        # Generate HMAC ID to identify token.
        id_challenge = stuff.gen_md5("HMAC_ID:%s" % token_pass)
        hmac_id = yk.send_challenge(challenge=id_challenge,
                                    **local_command_args)

        # Generate token secret from HMAC challenge and password.
        secret_challenge = "%s%s" % (hmac_challenge, token_pass)
        secret = yk.send_challenge(challenge=secret_challenge,
                                    **local_command_args)

        # Add token config to deployment args sent to server.
        deploy_args = {}
        deploy_args['hmac_challenge'] = hmac_challenge
        deploy_args['smartcard_id'] = smartcard_id
        deploy_args['hmac_id'] = hmac_id
        deploy_args['secret'] = secret
        deploy_args['slot'] = slot

        if not no_token_write:
            # Print new HMAC secret.
            message(_("New HMAC-SHA1 secret: %s") % hmac_secret)

        return deploy_args

    def handle_preauth(self, smartcard, password):
        # Get yubikey slot.
        slot = self.token_options['slot']
        # Get HMAC challenge.
        challenge = self.token_options['challenge']
        # Get otp len.
        otp_len = self.token_options['otp_len']
        # Generate token secret from HMAC challenge and password.
        secret_challenge = "%s%s" % (challenge, password)
        # Try to get HMAC response (otpme token secret) from
        # smartcard.
        try:
            secret = smartcard.send_challenge(slot=slot,
                                    challenge=secret_challenge)
        except OTPmeException as e:
            msg = (_("Error sending HMAC challenge to smartcard: %s") % e)
            raise AuthFailed(msg)
        # If we got the token secret we can generate a OTPme
        # OTP as response.
        epoch_time = time.time()
        otp_epoch_time = int(str(int(epoch_time))[:-1])
        otp = otpme.generate(epoch_time=otp_epoch_time,
                                secret=secret, otp_count=1,
                                otp_len=otp_len)
        smartcard_data = self.token_options.copy()
        smartcard_data['otp'] = otp
        smartcard_data['token_rel_path'] = self.token_rel_path
        return smartcard_data

    def handle_authentication(self, smartcard, smartcard_data,
        password, peer_time_diff, **kwargs):
        # Get yubikey slot.
        slot = smartcard_data['slot']
        # Get HMAC challenge.
        challenge = smartcard_data['challenge']
        # Get otp len.
        otp_len = smartcard_data['otp_len']
        # Generate token secret from HMAC challenge and password.
        secret_challenge = "%s%s" % (challenge, password)
        # Try to get HMAC response (otpme token secret) from
        # smartcard.
        try:
            secret = smartcard.send_challenge(slot=slot,
                                    challenge=secret_challenge)
        except OTPmeException as e:
            msg = (_("Error sending HMAC challenge to smartcard: %s") % e)
            raise AuthFailed(msg)
        # If we got the token secret we can generate a OTPme
        # OTP as response.
        epoch_time = time.time() - peer_time_diff
        otp_epoch_time = int(str(int(epoch_time))[:-1])
        response = otpme.generate(epoch_time=otp_epoch_time,
                                secret=secret, otp_count=1,
                                otp_len=otp_len)
        return response

    def handle_offline_token_challenge(self, smartcard, password, enc_challenge, **kwargs):
        # Try to generate offline token encryption passphrase.
        enc_pass_challenge = "%s%s" % (enc_challenge, password)
        try:
            enc_pass = smartcard.send_challenge(challenge=enc_pass_challenge)
        except Exception as e:
            msg = (_("Error sending offline encryption HMAC "
                    "challenge to smartcard: %s") % e)
            raise OTPmeException(msg)
        return enc_pass

    def handle_offline_challenge(self, smartcard, token, password, enc_challenge, **kwargs):
        # Generate HMAC ID to identifiy token.
        id_challenge = stuff.gen_md5("HMAC_ID:%s" % password)
        try:
            hmac_id = smartcard.send_challenge(challenge=id_challenge)
        except Exception as e:
            msg = (_("Error sending HMAC ID challenge to smartcard: %s")
                    % e)
            raise OTPmeException(msg)
        # Check if we found the correct smartcard.
        if hmac_id != token.hmac_id:
            msg = (_("Found wrong smartcard or wrong password "
                    "given: %s") % self.smartcard.type)
            raise AuthFailed(msg)
        # Try to generate offline token encryption passphrase.
        enc_pass_challenge = enc_challenge + password
        try:
            enc_pass = smartcard.send_challenge(challenge=enc_pass_challenge,
                                                    slot=token.slot)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error sending offline encryption HMAC "
                    "challenge to smartcard: %s") % e)
            raise OTPmeException(msg)
        return enc_pass

    def get_smartcard_data(self, smartcard, token, password, **kwargs):
        # Generate HMAC ID to identifiy token.
        id_challenge = stuff.gen_md5("HMAC_ID:%s" % password)
        try:
            hmac_id = smartcard.send_challenge(challenge=id_challenge)
        except Exception as e:
            msg = (_("Error sending HMAC ID challenge to smartcard: %s")
                    % e)
            raise OTPmeException(msg)
        # Check if we found the correct smartcard.
        if hmac_id != token.hmac_id:
            msg = (_("Found wrong smartcard or wrong password "
                    "given: %s") % self.smartcard.type)
            raise AuthFailed(msg)

        # Generate token secret from HMAC challenge and password.
        secret_challenge = token.hmac_challenge + password
        try:
            secret = smartcard.send_challenge(challenge=secret_challenge,
                                                    slot=token.slot)
        except Exception as e:
            msg = (_("Error sending secret challenge to smartcard: "
                    "%s: %s") % (self.smartcard.type, e))
            raise OTPmeException(msg)

        # If we got the token secret we can generate a OTPme OTP to verify
        # the offline token.
        otp = otpme.generate(secret=secret,
                            otp_count=1,
                            otp_len=token.otp_len)
        smartcard_data = {
                        'otp'           : otp,
                        'smartcard_id'  : token.smartcard_id,
                        }
        return smartcard_data

class YubikeyHmacServerHandler(object):
    def handle_preauth(self, token):
        token_options = {
                    'token_type'        : token.token_type,
                    'smartcard_id'      : token.smartcard_id,
                    'challenge'         : token.hmac_challenge,
                    'otp_len'           : token.otp_len,
                    'slot'              : token.slot,
                    'pass_required'     : True,
                    }
        return token_options

    def prepare_authentication(self, smartcard_data):
        return smartcard_data

class Yubikeyhmac(Yubikey):
    """ Class for yubikey HMAC tokens. """
    # Set supported auth types
    otpme_auth_types = [ "yubikey_hmac" ]

