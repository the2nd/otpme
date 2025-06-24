# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import hashlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.messages import message
from otpme.lib.help import command_map
#from otpme.lib.messages import error_message
from otpme.lib.smartcard.yubikey.yubikey import Yubikey

from otpme.lib. exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_smartcard_type("yubikey_hotp", YubikeyHotpClientHandler, YubikeyHotpServerHandler)

class YubikeyHotpClientHandler(object):
    def __init__(self, sc_type, token_rel_path,
        message_method=print, error_message_method=print):
        # The token type used on server side.
        self.token_type = "hotp"
        self.secret_len = 40
        self.smartcard_type = sc_type
        self.token_rel_path = token_rel_path
        self.message_method = message_method
        self.error_message_method = error_message_method
        # FIXME: pam message methods from pam.py does not work with sddm
        #       and adds some strange delay.
        self.message_method = print
        self.error_message_method = print
        self.logger = config.logger

    def handle_deploy(self, command_handler, no_token_write=False, pre_deploy_result=None, **kwargs):
        # Get command syntax.
        try:
            command_syntax = command_map['token']['yubikey_hotp']['deploy']['cmd']
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

        # Try to find yubikey.
        try:
            yk = Yubikey()
        except Exception as e:
            raise OTPmeException(_("Error detecting yubikey: %s") % e)

        try:
            slot = local_command_args['slot']
        except:
            # Set default slot=1 if we got no slot from user.
            slot = 1
            local_command_args['slot'] = slot

        # FIXME: make PIN format check a function and use in token.py and here!!
        # Get token PIN from user.
        pin = None
        pin1 = "x"
        pin2 = "y"
        while True:
            pin1 = cli.read_pass(prompt="Token PIN: ")
            pin2 = cli.read_pass(prompt="Repeat PIN: ")
            if pin1 != pin2:
                message("Sorry PINs do not match!")
                continue
            pin = str(pin1)
            break

        # Generate token server secret.
        server_secret = stuff.gen_secret(self.secret_len)

        # Derive token secret form server secret and PIN.
        sha512 = hashlib.sha512()
        secret = "%s%s" % (pin, server_secret)
        secret = secret.encode()
        sha512.update(secret)
        token_secret = str(sha512.hexdigest())[0:self.secret_len]

        # Add token config to deployment args sent to server.
        deploy_args = {}
        deploy_args['server_secret'] = server_secret
        deploy_args['secret_len'] = self.secret_len
        deploy_args['secret_encoding'] = "hex"
        deploy_args['pin'] = pin

        if no_token_write:
            return deploy_args

        if not config.force:
            message(_("WARNING!!!!!!! You will lose any key/password "
                    "configured for the given slot!!!"))
            ask = cli.user_input(_("Write HOTP secret to slot '%s'?: ")
                                    % slot)
            if str(ask).lower() != "y":
                return

        # Try to write new config to yubikey.
        try:
            yk.add_oath_hotp(key=token_secret, slot=slot)
            message(_("Configuration successfully written to slot %s")
                        % slot)
        except Exception as e:
            raise OTPmeException(str(e))

        # FIXME: do we need this?
        # Workaround for http://bugs.python.org/issue24596
        try:
            del yk
        except:
            pass

        ask = cli.user_input(_("Please re-plug your yubikey now and "
                            "press RETURN."))
        return deploy_args

class YubikeyHotpServerHandler(object):
    pass

class Yubikeyhotp(Yubikey):
    """ Class for yubikey HOTP tokens. """
    # Set supported auth types
    otpme_auth_types = [ "yubikey_hotp" ]
