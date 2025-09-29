# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="yubikey_hotp")

cmd_help = {
    '_need_command'             : True,
    'deploy' : {
                    '_cmd_usage_help' : _('Usage: otpme-token deploy [-d] [-r] [-s <slot>] [token]'),
                    'cmd'   :   '-n :no_token_write=True: -s :slot: -r :replace=True: -d :debug=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Write OATH HOTP config to given yubikey slot.'),
                                    '-s <slot>'             : _('Write new config to given slot.'),
                                    '-r'                    : _('Replace existing token.'),
                                    '-n'                    : _('Do NOT reconfigure yubikey, just add token data to OTPme token.'),
                                    '-d'                    : _('Enable token related debug output.'),
                                },
                    },
    }
