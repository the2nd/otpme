# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="yubikey_hotp")

cmd_help = {
    '_need_command'             : True,
    'deploy' : {
                    '_cmd_usage_help' : 'Usage: otpme-token deploy [-d] [-r] [-s <slot>] [token]',
                    'cmd'   :   '-n :no_token_write=True: -s :slot: -r :replace=True: -d :debug=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'write OATH HOTP config to given yubikey slot',
                                    '-s <slot>'             : 'write new config to given slot',
                                    '-r'                    : 'Replace existing token.',
                                    '-n'                    : 'do NOT reconfigure yubikey, just add token data to OTPme token',
                                    '-d'                    : 'enable token related debug output',
                                },
                    },
    }
