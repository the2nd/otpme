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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="fido2")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] {token}',
                    'cmd'   :   '-r :replace=True: <|object|>:',
                    '_help' :   {
                                    'cmd'                   : 'add new token',
                                    '-r'                    : 'replace existing token and keep its UUID',
                                },
                },

    'deploy' : {
                    '_cmd_usage_help' : 'Usage: otpme-token deploy [-d] [-r] <token>',
                    'cmd'   :   '-d :debug=True: -r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Deploy fido2 token.',
                                    '-r'                    : 'Replace existing token.',
                                    '-d'                    : 'Enable token related debug output.',
                                },
                    },
    }
