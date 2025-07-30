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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="otp_push")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] {token}',
                    'cmd'   :   '-r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new token',
                                    '-r'                    : 'replace existing token and keep its UUID',
                                },
                },

    'password'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token password --generate {token} [password]',
                    'cmd'   :   '--generate :auto_password=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : 'change token password',
                                    '--generate'            : 'generate password',
                                },
                },

    'enable_mschap'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_mschap {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable MSCHAP authentication',
                                },
                },

    'disable_mschap'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_mschap {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable MSCHAP authentication',
                                },
                },
    }
