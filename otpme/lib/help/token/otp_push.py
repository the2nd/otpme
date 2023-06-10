# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="otp-push")

cmd_help = {
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
