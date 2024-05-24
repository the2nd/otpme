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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="password")

cmd_help = {
    '_need_command'             : True,
    '_usage_help'               : "Usage: otpme-token --type password {command} [token]",
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] [--enable-mschap] {token}',
                    'cmd'   :   '-r :replace=True: --enable-mschap :enable_mschap=True: <|object|>:',
                    '_help' :   {
                                    'cmd'                   : 'Add new token',
                                    '-r'                    : 'Replace existing token and keep its UUID',
                                    '--enable-mschap'       : 'Enable MSCHAP for this token',
                                },
                },

    'password'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token password [--generate] {token} [password]',
                    'cmd'   :   '--generate :auto_password=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : 'change token password',
                                    '--generate'            : 'generate password',
                                },
                },

    'upgrade_pass_hash'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token upgrade_pass_hash {token} [hash_type] [arg1=val1,arg2=val2]',
                    'cmd'   :   '<|object|> [hash_type] [{hash_args}]',
                    '_help' :   {
                                    'cmd'                   : 'Upgrade password hash.',
                                },
                },

    '2f_token'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token 2f_token {token} {2f_token}',
                    'cmd'   :   '<|object|> <second_factor_token>',
                    '_help' :   {
                                    'cmd'                   : 'change second factor token',
                                },
                },

    'enable_2f'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_2f {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable second factor token',
                                },
                },


    'disable_2f'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_2f {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable second factor token',
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


    'gen_mschap'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token gen_mschap {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'generate MSCHAP challenge/response from second factor token',
                                },
                },
    }
