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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="password")

cmd_help = {
    '_need_command'             : True,
    '_usage_help'               : _("Usage: otpme-token --type password {command} [token]"),
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token --type password add [-r] [--password <password>] [--enable-mschap] {token}'),
                    'cmd'   :   '-r :replace=True: --password :password: --enable-mschap :enable_mschap=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new token.'),
                                    '-r'                    : _('Replace existing token and keep its UUID.'),
                                    '--password'            : _('Set token password.'),
                                    '--enable-mschap'       : _('Enable MSCHAP for this token.'),
                                },
                },

    'password'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token password [--generate] {token} [password]'),
                    'cmd'   :   '--generate :auto_password=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : _('Change token password.'),
                                    '--generate'            : _('Generate password.'),
                                },
                },

    'upgrade_pass_hash'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token upgrade_pass_hash {token} [hash_type] [arg1=val1,arg2=val2]'),
                    'cmd'   :   '<|object|> [hash_type] [{hash_args}]',
                    '_help' :   {
                                    'cmd'                   : _('Upgrade password hash.'),
                                },
                },

    '2f_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token 2f_token {token} {2f_token}'),
                    'cmd'   :   '<|object|> <second_factor_token>',
                    '_help' :   {
                                    'cmd'                   : _('Change second factor token.'),
                                },
                },

    'enable_2f'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token enable_2f {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable second factor token.'),
                                },
                },


    'disable_2f'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token disable_2f {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable second factor token.'),
                                },
                },




    'enable_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token enable_mschap {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable MSCHAP authentication.'),
                                },
                },


    'disable_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token disable_mschap {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable MSCHAP authentication.'),
                                },
                },


    'gen_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token gen_mschap {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Generate MSCHAP challenge/response from second factor token.'),
                                },
                },
    }
