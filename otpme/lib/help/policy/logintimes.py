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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="logintimes")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'login_times'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy login_times {policy} {login_times}',
                    'cmd'   :   '<|object|> <login_times>',
                    '_help' :   {
                                    'cmd'                   : 'Change login times.',
                                },
                },
    'add_token'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_token {policy} {token_path}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Add token to policy.',
                                },
                },
    'remove_token'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy remove_token {policy} {token_path}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove token to policy.',
                                },
                },
    'add_role'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_role {policy} {role_name}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add role to policy.',
                                },
                },
    'remove_role'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy remove_role {policy} {role_name}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove role to policy.',
                                },
                },
    'enable_ignore_empty'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy enable_ignore_empty {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable ignore on empty feature.',
                                },
                },
    'disable_ignore_empty'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy disable_ignore_empty {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable ignore on empty feature.',
                                },
                },
    }
