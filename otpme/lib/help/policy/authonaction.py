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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="authonaction")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'add_hook'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_hook {policy} {object_type} {hook}',
                    'cmd'   :   '<|object|> <object_type> <hook_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add hook when to force reauth (e.g. change_pin).',
                                },
                },

    'remove_hook'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy remove_hook {policy} {object_type} {hook}',
                    'cmd'   :   '<|object|> <object_type> <hook_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove hook',
                                },
                },

    'reauth_timeout'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy reauth_timeout {policy} {reauth_timeout}',
                    'cmd'   :   '<|object|> <reauth_timeout>',
                    '_help' :   {
                                    'cmd'                   : 'Set reauth timeout.',
                                },
                },


    'reauth_expiry'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy reauth_expiry {policy} {reauth_expiry}',
                    'cmd'   :   '<|object|> <reauth_expiry>',
                    '_help' :   {
                                    'cmd'                   : 'Set reauth expiry timeout.',
                                },
                },

    'whitelist_token'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy whitelist_token {policy} {token}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Add token to reauth whitelist.',
                                },
                },

    'unwhitelist_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy unwhitelist_token {policy} {token}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove token from reauth whitelist.',
                                },
                },


    'whitelist_role'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy whitelist_role {policy} {role}',
                    'cmd'   :   '<|object|> <role_path>',
                    '_help' :   {
                                    'cmd'                   : 'Add role to reauth whitelist.',
                                },
                },

    'unwhitelist_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy unwhitelist_role {policy} {role}',
                    'cmd'   :   '<|object|> <role_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove role from reauth whitelist.',
                                },
                },
    }
