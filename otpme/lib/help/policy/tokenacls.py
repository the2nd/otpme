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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="tokenacls")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'add_user_acl'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_user_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Add user ACL.',
                                },
                },

    'del_user_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy del_user_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Delete user ACL',
                                },
                },

    'add_token_acl'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_token_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Add token ACL.',
                                },
                },

    'del_token_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy del_token_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Delete token ACL',
                                },
                },

    'add_creator_acl'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_creator_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Add token creator ACL.',
                                },
                },

    'del_creator_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy del_creator_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Delete token creator ACL',
                                },
                },
    }
