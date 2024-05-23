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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="defaultroles")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'add_default_role'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_default_role {policy} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add role.',
                                },
                },

    'remove_default_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy remove_default_role {policy} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove role.',
                                },
                },
    }
