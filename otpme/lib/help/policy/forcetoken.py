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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="forcetoken")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'force_token_types'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy force_token_types {policy} {token_types}',
                    'cmd'   :   '<|object|> <token_types>',
                    '_help' :   {
                                    'cmd'                   : 'change list with allowed token types',
                                },
                },

    'force_pass_types'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy force_pass_types {policy} {pass_types}',
                    'cmd'   :   '<|object|> <pass_types>',
                    '_help' :   {
                                    'cmd'                   : 'change list with allowed pass types',
                                },
                },
    }
