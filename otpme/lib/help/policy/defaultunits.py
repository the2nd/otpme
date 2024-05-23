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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="defaultunits")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'add_unit'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_unit {policy} {object_type} {unit}',
                    'cmd'   :   '<|object|> <object_type> <unit_path>',
                    '_help' :   {
                                    'cmd'                   : 'Add default unit.',
                                },
                },

    'remove_unit'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy remove_unit {policy} {object_type} {unit}',
                    'cmd'   :   '<|object|> <object_type> <unit_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove default unit.',
                                },
                },
    'change_unit'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy change_unit {policy} {object_type} {unit}',
                    'cmd'   :   '<|object|> <object_type> <unit_path>',
                    '_help' :   {
                                    'cmd'                   : 'Change default unit.',
                                },
                },
    }
