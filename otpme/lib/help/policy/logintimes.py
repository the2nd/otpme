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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="logintimes")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-policy add {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new policy'),
                                },
                },

    'login_times'          : {
                    '_cmd_usage_help' : _('Usage: otpme-policy login_times {policy} {login_times}'),
                    'cmd'   :   '<|object|> <login_times>',
                    '_help' :   {
                                    'cmd'                   : _('Change login times.'),
                                },
                },

    'test'          : {
                    '_cmd_usage_help' : _('Usage: otpme-policy test --object-type <object_type> --test-object <test_object> --token <token> {policy}'),
                    'cmd'   :   '--object-type ::object_type:: --test-object ::test_object:: --token ::token:: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Test policy.'),
                                    '--object-type'         : _('Object type to assume policy is assigned to.'),
                                    '--test-object'         : _('Object name/rel_path of object.'),
                                    '--token'               : _('Token to test with.'),
                                },
                },
    }
