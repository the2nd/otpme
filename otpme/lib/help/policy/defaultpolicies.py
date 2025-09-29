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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="defaultpolicies")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-policy add {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new policy'),
                                },
                },

    'add_default_policy'      : {
                    '_cmd_usage_help' : _('Usage: otpme-policy add_default_policy {policy} {object_type} {policy}'),
                    'cmd'   :   '<|object|> <object_type> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add default policy to be added to object of type <object_type>.'),
                                },
                },

    'remove_default_policy'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy remove_default_policy {policy} {object_type} {policy}'),
                    'cmd'   :   '<|object|> <object_type> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove default policy.'),
                                },
                },
    }
