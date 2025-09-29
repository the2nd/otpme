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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="fido2")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token add [-r] {token}'),
                    'cmd'   :   '-r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new token.'),
                                    '-r'                    : _('Replace existing token and keep its UUID.'),
                                },
                },

    'deploy' : {
                    '_cmd_usage_help' : _('Usage: otpme-token deploy [-d] [-r] <token>'),
                    'cmd'   :   '-d :debug=True: -r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Deploy fido2 token.'),
                                    '-r'                    : _('Replace existing token.'),
                                    '-d'                    : _('Enable token related debug output.'),
                                },
                    },
    }
