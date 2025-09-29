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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="otp_push")

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

    'password'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token password --generate {token} [password]'),
                    'cmd'   :   '--generate :auto_password=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : _('Change token password.'),
                                    '--generate'            : _('Generate password.'),
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
    }
