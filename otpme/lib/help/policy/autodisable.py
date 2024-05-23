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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="autodisable")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'auto_disable'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy auto_disable {policy} {time}',
                    'cmd'   :   '<|object|> <auto_disable> -u :unused=True:',
                    '_help' :   {
                                    'cmd'                   : 'Change auto disable value (e.g "1d" or "09:53 13.06.2023").',
                                    '-u'                    : 'Disable object if it was unused for the given time.',
                                },
                },
    }
