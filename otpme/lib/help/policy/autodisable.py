# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
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
    'auto_disable'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy auto_disable {policy} {time}',
                    'cmd'   :   '<|object|> <auto_disable> -u :unused=True:',
                    '_help' :   {
                                    'cmd'                   : 'change auto disable value',
                                    '-u'                    : 'disable object if it was unused for the given time',
                                },
                },
    }
