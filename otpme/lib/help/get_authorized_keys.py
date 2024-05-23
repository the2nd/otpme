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
    register_cmd_help(command="get-authorized-keys", help_dict=cmd_help)

cmd_help = {
        '_need_command'             : False,
        '_include_global_opts'      : False,
        '_usage_help'      : "Usage: otpme-get-authorized-keys <username>",
    }
