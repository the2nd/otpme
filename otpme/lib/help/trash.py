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
    register_cmd_help(command="trash", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-trash {command}",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-trash show [--fields <field1,field2,field3>] [-z <size_limit>]',
                    'cmd'   :   '--fields :output_fields: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: -z :max_len:',
                    '_help' :   {
                                    'cmd'                   : 'Show trash.',
                                },
                },

    'restore'    : {
                    '_cmd_usage_help' : 'Usage: otpme-trash restore --objects <object_id_1,object_id_2> {trash_id}',
                    'cmd'   :   '--objects :[objects]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'Restore object(s).',
                                },
                },


    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-trash del {trash_id}',
                    'cmd'   :   '[|object|]',
                    '_help' :   {
                                    'cmd'                   : 'Delete entry from trash.',
                                },
                },

    'empty'    : {
                    '_cmd_usage_help' : 'Usage: otpme-trash empty}',
                    'cmd'   :   '[|object|]',
                    '_help' :   {
                                    'cmd'                   : 'Empty trash.',
                                },
                },
    }
