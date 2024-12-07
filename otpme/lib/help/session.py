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
    register_cmd_help(command="session", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-session {command} [options...] [username]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-session show [-a] [--fields <f1,f2,f3>] [-z <size_limit>] [--sort-by <field>] [--reverse-sort] [search_regex]',
                    'cmd'   :   '-a :show_all=True: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse-sort :reverse_sort=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [search_regex]',
                    '_help' :   {
                                    'cmd'                   : 'Show sessions.',
                                    '-a'                    : 'Show all sessions.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                    '--sort-by {field}'     : 'sort session list by field [creation_time, expiration_time, unused_expiration_time, last_login, user]',
                                    '--reverse-sort'        : 'sort in reverse order',
                                    '--raw'                 : 'Output table without any headers/borders.',
                                    '--csv'                 : 'Output table as CSV.',
                                    '--csv-sep <separator>' : 'Output table as CSV.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-session list [-a] [username]',
                    'cmd'   :   '-a :show_all=True: [username]',
                    '_help' :   {
                                    'cmd'                   : 'List sessions.',
                                    '-a'                    : 'List all sessions.',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-session del [-r -f] {session_id}',
                    'cmd'   :   '-r :recursive=True: -f :force=True: <|objects|>',
                    '_help' :   {
                                    'cmd'                   : 'delete session',
                                    '-r'                    : 'delete recursive (with child sessions)',
                                    '-f'                    : 'force deletion',
                                },
                },

    'export'    : {
                    '_cmd_usage_help' : 'Usage: otpme-session export {session_id}',
                    'cmd'   :   '<|objects|>',
                    '_help' :   {
                                    'cmd'                   : 'Export session',
                                },
                },
    }
