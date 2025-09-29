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
    register_cmd_help(command="session", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-session {command} [options...] [username]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-session show [-a] [--fields <f1,f2,f3>] [-z <size_limit>] [--sort-by <field>] [--reverse-sort] [search_regex]'),
                    'cmd'   :   '-a :show_all=True: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse-sort :reverse_sort=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [search_regex]',
                    '_help' :   {
                                    'cmd'                   : _('Show sessions.'),
                                    '-a'                    : _('Show all sessions.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--sort-by {field}'     : _('Sort session list by field [creation_time, expiration_time, unused_expiration_time, last_login, user]'),
                                    '--reverse-sort'        : _('Sort in reverse order'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-session list [-a] [username]'),
                    'cmd'   :   '-a :show_all=True: [username]',
                    '_help' :   {
                                    'cmd'                   : _('List sessions.'),
                                    '-a'                    : _('List all sessions.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-session del [-r -f] {session_id}'),
                    'cmd'   :   '-r :recursive=True: -f :force=True: <|objects|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete session'),
                                    '-r'                    : _('Delete recursive (with child sessions)'),
                                    '-f'                    : _('Force deletion'),
                                },
                },

    'export'    : {
                    '_cmd_usage_help' : _('Usage: otpme-session export {session_id}'),
                    'cmd'   :   '<|objects|>',
                    '_help' :   {
                                    'cmd'                   : _('Export session'),
                                },
                },
    }
