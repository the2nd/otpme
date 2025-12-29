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
    register_cmd_help(command="job", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-job {command} [job]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-job show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [job]'),
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [search_regex]',
                    '_help' :   {
                                    'cmd'                           : _('Show job(s)'),
                                    '-a'                            : _('Show all jobs.'),
                                    '-z <limit>'                    : _('Limit output size'),
                                    '--fields f1,f2,f3'             : _('Output only given fields'),
                                    '--reverse'                     : _('Reverse the output order.'),
                                    '--sort-by <attribute>'         : _('Sort output by <attribute>.'),
                                    '--raw'                         : _('Output table without any headers/borders.'),
                                    '--csv'                         : _('Output table as CSV.'),
                                    '--csv-sep <separator>'         : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-job list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List jobs.'),
                                    '-a'                        : _('List all jobs.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-job del {job_uuid}'),
                    'cmd'   :   '<|objects|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete job.'),
                                },
                },
    }
