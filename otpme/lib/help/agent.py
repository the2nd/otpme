# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="agent", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-agent {command}"),

    # Only what is ours. Everything else comes from the global options,
    # which is also where it stays correct: the copy that used to be
    # here still called "-df" a file read/write long after that became
    # the option for forking.
    '_help' :   {
                    'cmd'                           : _('Manage OTPme agent'),
                    '--reneg-timeout <timeout>'     : _('Timeout when trying session renegotiation.'),
                    '-l <file>'                     : _('Log to file instead of stdout.'),
                },

    'start'    : {
                    '_cmd_usage_help' : _('Usage: otpme-agent start'),
                    '_help' :   {
                                    'cmd'                   : _('Start OTPme agent'),
                                },
                },

    'stop'    : {
                    '_cmd_usage_help' : _('Usage: otpme-agent stop [--timeout 10 -k]'),
                    'cmd'   :   '--timeout :timeout: -k :kill=True:',
                    '_help' :   {
                                    'cmd'                   : _('Stop OTPme agent'),
                                    '-k'                    : _('Send SIGKILL to OTPme agent (after timeout)'),
                                    '--timeout <60>'        : _('Timeout to wait for OTPme agent to quit and send SIGKILL (-k)'),
                                },
                },


    'restart'    : {
                    '_cmd_usage_help' : _('Usage: otpme-agent restart'),
                    '_help' :   {
                                    'cmd'                   : _('Restart OTPme agent'),
                                },
                },

    'reload'    : {
                    '_cmd_usage_help' : _('Usage: otpme-agent reload'),
                    '_help' :   {
                                    'cmd'                   : _('Send SIGHUP to agent for config reload'),
                                },
                },

    'status'    : {
                    '_cmd_usage_help' : _('Usage: otpme-agent status'),
                    '_help' :   {
                                    'cmd'                   : _('Show current agent status'),
                                },
                },
    }
