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
    register_cmd_help(command="controld", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-controld {command}"),

    # Only what is ours. Everything else comes from the global options,
    # which is also where it stays correct: the copy that used to be
    # here still called "-df" a file read/write long after that became
    # the option for forking.
    '_help' :   {
                    'cmd'                               : _('Manage OTPme daemons.'),
                    '-l <file>'                         : _('Log to file instead of stdout.'),
                    '--no-index-start'                  : _('Don\'t start/stop index.'),
                    '--no-cache-start'                  : _('Don\'t start/stop cache.'),
                    '--flush-cache'                     : _('Flush cache on daemon start.'),
                    '--ignore-changed-objects'          : _('Hostd should sync objects even if they changed while syncing.'),
                    '--no-sync-mem-cache'               : _('Hostd should not cache objects in memory while syncing.'),
                    '--keep-floating-ip'                : _('Do not deconfigure floating IP when shutting down on master node.'),
                },

    'start'    : {
                    '_cmd_usage_help' : _('Usage: otpme-controld start'),
                    '_help' :   {
                                    'cmd'                   : _('Start OTPme daemons'),
                                },
                },

    'stop'    : {
                    '_cmd_usage_help' : _('Usage: otpme-controld stop [--timeout 10 -k]'),
                    'cmd'   :   '--timeout :timeout: -k :kill=True:',
                    '_help' :   {
                                    'cmd'                   : _('Stop OTPme daemons'),
                                    '-k'                    : _('Send SIGKILL to OTPme daemons (after timeout)'),
                                    '--timeout <60>'        : _('Timeout to wait for OTPme daemons to quit and send SIGKILL (-k)'),
                                },
                },

    'restart'    : {
                    '_cmd_usage_help' : _('Usage: otpme-controld restart [daemon]'),
                    '_help' :   {
                                    'cmd'                   : _('Restart OTPme daemons'),
                                },
                },

    'reload'    : {
                    '_cmd_usage_help' : _('Usage: otpme-controld reload [daemon]'),
                    '_help' :   {
                                    'cmd'                   : _('Send SIGHUP to daemon for config reload'),
                                },
                },

    'status'    : {
                    '_cmd_usage_help' : _('Usage: otpme-controld status'),
                    '_help' :   {
                                    'cmd'                   : _('Show current daemon status'),
                                },
                },
    }
