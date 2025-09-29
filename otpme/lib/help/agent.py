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
    register_cmd_help(command="agent", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : False,
    '_usage_help'               : _("Usage: otpme-agent {command}"),

    '_help' :   {
                    'cmd'                           : _('Manage OTPme agent'),
                    # Agent specific options.
                    '--reneg-timeout <timeout>'     : _('Timeout when trying session renegotiation.'),
                    '--no-dns'                      : _('Do not resolve OTPme site address via DNS.'),
                    '--use-dns'                     : _('Resolve OTPme site address via DNS.'),
                    '--login-no-dns'                : _('Do not resolve OTPme login point via DNS.'),
                    '--login-use-dns'               : _('Resolve OTPme login point via DNS.'),
                    # Generic options.
                    '-l <file>'                     : _('Log to file instead of stdout.'),
                    '-t <timeout>'                  : _('Connect timeout in seconds.'),
                    '-tt <timeout>'                 : _('Connection timeout in seconds.'),
                    '-d'                            : _('Enable debug mode. Multiple "d" will increase debug level.'),
                    '-da'                           : _('Debug function cache adds.'),
                    '-db'                           : _('Print when objects are read from backend.'),
                    '-dc'                           : _('Print when objects are read from cache.'),
                    '-dC'                           : _('Enable debug logging for client messages.'),
                    '-dD'                           : _('Do not go to background and log to stdout.'),
                    '-de'                           : _('Print tracebacks.'),
                    '-dee'                          : _('Raise debug exceptions.'),
                    '-df'                           : _('Print when reading/writing files.'),
                    '-dh'                           : _('Debug function cache hits.'),
                    '-dL'                           : _('Enable debug of locks.'),
                    '-dm'                           : _('Print loading of OTPme modules.'),
                    '-dM'                           : _('Enable function/method call tracing.'),
                    '-dN'                           : _('Enable debug of network packets.'),
                    '-dt'                           : _('Enable timestamps in debug output.'),
                    '-dT'                           : _('Enable (debug) timing of function/method calls.'),
                    '--color-logs'                  : _('Use colored logs.'),
                    '--log-filter <syncd,authd>'    : _('Only print log messages for the given daemons.'),
                    '--debug-daemons <authd,mgmtd>' : _('Enable debug stuff only for the given daemons.'),
                    '--debug-users <user1,user2>'   : _('Enable debug stuff only for the given users.'),
                    '--debug-timing-limit <seconds>': _('Print warning if function/method call takes longer than <seconds>.'),
                    '--debug-counter-limit <call_count>': _('Print warning if function/method is called more than <call_count>.'),
                    '--debug-func-caches <instance_cache,search_cache>' : _('Enable debug stuff only for the given function caches.'),
                    '--version'                     : _('Show version.'),
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
