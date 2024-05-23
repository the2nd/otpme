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
    register_cmd_help(command="agent", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : False,
    '_usage_help'               : "Usage: otpme-agent {command}",

    '_help' :   {
                    'cmd'                           : 'Manage OTPme agent',
                    # Agent specific options.
                    '--reneg-timeout <timeout>'     : 'Timeout when trying session renegotiation.',
                    '--no-dns'                      : 'Do not resolve OTPme site address via DNS.',
                    '--use-dns'                     : 'Resolve OTPme site address via DNS.',
                    '--login-no-dns'                : 'Do not resolve OTPme login point via DNS.',
                    '--login-use-dns'               : 'Resolve OTPme login point via DNS.',
                    # Generic options.
                    '-l <file>'                     : 'Log to file instead of stdout.',
                    '-t <timeout>'                  : 'Connect timeout in seconds.',
                    '-tt <timeout>'                 : 'Connection timeout in seconds.',
                    '-d'                            : 'Enable debug mode. Multiple "d" will increase debug level.',
                    '-da'                           : 'Debug function cache adds.',
                    '-db'                           : 'Print when objects are read from backend.',
                    '-dc'                           : 'Print when objects are read from cache.',
                    '-dC'                           : 'Enable debug logging for client messages..',
                    '-dD'                           : 'Do not go to background and log to stdout.',
                    '-de'                           : 'Print tracebacks.',
                    '-dee'                          : 'Raise debug exceptions.',
                    '-df'                           : 'Print when reading/writing files.',
                    '-dh'                           : 'Debug function cache hits.',
                    '-dL'                           : 'Enable debug of locks.',
                    '-dm'                           : 'Print loading of OTPme modules.',
                    '-dM'                           : 'Enable function/method call tracing.',
                    '-dN'                           : 'Enable debug of network packets.',
                    '-dt'                           : 'Enable timestamps in debug output.',
                    '-dT'                           : 'Enable (debug) timing of function/method calls.',
                    '--color-logs'                  : 'Use colored logs.',
                    '--log-filter <syncd,authd>'    : 'Only print log messages for the given daemons.',
                    '--debug-daemons <authd,mgmtd>' : 'Enable debug stuff only for the given daemons.',
                    '--debug-users <user1,user2>'   : 'Enable debug stuff only for the given users.',
                    '--debug-timing-limit <seconds>': 'Print warning if function/method call takes longer than <seconds>.',
                    '--debug-counter-limit <call_count>': 'Print warning if function/method is called more than <call_count>.',
                    '--debug-func-caches <instance_cache,search_cache>' : 'Enable debug stuff only for the given function caches.',
                    '--disable-transactions'        : 'Disable transactions.',
                    '--version'                     : 'Show version.',
                },

    'start'    : {
                    '_cmd_usage_help' : 'Usage: otpme-agent start',
                    '_help' :   {
                                    'cmd'                   : 'start OTPme agent',
                                },
                },

    'stop'    : {
                    '_cmd_usage_help' : 'Usage: otpme-agent stop [--timeout 10 -k]',
                    'cmd'   :   '--timeout :timeout: -k :kill=True:',
                    '_help' :   {
                                    'cmd'                   : 'Stop OTPme agent',
                                    '-k'                    : 'Send SIGKILL to OTPme agent (after timeout)',
                                    '--timeout <60>'        : 'Timeout to wait for OTPme agent to quit and send SIGKILL (-k)',
                                },
                },


    'restart'    : {
                    '_cmd_usage_help' : 'Usage: otpme-agent restart',
                    '_help' :   {
                                    'cmd'                   : 'restart OTPme agent',
                                },
                },

    'reload'    : {
                    '_cmd_usage_help' : 'Usage: otpme-agent reload',
                    '_help' :   {
                                    'cmd'                   : 'send SIGHUP to agent for config reload',
                                },
                },

    'status'    : {
                    '_cmd_usage_help' : 'Usage: otpme-agent status',
                    '_help' :   {
                                    'cmd'                   : 'show current agent status',
                                },
                },
    }
