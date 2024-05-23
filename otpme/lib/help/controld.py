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
    register_cmd_help(command="controld", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : False,
    '_usage_help'               : "Usage: otpme-controld {command}",

    '_help' :   {
                    'cmd'                               : 'Manage OTPme daemons.',
                    '-l <file>'                         : 'Log to file instead of stdout.',
                    '-t <timeout>'                      : 'Connect timeout in seconds.',
                    '-tt <timeout>'                     : 'Connection timeout in seconds.',
                    '-d'                                : 'Enable debug mode. Multiple "d" will increase debug level.',
                    '-da'                               : 'Debug function cache adds.',
                    '-dA'                               : 'Enable debug transactions.',
                    '-db'                               : 'Print when objects are read from backend.',
                    '-dc'                               : 'Print when objects are read from cache.',
                    '-dC'                               : 'Enable debug logging for client messages..',
                    '-dD'                               : 'Do not go to background and log to stdout.',
                    '-de'                               : 'Print tracebacks.',
                    '-dee'                              : 'Raise debug exceptions.',
                    '-df'                               : 'Print when reading/writing files.',
                    '-dh'                               : 'Debug function cache hits.',
                    '-dL'                               : 'Enable debug of locks.',
                    '-dm'                               : 'Print loading of OTPme modules.',
                    '-dM'                               : 'Enable function/method call tracing.',
                    '-dN'                               : 'Enable debug of network packets.',
                    '-dt'                               : 'Enable timestamps in debug output.',
                    '-dT'                               : 'Enable (debug) timing of function/method calls.',
                    '--color-logs'                      : 'Use colored logs.',
                    '--no-index-start'                  : 'Dont start/stop index.',
                    '--no-cache-start'                  : 'Dont start/stop cache.',
                    '--flush-cache'                     : 'Flush cache on daemon start.',
                    '--ignore-changed-objects'          : 'Hostd should sync objects even if they changed while syncing.',
                    '--no-sync-mem-cache'               : 'Hostd should not cache objects in memory while syncing.',
                    '--log-filter <syncd,authd>'        : 'Only print log messages for the given daemons.',
                    '--debug-daemons <authd,mgmtd>'     : 'Enable debug stuff only for the given daemons.',
                    '--debug-users <user1,user2>'       : 'Enable debug stuff only for the given users.',
                    '--debug-timing-limit <seconds>'    : 'Print warning if function/method call takes longer than <seconds>. (default 0.2)',
                    '--debug-counter-limit <call_count>': 'Print warning if function/method is called more than <call_count>.',
                    '--debug-func-caches <instance_cache,search_cache>' : 'Enable debug stuff only for the given function caches.',
                    '--disable-transactions'            : 'Disable transactions.',
                    '--keep-floating-ip'                : 'Do not deconfigure floating IP when shutting down on master node.',
                    '--version'                         : 'Show version',
                },

    'start'    : {
                    '_cmd_usage_help' : 'Usage: otpme-controld start',
                    '_help' :   {
                                    'cmd'                   : 'start OTPme daemons',
                                },
                },

    'stop'    : {
                    '_cmd_usage_help' : 'Usage: otpme-controld stop [--timeout 10 -k]',
                    'cmd'   :   '--timeout :timeout: -k :kill=True:',
                    '_help' :   {
                                    'cmd'                   : 'Stop OTPme daemons',
                                    '-k'                    : 'Send SIGKILL to OTPme daemons (after timeout)',
                                    '--timeout <60>'        : 'Timeout to wait for OTPme daemons to quit and send SIGKILL (-k)',
                                },
                },

    'restart'    : {
                    '_cmd_usage_help' : 'Usage: otpme-controld restart',
                    '_help' :   {
                                    'cmd'                   : 'restart OTPme daemons',
                                },
                },

    'reload'    : {
                    '_cmd_usage_help' : 'Usage: otpme-controld reload',
                    '_help' :   {
                                    'cmd'                   : 'send SIGHUP to daemon for config reload',
                                },
                },

    'status'    : {
                    '_cmd_usage_help' : 'Usage: otpme-controld status',
                    '_help' :   {
                                    'cmd'                   : 'show current daemon status',
                                },
                },
    }
