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
    register_cmd_help(command="auth", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-auth {command} {username} {{password|otp}|{challenge}{response}} [client] [ipaddr]"),

    'verify'    : {
                    '_cmd_usage_help' : _('Usage: otpme-auth verify [--socket] [--cache <seconds>] [--env-password <VARNAME>] {username} [{password|otp}] [client] [ipaddr]'),
                    'cmd'   :   '--socket :use_socket=True: --cache :cache_seconds: <username> <password> [client] [client_ip]',
                    '_help' :   {
                                    'cmd'                   : _('Verify clear-text password|otp against valid tokens of user. RECOMMENDED for production: use --env-password instead of the positional password to keep the cleartext out of argv / /proc/<pid>/cmdline.'),
                                    '--cache <seconds>'     : _('Cache auth request for given seconds. SECURITY NOTE: during the cache lifetime, account-disable, token-revoke, password-change and lockout policies do NOT take effect for cached users -- the daemon is not consulted until the entry expires. Choose a TTL that matches your tolerated revocation delay.'),
                                    '--env-password <VARNAME>' : _('Read the password from environment variable VARNAME instead of taking it positionally. Place the flag IMMEDIATELY before <username> (e.g. "otpme-auth verify --env-password User_Password alice nas1"). With FreeRADIUS rlm_exec this is the safe pattern -- each request attribute is exported as an env var, so %{User-Password} substitution into the program line (which leaks via /proc/<pid>/cmdline) can be avoided entirely.'),
                                    '--socket'              : _('Connect to authd socket.'),
                                },
                },


    'verify_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-auth verify_mschap [--socket] {username} {challenge} {response} [client] [ipaddr]'),
                    'cmd'   :   '--socket :use_socket=True: <username> <mschap_challenge> <mschap_response> [client] [client_ip]',
                    '_help' :   {
                                    'cmd'                   : _('Verify mschap challenge/response against valid tokens of user'),
                                    '--socket'              : _('Connect to authd socket.'),
                                },
                },
    }
