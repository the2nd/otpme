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
    register_cmd_help(command="auth", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-auth {command} {username} {{password|otp}|{challenge}{response}} [client] [ipaddr]",

    'verify'    : {
                    '_cmd_usage_help' : 'Usage: otpme-auth verify [--socket] [--cache <seconds>] {username} {password|otp} [client] [ipaddr]',
                    'cmd'   :   '--socket :use_socket=True: --cache :cache_seconds: <username> <password> [client] [client_ip]',
                    '_help' :   {
                                    'cmd'                   : 'verify clear-text password|otp against valid tokens of user',
                                    '--cache <seconds>'     : 'Cache auth request for given seconds..',
                                    '--socket'              : 'Connect to authd socket.',
                                },
                },


    'verify_mschap'    : {
                    '_cmd_usage_help' : 'Usage: otpme-auth verify_mschap {[--socket] username} {challenge} {response} [client] [ipaddr]',
                    'cmd'   :   '--socket :use_socket=True: <username> <mschap_challenge> <mschap_response> [client] [client_ip]',
                    '_help' :   {
                                    'cmd'                   : 'verify mschap challenge/response against valid tokens of user',
                                    '--socket'              : 'Connect to authd socket.',
                                },
                },
    }
