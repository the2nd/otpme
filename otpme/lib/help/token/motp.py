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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="motp")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] {token}',
                    'cmd'   :   '-r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new token',
                                    '-r'                    : 'replace existing token and keep its UUID',
                                },
                },

    'secret'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token secret {token} [secret]',
                    'cmd'   :   '<|object|> [secret]',
                    '_help' :   {
                                    'cmd'                   : 'change token secret',
                                },
                },

    'show_secret'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token show_secret {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show tokens secret',
                                },
                },

    'pin'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token pin {token} [pin]',
                    'cmd'   :   '--generate :auto_pin=True: <|object|> ["pin"]',
                    '_help' :   {
                                    'cmd'                   : 'change token pin',
                                    '--generate'            : 'generate PIN',
                                },
                },

    'show_pin'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token show_pin {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show tokens PIN',
                                },
                },

    'gen'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token gen {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'generate token OTP',
                                },
                },

    'gen_mschap'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token gen_mschap {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'generate MSCHAP challenge/response from token OTP',
                                },
                },

    #'gen_qrcode'    : {
    #                '_cmd_usage_help' : 'Usage: otpme-token gen_qrcode {token}',
    #                'cmd'   :   '<|object|>',
    #                '_help' :   {
    #                                'cmd'                   : 'generate QRCode for automatic token configuration (e.g. yubico authenticator)',
    #                            },
    #            },

    'validity_time'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token validity_time {token} [int]',
                    'cmd'   :   '<|object|> [validity_time]',
                    '_help' :   {
                                    'cmd'                   : 'change OTP validity time',
                                },
                },

    'timedrift_tolerance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token timedrift_tolerance {token} [int]',
                    'cmd'   :   '<|object|> [timedrift_tolerance]',
                    '_help' :   {
                                    'cmd'                   : 'change OTP timedrift tolerance',
                                },
                },

    '_list_card_types'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_otp_formats'    : {
                    'cmd'   :   '<|object|>',
                },
    }
