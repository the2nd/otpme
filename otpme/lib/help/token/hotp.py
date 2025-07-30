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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="hotp")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] [--no-qrcode] {token}',
                    'cmd'   :   '-r :replace=True: --no-qrcode :gen_qrcode=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new token',
                                    '-r'                    : 'replace existing token and keep its UUID',
                                    '--no-qrcode'           : 'Do not generate QRCode',
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

    'enable_pin'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_pin {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable token PIN',
                                },
                },

    'disable_pin'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_pin {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable token PIN',
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

    'gen_qrcode'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token gen_qrcode {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'generate QRCode for automatic token configuration (e.g. yubico authenticator)',
                                },
                },

    'counter_check_range'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token counter_check_range {token} [int]',
                    'cmd'   :   '<|object|> [counter_check_range]',
                    '_help' :   {
                                    'cmd'                   : 'change OTP check range',
                                },
                },

    'resync'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token resync {token} [otp]',
                    'cmd'   :   '<|object|> [otp]',
                    '_help' :   {
                                    'cmd'                   : 'resync counter based token',
                                },
                },

    'mode'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token mode {token} {mode}',
                    'cmd'   :   '<|object|> <new_mode>',
                    '_help' :   {
                                    'cmd'                   : 'Change token operation mode.',
                                },
                },

    'get_token_counter'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token get_token_counter {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Get token counter.',
                                },
                },

    '_list_modes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_card_types'    : {
                    'cmd'   :   '<|object|>',
                },
    }
