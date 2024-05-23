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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="totp")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] {token}',
                    'cmd'   :   '-r :replace=True: <|object|>:',
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
                    'cmd'   :   '--generate :auto_pin=True: <|object|> [pin]',
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

    'otp_format'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token otp_format {token} [otp_format]',
                    'cmd'   :   '<|object|> [otp_format]',
                    '_help' :   {
                                    'cmd'                   : 'change token OTP format',
                                },
                },

    'check_period'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token check_period {token} [int]',
                    'cmd'   :   '<|object|> [period]',
                    '_help' :   {
                                    'cmd'                   : 'change OTP check period',
                                },
                },

    'backward_drift'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token backward_drift {token} [int]',
                    'cmd'   :   '<|object|> [backward_drift]',
                    '_help' :   {
                                    'cmd'                   : 'change OTP backward drift',
                                },
                },

    'forward_drift'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token forward_drift {token} [int]',
                    'cmd'   :   '<|object|> [forward_drift]',
                    '_help' :   {
                                    'cmd'                   : 'change OTP forward drift',
                                },
                },

    'mode'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token mode {token} {mode}',
                    'cmd'   :   '<|object|> <new_mode>',
                    '_help' :   {
                                    'cmd'                   : 'change token operation mode',
                                },
                },

    '_list_modes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_card_types'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_otp_formats'    : {
                    'cmd'   :   '<|object|>',
                },
    }
