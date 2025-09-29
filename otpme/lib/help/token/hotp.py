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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="hotp")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token add [-r] [--no-qrcode] {token}'),
                    'cmd'   :   '-r :replace=True: --no-qrcode :gen_qrcode=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new token.'),
                                    '-r'                    : _('Replace existing token and keep its UUID.'),
                                    '--no-qrcode'           : _('Do not generate QRCode.'),
                                },
                },

    'secret'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token secret {token} [secret]'),
                    'cmd'   :   '<|object|> [secret]',
                    '_help' :   {
                                    'cmd'                   : _('Change token secret.'),
                                },
                },

    'show_secret'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token show_secret {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show token\'s secret.'),
                                },
                },

    'pin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token pin {token} [pin]'),
                    'cmd'   :   '--generate :auto_pin=True: <|object|> ["pin"]',
                    '_help' :   {
                                    'cmd'                   : _('Change token PIN.'),
                                    '--generate'            : _('Generate PIN.'),
                                },
                },

    'show_pin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token show_pin {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show token\'s PIN.'),
                                },
                },

    'enable_pin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token enable_pin {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable token PIN.'),
                                },
                },

    'disable_pin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token disable_pin {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable token PIN.'),
                                },
                },

    'gen'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token gen {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Generate token OTP.'),
                                },
                },

    'gen_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token gen_mschap {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Generate MSCHAP challenge/response from token OTP.'),
                                },
                },

    'gen_qrcode'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token gen_qrcode {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Generate QRCode for automatic token configuration (e.g. yubico authenticator).'),
                                },
                },

    'counter_check_range'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token counter_check_range {token} [int]'),
                    'cmd'   :   '<|object|> [counter_check_range]',
                    '_help' :   {
                                    'cmd'                   : _('Change OTP check range.'),
                                },
                },

    'resync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token resync {token} [otp]'),
                    'cmd'   :   '<|object|> [otp]',
                    '_help' :   {
                                    'cmd'                   : _('Resync counter based token.'),
                                },
                },

    'mode'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token mode {token} {mode}'),
                    'cmd'   :   '<|object|> <new_mode>',
                    '_help' :   {
                                    'cmd'                   : _('Change token operation mode.'),
                                },
                },

    'get_token_counter'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token get_token_counter {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Get token counter.'),
                                },
                },

    '_list_modes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_card_types'    : {
                    'cmd'   :   '<|object|>',
                },
    }
