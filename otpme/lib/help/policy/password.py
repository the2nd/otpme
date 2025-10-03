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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="password")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-policy add {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new policy'),
                                },
                },

    'pin_min_len'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy pin_min_len {policy} {pin_min_len}'),
                    'cmd'   :   '<|object|> <pin_min_len>',
                    '_help' :   {
                                    'cmd'                   : _('Set PIN min length.'),
                                },
                },

    'password_min_len'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy password_min_len {policy} {pass_min_len}'),
                    'cmd'   :   '<|object|> <password_min_len>',
                    '_help' :   {
                                    'cmd'                   : _('Set password min length.'),
                                },
                },

    'strength_checker'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy strength_checker {policy} {strength_checker}'),
                    'cmd'   :   '<|object|> <strength_checker>',
                    '_help' :   {
                                    'cmd'                   : _('Change strength checker.'),
                                },
                },

    'enable_require_number'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy enable_require_number {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable check for number in password.'),
                                },

                },

    'disable_require_number'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy disable_require_number {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable check for number in password.'),
                                },
                },

    'enable_require_upper'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy enable_require_upper {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable check for uppercase character in password.'),
                                },

                },

    'disable_require_upper'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy disable_require_upper {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable check for uppercase character in password.'),
                                },
                },

    'enable_require_lower'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy enable_require_lower {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable check for lowercase character in password.'),
                                },

                },

    'disable_require_lower'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy disable_require_lower {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable check for lowercase character in password.'),
                                },
                },

    'enable_require_special'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy enable_require_special {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable check for special character in password.'),
                                },

                },

    'disable_require_special'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy disable_require_special {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable check for special character in password.'),
                                },
                },

    'enable_strength_checker'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy enable_strength_checker {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable strength checker.'),
                                },

                },

    'disable_strength_checker'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy disable_strength_checker {policy}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable strength checker.'),
                                },
                },

    'strength_checker_opts'   : {
                    '_cmd_usage_help' : _('Usage: otpme-policy strength_checker_opts {policy} {options}'),
                    'cmd'   :   '<|object|> <options>',
                    '_help' :   {
                                    'cmd'                   : _('Change strength checker options.'),
                                },
                },
    'test'          : {
                    '_cmd_usage_help' : _('Usage: otpme-policy test [--password <password>] [--pin <pin>] {policy}'),
                    'cmd'   :   '--password :password: --pin :pin: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Test policy.'),
                                    '--password'            : _('Password to test.'),
                                    '--pin'                 : _('PIN to test.'),
                                },
                },
    }
