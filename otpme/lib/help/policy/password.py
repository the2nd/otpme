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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="password")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'pin_min_len'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy pin_min_len {policy} {pin_min_len}',
                    'cmd'   :   '<|object|> <pin_min_len>',
                    '_help' :   {
                                    'cmd'                   : 'set PIN min length',
                                },
                },

    'password_min_len'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy password_min_len {policy} {pass_min_len}',
                    'cmd'   :   '<|object|> <password_min_len>',
                    '_help' :   {
                                    'cmd'                   : 'set password min length',
                                },
                },

    'strength_checker'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy strength_checker {policy} {strength_checker}',
                    'cmd'   :   '<|object|> <strength_checker>',
                    '_help' :   {
                                    'cmd'                   : 'change strength checker',
                                },
                },

    'enable_strength_checker'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy enable_strength_checker {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable strength checker',
                                },

                },

    'disable_strength_checker'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy disable_strength_checker {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable strength checker',
                                },
                },

    'strength_checker_opts'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy strength_checker_opts {policy} {options}',
                    'cmd'   :   '<|object|> <options>',
                    '_help' :   {
                                    'cmd'                   : 'change strength checker options',
                                },
                },
    'test'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy test [--password <password>] [--pin <pin>] {policy}',
                    'cmd'   :   '--password :password: --pin :pin: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'test policy',
                                    '--password'            : 'Password to test.',
                                    '--pin'                 : 'PIN to test.',
                                },
                },
    }
