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
    register_cmd_help(command="policy", help_dict=cmd_help, mod_name="idrange")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new policy',
                                },
                },

    'add_id_range'              : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_id_range {policy} {attribute:type:range}',
                    'cmd'   :   '<|object|> <id_range>',
                    '_help' :   {
                                    'cmd'                   : 'Add ID range. Range type must be s=sequence or r=random.',
                                },
                },

    'del_id_range'              : {
                    '_cmd_usage_help' : 'Usage: otpme-policy del_id_range {policy} {attribute:type:range}',
                    'cmd'   :   '<|object|> <id_range>',
                    '_help' :   {
                                    'cmd'                   : 'Delete ID range',
                                },
                },

    'enable_id_check'              : {
                    '_cmd_usage_help' : 'Usage: otpme-policy enable_id_check {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable check if new ID is already used.',
                                },
                },

    'disable_id_check'              : {
                    '_cmd_usage_help' : 'Usage: otpme-policy disable_id_check {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable check if new ID is already used.',
                                },
                },

    'enable_id_range_recheck'              : {
                    '_cmd_usage_help' : 'Usage: otpme-policy enable_id_range_recheck {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable ID range re-check.',
                                },
                },

    'disable_id_range_recheck'              : {
                    '_cmd_usage_help' : 'Usage: otpme-policy disable_id_range_recheck {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable ID range re-check.',
                                },
                },
    }
