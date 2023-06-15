# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from .. import register_cmd_help

def register():
    register_cmd_help(command="policy", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-policy {command} [policy]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [policy]',
                    'cmd'   :   '--fields :output_fields: -z :max_len: -a :show_all=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show policies',
                                    '-a'                    : 'Show all policies.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy list [regex]',
                    'cmd'   :   '[search_regex]',
                    '_help' :   {
                                    'cmd'                   : 'list policies',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy del {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete policy',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy enable {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable policy',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy disable {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable policy',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy rename {policy} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename policy',
                                },
                },

    'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy config {policy} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to policy.',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_acl {policy} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to policy',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy del_acl {policy} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from policy',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy show_acls {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of policy',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy enable_acl_inheritance {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for policy',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy disable_acl_inheritance {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for policy',
                                },
                },


    'unit'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy unit {policy} {unit}',
                    'cmd'   :   '<|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change policys unit',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy description {policy} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set policy description',
                                },
                },

    '_list_valid_object_classes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_valid_attributes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_attributes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_object_classes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_supported_acls'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_supported_default_acls'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_supported_recursive_default_acls'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_config'    : {
                    'cmd'   :   '<|object|>',
                },

    'export'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy export {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export policy config to stdout',
                                },
                },

    'test'          : {
                    '_cmd_usage_help' : 'Usage: otpme-policy test {policy} [policy_parameters]',
                    'cmd'   :   '<|object|> [policy_parameters]',
                    '_help' :   {
                                    'cmd'                   : 'test policy',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy add_policy {policy} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add policy to policy.',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy remove_policy {policy} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove policy from policy.',
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-policy list_policies {policy}',
                    'cmd'   :   '--return-type :return_type: --policy-types :[policy_types]: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                           : 'List assigned policies.',
                                    '--return-type'                 : 'Attribute to return.',
                                    '--policy-types <type1,type2>'  : 'Policy types to list.',
                                },
                },
    }
