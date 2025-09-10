# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
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
    '_usage_help'               : "Usage: otpme-policy [--type <policy_type>] {command} [policy]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [policy]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: -a :show_all=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show policies',
                                    '-a'                    : 'Show all policies.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                    '--policy-limit <limit>': 'Output max policies.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy list [regex]',
                    'cmd'   :   '[search_regex]',
                    '_help' :   {
                                    'cmd'                   : 'list policies',
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy --type <policy_type> add {policy}',
                    '_help' :   {
                                    'cmd'                   : 'Add new policy',
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

    'show_config'      : {
                    '_cmd_usage_help' : 'Usage: otpme-policy show_config {policy}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Show policy config parameters',
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

    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-policy move [--keep-acls] {group} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'Change policies unit.',
                                    '--keep-acls'           : 'Keep object ACLs.'
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
                    'cmd'   :   '--return-type :return_type: --policy-types :[policy_types]: <|object|>',
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
