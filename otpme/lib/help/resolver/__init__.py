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
    register_cmd_help(command="resolver", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-resolver {command} [resolver]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [resolver]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: -a :show_all=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show resolvers',
                                    '-a'                    : 'Show all resolvers.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                    '--policy-limit <limit>': 'Output max policies.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver list [regex]',
                    'cmd'   :   '[search_regex]',
                    '_help' :   {
                                    'cmd'                   : 'list resolvers',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver del {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete resolver',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver enable {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable resolver',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver disable {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable resolver',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver rename {resolver} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename resolver',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver config {resolver} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to resolver.',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver add_acl {resolver} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to resolver',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver del_acl {resolver} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from resolver',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver show_acls {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of resolver',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver enable_acl_inheritance {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for resolver',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver disable_acl_inheritance {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for resolver',
                                },
                },


    'unit'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver unit {resolver} {unit}',
                    'cmd'   :   '<|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change resolvers unit',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver description {resolver} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set resolver description',
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
                    '_cmd_usage_help' : 'Usage: otpme-resolver export {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export resolver config to stdout',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver add_policy {resolver} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to resolver',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver remove_policy {resolver} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from resolver',
                                },
                },

    'enable_sync_units' : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver enable_sync_units {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable sync of units.',
                                },
                },

    'disable_sync_units' : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver disable_sync_units {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable sync of units.',
                                },
                },

    'enable_deletions' : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver enable_deletions {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable deletions of objects missing on resolver site.',
                                },
                },

    'disable_deletions' : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver disable_deletions {resolver}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable deletions of objects missing on resolver site.',
                                },
                },

    'key_attribute' : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver key_attribute {resolver} {object_type} {attribute}',
                    'cmd'   :   '<|object|> <object_type> <key_attribute>',
                    '_help' :   {
                                    'cmd'                   : 'Set key attribute used to sync objects (e.g. entryUUID).',
                                },
                },

    'run'           : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver run [--object-types <object_types>] {resolver}',
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Run resolver',
                                },
                },

    'sync_interval': {
                    '_cmd_usage_help' : 'Usage: otpme-resolver sync_interval {resolver} {sync_interval}',
                    'cmd'   :   '<|object|> <sync_interval>',
                    '_help' :   {
                                    'cmd'                       : 'Set resolver sync interval.',
                                },
                },

    'get_objects': {
                    '_cmd_usage_help' : 'Usage: otpme-resolver get_objects [--object-types object_types] {resolver}',
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                       : 'Get resolver objects.',
                                    '--object-types user,group' : 'Get only the following object types.',
                                },
                },

    'delete_objects': {
                    '_cmd_usage_help' : 'Usage: otpme-resolver delete_objects [--object-types object_types] {resolver}',
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                       : 'Delete resolver objects.',
                                    '--object-types user,group' : 'Delete only the following object types.',
                                },
                },

    'test'          : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver test [--object-types <object_types>] {resolver}',
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'test resolver',
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-resolver list_policies {resolver}',
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
