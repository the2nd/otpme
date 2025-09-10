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
    register_cmd_help(command="group", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-group {command} [group]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-group show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [group]',
                    'cmd'   :   '--policy-limit :max_policies: --role-limit :max_roles: --token-limit :max_tokens: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show group(s)',
                                    '-a'                    : 'Show all groups.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                    '--reverse'             : 'Reverse the output order.',
                                    '--sort-by <attribute>' : 'Sort output by <attribute>.',
                                    '--role-limit <limit>'  : 'Output max roles.',
                                    '--token-limit <limit>' : 'Output max tokens.',
                                    '--policy-limit <limit>': 'Output max policies.',
                                    '--raw'                 : 'Output table without any headers/borders.',
                                    '--csv'                 : 'Output table as CSV.',
                                    '--csv-sep <separator>' : 'Output table as CSV.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List groups.',
                                    '-a'                        : 'List all groups.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group add [--attributes <attr1=val1,attr2=val2> {group}',
                    'cmd'   :   '--attributes :[ldif_attributes]: <|object|>',
                    '_help' :   {
                                    'cmd'                                   : 'add new group',
                                    '--attributes <attr1=val1,attr2=val2>'  : 'Add LDIF attributes to user.',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group del {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete group',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group touch {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch group (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group enable {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable group',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group disable {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable group',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group rename {group} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename group',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group config {group} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to group.',
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : 'Usage: otpme-group show_config {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Show group config parameters',
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_extension {group} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'add extension to group',
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group remove_extension {group} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'remove extension from group',
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_attribute {group} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) attribute to group',
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group del_attribute {group} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) attribute from group',
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_object_class {group} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) object class to group',
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group del_object_class {group} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) object class from group',
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group show_ldif {group} -a attribute1,attribute2',
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : 'show ldif representation of group',
                                    '-a'                    : 'show only given LDIF attributes',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_acl {group} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to group',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group del_acl {group} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from group',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group show_acls {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of group',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group enable_acl_inheritance {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for group',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group disable_acl_inheritance {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for group',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group move [--keep-acls] {group} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change groups unit',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group remove_orphans {group}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group description {group} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set group description',
                                },
                },

    'list_sync_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group list_sync_users {group}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List sync users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group list_users {group}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_default_group_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group list_default_group_users {group}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List default group users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group list_tokens {group}',
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'List assigned tokens.',
                                    '--return-type'             : 'Attribute to return.',
                                    '--token-types <hotp,totp>' : 'Token types to list.',
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group list_roles {group}',
                    'cmd'   :   '--return-type :return_type: -r :recursive=True: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : 'List assigned roles.',
                                    '--return-type'         : 'Attribute to return.',
                                    '-r'                    : 'List roles recursive.',
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
                    '_cmd_usage_help' : 'Usage: otpme-group export --password <password> {group}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export group config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_policy {group} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to group',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-group remove_policy {group} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from group',
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group list_policies {group}',
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
    'add_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_role {group} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'add role to group',
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group remove_role {group} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove role from group',
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_token [--no-auto-sign] [--sign --tags {tag1,tag2,...}] {group} {token} [token_options]',
                    'cmd'   :   '--no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : 'Add token to group.',
                                    '--sign'                : 'Sign the object with default tags.',
                                    '--tags <tag1,tag2>'    : 'Add tags to signature.',
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group remove_token --keep-sign {group} {token}',
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove token from group.',
                                    '--keep-sign'           : 'Do not remove any signature.',
                                },
                },

    'add_sync_user'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group add_sync_user {group} {user}',
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add sync user to group.',
                                },
                },

    'remove_sync_user'   : {
                    '_cmd_usage_help' : 'Usage: otpme-group remove_sync_user {user}',
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove sync user from group.',
                                },
                },
    }
