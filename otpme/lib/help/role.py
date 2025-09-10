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
    register_cmd_help(command="role", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-role {command} [role]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-role show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [role]',
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --token-limit :max_tokens: --role-limit :max_roles: --accessgroup-limit :max_ags: --group-limit :max_groups: --policy-limit :max_policies: [|object|]',
                    '_help' :   {
                                    'cmd'                           : 'show role(s)',
                                    '-a'                            : 'Show all roles.',
                                    '-z <limit>'                    : 'limit output size',
                                    '--fields f1,f2,f3'             : 'output only given fields',
                                    '--reverse'                     : 'Reverse the output order.',
                                    '--sort-by <attribute>'         : 'Sort output by <attribute>.',
                                    '--raw'                         : 'Output table without any headers/borders.',
                                    '--csv'                         : 'Output table as CSV.',
                                    '--csv-sep <separator>'         : 'Output table as CSV.',
                                    '--token-limit <limit>'         : 'Output <limit> member tokens.',
                                    '--role-limit <limit>'          : 'Output <limit> member roles.',
                                    '--accessgroup-limit <limit>'   : 'Output <limit> member accessgroups.',
                                    '--group-limit <limit>'         : 'Output <limit> member groups.',
                                    '--policy-limit <limit>'        : 'Output <limit> assigned policies.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List roles.',
                                    '-a'                        : 'List all roles.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role add [--groups <group1,group2>] [--roles <role1,role2>] {role}',
                    'cmd'   :   '--groups :[groups]: --roles :[roles]: <|object|>',
                    '_help' :   {
                                    'cmd'                           : 'add new role',
                                    '--groups <group1,group2>'      : 'Groups to add role to.',
                                    '--roles <role1,role2>'         : 'Roles to add role to.',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role del {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete role',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role touch {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch role (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role enable {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable role',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role disable {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable role',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role rename {role} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename role',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role config {role} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to role.',
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : 'Usage: otpme-role show_config {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Show role config parameters',
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_extension {role} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'add extension to role',
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_extension {role} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'remove extension from role',
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_attribute {role} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) attribute to role',
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role del_attribute {role} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) attribute from role',
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_object_class {role} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) object class to role',
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role del_object_class {role} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) object class from role',
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role show_ldif {role} -a attribute1,attribute2',
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : 'show ldif representation of role',
                                    '-a'                    : 'show only given LDIF attributes',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_acl {role} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to role',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role del_acl {role} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from role',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role show_acls {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of role',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role enable_acl_inheritance {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for role',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role disable_acl_inheritance {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for role',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role move [--keep-acls] {role} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change roles unit',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_orphans {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role description {role} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set role description',
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
                    '_cmd_usage_help' : 'Usage: otpme-role export --password <password> {role}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export role config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_policy {role} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to role',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_policy {role} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from role',
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_token [-i tty,gui,ssh] [--no-auto-sign] [--sign --tags {tag1,tag2,...}] {role} {token} [token_options]',
                    'cmd'   :   '-i :[login_interfaces]: --no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : 'Add token to role.',
                                    '-i <tty,gui,ssh>'      : 'Limit login to given interface(s).',
                                    '--sign'                : 'Sign the object with default tags.',
                                    '--tags <tag1,tag2>'    : 'Add tags to signature.',
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_token --keep-sign {role} {token}',
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'remove token from role',
                                    '--keep-sign'           : 'Do not remove any signature.',
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_role {role} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'add role to role',
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_role {role} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove role from role',
                                },
                },

    'add_dynamic_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_dynamic_group {role} {group_name}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add dynamic group to role.',
                                },
                },

    'remove_dynamic_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_dynamic_group {role} {group_name}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove dynamic group from role.',
                                },
                },

    'add_sync_user'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role add_sync_user {role} {user}',
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add sync user to role.',
                                },
                },

    'remove_sync_user'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role remove_sync_user {user}',
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove sync user from role.',
                                },
                },
    'list_sync_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role list_sync_users {role}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List sync users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role list_users {role}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role list_tokens {role}',
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'List assigned tokens.',
                                    '--return-type'             : 'Attribute to return.',
                                    '--token-types <hotp,totp>' : 'Token types to list.',
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role list_roles -r {role}',
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'List assigned roles.',
                                    '-r'                    : 'List roles recursive..',
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role list_policies {role}',
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
    'list_dynamic_groups'   : {
                    '_cmd_usage_help' : 'Usage: otpme-role list_dynamic_groups {role}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'List dynamic groups of role.',
                                },
                },
    }
