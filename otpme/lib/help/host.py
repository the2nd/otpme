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
    register_cmd_help(command="host", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-host {command} [host]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-host show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-t] [-a] [host]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: -t :show_templates=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show host(s)',
                                    '-a'                    : 'Show all hosts.',
                                    '-t'                    : 'Show hosts templates.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                    '--policy-limit <limit>': 'Output max policies.',
                                    '--reverse'             : 'Reverse the output order.',
                                    '--sort-by <attribute>' : 'Sort output by <attribute>.',
                                    '--raw'                 : 'Output table without any headers/borders.',
                                    '--csv'                 : 'Output table as CSV.',
                                    '--csv-sep <separator>' : 'Output table as CSV.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List hosts.',
                                    '-a'                        : 'List all hosts.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host add {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new host',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host del {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete host',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host touch {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch host (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable host',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host disable {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable host',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host config {host} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to host.',
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_extension {host} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'add extension to host',
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_extension {host} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'remove extension from host',
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_attribute {host} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) attribute to host',
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host del_attribute {host} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) attribute from host',
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_object_class {host} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) object class to host',
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host del_object_class {host} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) object class from host',
                                },
                },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-host show_ldif {host} -a attribute1,attribute2',
     #               'cmd'   :   '<|object|> -a :[attributes]:',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of host',
     #                               '-a'                    : 'show only given LDIF attributes',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_acl {host} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to host',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host del_acl {host} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from host',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host show_acls {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of host',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_acl_inheritance {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for host',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host disable_acl_inheritance {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for host',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host move [--keep-acls] {host} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change hosts unit',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_orphans {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host description {host} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set host description',
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
                    '_cmd_usage_help' : 'Usage: otpme-host export --password <password> {host}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export host config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_policy {host} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to host',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_policy {host} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from host',
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host list_policies {host}',
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
    'list_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host list_users {host}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host list_tokens {host}',
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'List assigned tokens.',
                                    '--return-type'             : 'Attribute to return.',
                                    '--token-types <hotp,totp>' : 'Token types to list.',
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host list_roles {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'List assigned roles.',
                                },
                },
    'list_sync_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host list_sync_users {host}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List sync users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },

    'list_sync_groups'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host list_sync_groups {host}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List sync groups.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },

    'dump_cert'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host dump_cert {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'dump host cert to stdout',
                                },
                },


    'dump_ca_chain'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host dump_ca_chain {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'dump host certificate chain of host cert to stdout',
                                },
                },

    'renew_cert'   : {
                    'cmd'   :   '<|object|>',
                },

    'public_key'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host public_key {host} [public_key]',
                    'cmd'   :   '<|object|> [public_key]',
                    '_help' :   {
                                    'cmd'                   : 'change hosts public key.',
                                },
                },


    'address'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host address {host} [ip_address]',
                    'cmd'   :   '<|object|> [address]',
                    '_help' :   {
                                    'cmd'                   : 'change hosts IP address',
                                },
                },

    'enable_jotp'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_jotp {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable realm join via JOTP.',
                                },
                },

    'disable_jotp'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_jotp {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable realm join via JOTP.',
                                },
                },

    'enable_lotp'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_lotp {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable realm leaving via LOTP.',
                                },
                },

    'disable_lotp'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_lotp {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable realm leaving via LOTP.',
                                },
                },

    'enable_jotp_rejoin'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_jotp_rejoin {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable printing of rejoin JOTP on realm leave.',
                                },
                },

    'disable_jotp_rejoin'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_jotp_rejoin {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable printing of rejoin JOTP on realm leave.',
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_role {host} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add role to host.',
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_role {host} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove role from host.',
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_token [-i tty,gui,ssh] [--no-auto-sign] [--sign --tags {tag1,tag2,...}] {host} {token} [token_options]',
                    'cmd'   :   '-i :[login_interfaces]: --no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : 'Add token to host.',
                                    '-i <tty,gui,ssh>'      : 'Limit login to given interface(s).',
                                    '--sign'                : 'Sign the object with default tags.',
                                    '--tags <tag1,tag2>'    : 'Add tags to signature.',
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_token --keep-sign {host} {token}',
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove token from host.',
                                    '--keep-sign'           : 'Do not remove any signature.',
                                },
                },

    'add_sync_user'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_sync_user {host} {user}',
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add sync user to host.',
                                },
                },

    'remove_sync_user'   : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_sync_user {user}',
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove sync user from host.',
                                },
                },

    'add_sync_group'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host add_sync_group {host} {group}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add sync group.',
                                },
                },

    'remove_sync_group'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host remove_sync_group {host} {group}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove sync group.',
                                },
                },

    'enable_sync_groups'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_sync_groups {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable sync groups.',
                                },
                },

    'disable_sync_groups'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host disable_sync_groups {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable sync groups.',
                                },
                },

    'enable_sync_by_login_token'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host enable_sync_by_login_token {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable sync by login token.',
                                },
                },

    'disable_sync_by_login_token'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host disable_sync_by_login_token {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable sync by login token.',
                                },
                },

    'limit_logins'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host limit_logins {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Limit logins.',
                                },
                },

    'unlimit_logins'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host unlimit_logins {host}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Unlimit logins.',
                                },
                },

    'get_ssh_authorized_keys'    : {
                    '_cmd_usage_help' : 'Usage: otpme-host get_ssh_authorized_keys {host} [user]',
                    'cmd'   :   '<|object|> [user]',
                    '_help' :   {
                                    'cmd'                   : 'Get SSH authorized keys for host.',
                                },
                },
    }
