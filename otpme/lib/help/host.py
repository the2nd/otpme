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
    register_cmd_help(command="host", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-host {command} [host]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-host show [--policy-limit <limit>] [--token-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-t] [-a] [host]'),
                    'cmd'   :   '--policy-limit :max_policies: --token-limit :max_tokens: --role-limit :max_roles: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: -t :show_templates=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show host(s)'),
                                    '-a'                    : _('Show all hosts.'),
                                    '-t'                    : _('Show host templates.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--token-limit <limit>' : _('Output <limit> tokens.'),
                                    '--role-limit <limit>'  : _('Output max roles.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List hosts.'),
                                    '-a'                        : _('List all hosts.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host add {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new host'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host del {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete host'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host touch {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch host (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable host'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable host'),
                                },
                },

    'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host config {host} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to host.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-host show_config {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show host config parameters'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_extension {host} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to host'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_extension {host} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from host'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_attribute {host} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) attribute to host'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host del_attribute {host} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) attribute from host'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_object_class {host} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) object class to host'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host del_object_class {host} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) object class from host'),
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
                    '_cmd_usage_help' : _('Usage: otpme-host add_acl {host} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to host'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host del_acl {host} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from host'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host show_acls {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of host'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable_acl_inheritance {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for host'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable_acl_inheritance {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for host'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host move [--keep-acls] {host} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change host\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_orphans {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host description {host} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set host description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-host export --password <password> {host}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export host config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_policy {host} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to host'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_policy {host} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from host'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_policies {host}'),
                    'cmd'   :   '--return-type :return_type: --policy-types :[policy_types]: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                           : _('List assigned policies.'),
                                    '--return-type'                 : _('Attribute to return.'),
                                    '--policy-types <type1,type2>'  : _('Policy types to list.'),
                                },
                },
    'list_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_users {host}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_tokens {host}'),
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('List assigned tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_roles {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List assigned roles.'),
                                },
                },
    'list_dynamic_groups'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_dynamic_groups {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List dynamic groups of host.'),
                                },
                },
    'list_sync_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_sync_users {host}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List sync users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },

    'list_sync_groups'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host list_sync_groups {host}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List sync groups.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },

    'dump_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host dump_cert {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump host cert to stdout'),
                                },
                },


    'dump_ca_chain'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host dump_ca_chain {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump host certificate chain of host cert to stdout'),
                                },
                },

    'renew_cert'   : {
                    'cmd'   :   '<|object|>',
                },

    'public_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host public_key {host} [public_key]'),
                    'cmd'   :   '<|object|> [public_key]',
                    '_help' :   {
                                    'cmd'                   : _("Change host\\'s public key."),
                                },
                },

    'enable_jotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable_jotp {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable realm join via JOTP.'),
                                },
                },

    'disable_jotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable_jotp {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable realm join via JOTP.'),
                                },
                },

    'enable_lotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable_lotp {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable realm leaving via LOTP.'),
                                },
                },

    'disable_lotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable_lotp {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable realm leaving via LOTP.'),
                                },
                },

    'enable_jotp_rejoin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable_jotp_rejoin {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable printing of rejoin JOTP on realm leave.'),
                                },
                },

    'disable_jotp_rejoin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable_jotp_rejoin {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable printing of rejoin JOTP on realm leave.'),
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_role {host} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add role to host.'),
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_role {host} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from host.'),
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_token [-i tty,gui,ssh] [--no-auto-sign] [--sign --tags {tag1,tag2,...}] {host} {token} [token_options]'),
                    'cmd'   :   '-i :[login_interfaces]: --no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : _('Add token to host.'),
                                    '-i <tty,gui,ssh>'      : _('Limit login to given interface(s).'),
                                    '--sign'                : _('Sign the object with default tags.'),
                                    '--tags <tag1,tag2>'    : _('Add tags to signature.'),
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_token --keep-sign {host} {token}'),
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from host.'),
                                    '--keep-sign'           : _('Do not remove any signature.'),
                                },
                },

    'add_dynamic_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_dynamic_group {host} {group_name}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add dynamic group to host.'),
                                },
                },

    'remove_dynamic_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_dynamic_group {host} {group_name}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove dynamic group from host.'),
                                },
                },

    'add_sync_user'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_sync_user {host} {user}'),
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add sync user to host.'),
                                },
                },

    'remove_sync_user'   : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_sync_user {host} {user}'),
                    'cmd'   :   '<|object|> <user_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove sync user from host.'),
                                },
                },

    'add_sync_group'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host add_sync_group {host} {group}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add sync group.'),
                                },
                },

    'remove_sync_group'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host remove_sync_group {host} {group}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove sync group.'),
                                },
                },

    'enable_sync_groups'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable_sync_groups {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable sync groups.'),
                                },
                },

    'disable_sync_groups'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable_sync_groups {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable sync groups.'),
                                },
                },

    'enable_sync_by_login_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host enable_sync_by_login_token {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable sync by login token.'),
                                },
                },

    'disable_sync_by_login_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host disable_sync_by_login_token {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable sync by login token.'),
                                },
                },

    'limit_logins'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host limit_logins {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Limit logins.'),
                                },
                },

    'unlimit_logins'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host unlimit_logins {host}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Unlimit logins.'),
                                },
                },

    'get_ssh_authorized_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host get_ssh_authorized_keys {host} [user]'),
                    'cmd'   :   '<|object|> [user]',
                    '_help' :   {
                                    'cmd'                   : _('Get SSH authorized keys for host.'),
                                },
                },
    }
