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
    register_cmd_help(command="client", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-client {command} [client]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-client show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [client]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show client(s)'),
                                    '-a'                    : _('Show all clients.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List clients'),
                                    '-a'                        : _('List all clients.'),
                                    '--attribute <attribute>'   : _('Output given attribute.'),
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client add {client} [address]'),
                    'cmd'   :   '<|object|> [address]',
                    '_help' :   {
                                    'cmd'                   : _('Add new client'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client del {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete client'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client touch {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch client (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client enable {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable client'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client disable {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable client'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client rename {client} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename client'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client config {client} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to client.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-client show_config {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show client config parameters'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_extension {client} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to client'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client remove_extension {client} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from client'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_attribute {client} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (ldap) attribute to client'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client del_attribute {client} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (ldap) attribute from client'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_object_class {client} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (ldap) object class to client'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client del_object_class {client} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (ldap) object class from client'),
                                },
                },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-client show_ldif {client}',
     #               'cmd'   :   '<|object|>',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of client',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_acl {client} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to client'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client del_acl {client} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from client'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client show_acls {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of client'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client enable_acl_inheritance {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for client'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client disable_acl_inheritance {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for client'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client move [--keep-acls] {client} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change client\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.'),
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client remove_orphans {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client description {client} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set client description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-client export --password <password> {client}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export client config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_policy {client} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to client'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client remove_policy {client} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from client'),
                                },
                },

    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client list_tokens {client}'),
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client list_roles {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List assigned roles.'),
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client list_policies {client}'),
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

    'add_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_role {client} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add role to client.'),
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client remove_role {client} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from client.'),
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_token {client} {token} [token_options]'),
                    'cmd'   :   '<|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : _('Add token to client.'),
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client remove_token {client} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from client.'),
                                },
                },

    'limit_logins'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client limit_logins {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Limit logins.'),
                                },
                },

    'unlimit_logins'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client unlimit_logins {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Unlimit logins.'),
                                },
                },

    'secret'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client secret {client} [secret]'),
                    'cmd'   :   '<|object|> [secret]',
                    '_help' :   {
                                    'cmd'                   : _('Change client\'s secret'),
                                },
                },


    'show_secret'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client show_secret {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show client\'s secret'),
                                },
                },

    'enable_auth_cache'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client enable_auth_cache {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable auth cache for this client.'),
                                },
                },

    'disable_auth_cache'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client disable_auth_cache {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable auth cache for this client.'),
                                },
                },

    'auth_cache_timeout'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client auth_cache_timeout {client} {timeout}'),
                    'cmd'   :   '<|object|> <timeout>',
                    '_help' :   {
                                    'cmd'                   : _('Set auth cache timeout for this client.'),
                                },
                },

    'enable_sso'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client enable_sso {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable SSO app for this client.'),
                                },
                },

    'disable_sso'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client disable_sso {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable SSO app for this client.'),
                                },
                },

    'sso_name'      : {
                    '_cmd_usage_help' : _('Usage: otpme-client sso_name {client} {sso_name}'),
                    'cmd'   :   '<|object|> <sso_name>',
                    '_help' :   {
                                    'cmd'                   : _('Change client\'s SSO name.'),
                                },
                },

    'sso_logo'      : {
                    '_cmd_usage_help' : _('Usage: otpme-client sso_logo {client} {image_path}'),
                    'cmd'   :   '<|object|> <file:image_data>',
                    '_help' :   {
                                    'cmd'                   : _('Add SSO logo.'),
                                },
                },

    'dump_sso_logo'      : {
                    '_cmd_usage_help' : _('Usage: otpme-client dump_sso_logo {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump SSO logo as base64.'),
                                },
                },

    'del_sso_logo'      : {
                    '_cmd_usage_help' : _('Usage: otpme-client del_sso_logo {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete SSO logo.'),
                                },
                },

    'login_url'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client login_url {client} {login_url}'),
                    'cmd'   :   '<|object|> <login_url>',
                    '_help' :   {
                                    'cmd'                   : _('Change client\'s login URL.'),
                                },
                },

    'helper_url'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client helper_url {client} {helper_url}'),
                    'cmd'   :   '<|object|> <helper_url>',
                    '_help' :   {
                                    'cmd'                   : _('Change client\'s SSO helper URL.'),
                                },
                },

    'enable_sso_popup'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client enable_sso_popup {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable SSO popup for this client.'),
                                },
                },

    'disable_sso_popup'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client disable_sso_popup {client}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable SSO popup app for this client.'),
                                },
                },

    'add_address'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client add_address {client} {address}'),
                    'cmd'   :   '<|object|> <address>',
                    '_help' :   {
                                    'cmd'                   : _('Add address to client'),
                                },
                },

    'del_address'   : {
                    '_cmd_usage_help' : _('Usage: otpme-client del_address {client} {address}'),
                    'cmd'   :   '<|object|> <address>',
                    '_help' :   {
                                    'cmd'                   : _('Delete address from client'),
                                },
                },

    'access_group'    : {
                    '_cmd_usage_help' : _('Usage: otpme-client access_group {client} [access_group]'),
                    'cmd'   :   '<|object|> [access_group]',
                    '_help' :   {
                                    'cmd'                   : _('Change client\'s accessgroup'),
                                },
                },
    }
