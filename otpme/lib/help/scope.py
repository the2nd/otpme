# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="scope", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-scope {command} [scope]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-scope show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [scope]'),
                    'cmd'   :   '--policy-limit :max_policies: --limit :limit: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show scope(s)'),
                                    '-a'                    : _('Show all scopes.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--limit <limit>'       : _('Limit number of items shown per object.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '-a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List scopes'),
                                    '-a'                        : _('List all scopes.'),
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add {scope} [scope_id]'),
                    'cmd'   :   '<|object|> [scope_id]',
                    '_help' :   {
                                    'cmd'                   : _('Add new scope'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope del {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete scope'),
                                },
                },

    'scope_id'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope scope_id {scope} {scope_id}'),
                    'cmd'   :   '<|object|> <scope_id>',
                    '_help' :   {
                                    'cmd'                   : _('Change scope ID.'),
                                },
                },


     'enable_auto_member'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope enable_auto_member {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable auto member for scope'),
                                },
                },


     'disable_auto_member'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope disable_auto_member {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable auto member for scope'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope get_config {scope} {parameter}'),
                    'cmd'   :   '<|object|> <parameter>',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope touch {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch scope.'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope enable {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable scope'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope disable {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable scope'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope rename {scope} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename scope'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope config -d -a {scope} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to scope.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-scope show_config {scope} [parameter]'),
                    'cmd'   :   '<|object|> [parameter]',
                    '_help' :   {
                                    'cmd'                   : _('Show scope config parameters'),
                                },
                },

     #'add_extension'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-scope add_extension {scope} {extension}'),
     #               'cmd'   :   '<|object|> <extension>',
     #               '_help' :   {
     #                               'cmd'                   : _('Add extension to scope'),
     #                           },
     #           },

     #'remove_extension'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-scope remove_extension {scope} {extension}'),
     #               'cmd'   :   '<|object|> <extension>',
     #               '_help' :   {
     #                               'cmd'                   : _('Remove extension from scope'),
     #                           },
     #           },

     #'add_attribute'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-scope add_attribute {scope} {attribute}=[value]'),
     #               'cmd'   :   '<|object|> <attribute>=[value]',
     #               '_help' :   {
     #                               'cmd'                   : _('Add (ldap) attribute to scope'),
     #                           },
     #           },

     #'del_attribute'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-scope del_attribute {scope} {attribute}=[value]'),
     #               'cmd'   :   '<|object|> <attribute>=[value]',
     #               '_help' :   {
     #                               'cmd'                   : _('Delete (ldap) attribute from scope'),
     #                           },
     #           },

     #'add_object_class'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-scope add_object_class {scope} {object_class}'),
     #               'cmd'   :   '<|object|> <object_class>',
     #               '_help' :   {
     #                               'cmd'                   : _('Add (ldap) object class to scope'),
     #                           },
     #           },

     #'del_object_class'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-scope del_object_class {scope} {object_class}'),
     #               'cmd'   :   '<|object|> <object_class>',
     #               '_help' :   {
     #                               'cmd'                   : _('Delete (ldap) object class from scope'),
     #                           },
     #           },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-scope show_ldif {scope}',
     #               'cmd'   :   '<|object|>',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of scope',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add_acl {scope} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to scope'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope del_acl {scope} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from scope'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope show_acls {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of scope'),
                                },
                },

     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope enable_acl_inheritance {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for scope'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope disable_acl_inheritance {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for scope'),
                                },
                },

    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope move [--keep-acls] {scope} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change scope\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.'),
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope remove_orphans {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope description {scope} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set scope description'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope info {scope} [info]'),
                    'cmd'   :   '--language :language: <|object|> [info]',
                    '_help' :   {
                                    'cmd'                   : _('Set scope info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope dump_info {scope}'),
                    'cmd'   :   '--language :language: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump scope info'),
                                    '--language <lang>'     : _('Dump info for language.'),
                                },
                },

    #'_list_valid_object_classes'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_list_valid_attributes'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_show_attributes'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_show_object_classes'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_show_supported_acls'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_show_supported_default_acls'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_show_supported_recursive_default_acls'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    #'_show_config'    : {
    #                'cmd'   :   '<|object|>',
    #            },

    'export'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope export --password <password> {scope}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export scope config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add_policy {scope} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to scope'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-scope remove_policy {scope} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from scope'),
                                },
                },

    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope list_tokens {scope}'),
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope list_roles {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List assigned roles.'),
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope list_policies {scope}'),
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

    'list_clients'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope list_clients {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List assigned clients.'),
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add_role {scope} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add role to scope.'),
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope remove_role {scope} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from scope.'),
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add_token {scope} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Add token to scope.'),
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope remove_token {scope} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from scope.'),
                                },
                },

    'add_client'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add_client {scope} {client}'),
                    'cmd'   :   '<|object|> <client_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add client to scope.'),
                                },
                },

    'remove_client'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope remove_client {scope} {client}'),
                    'cmd'   :   '<|object|> <client_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove client from scope.'),
                                },
                },

    'list_groups'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope list_groups {scope}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List groups whitelisted on this scope.'),
                                },
                },

    'add_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope add_group {scope} {group}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add group to scope (whitelist for OIDC groups claim).'),
                                },
                },

    'remove_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-scope remove_group {scope} {group}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove group from scope.'),
                                },
                },
    }
