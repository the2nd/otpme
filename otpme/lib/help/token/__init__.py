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
    register_cmd_help(command="token", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-token [--type <token_type>] {command} [token]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-token show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [token]',
                    'cmd'   :   '--policy-limit :max_policies: --role-limit :max_roles: --fields :output_fields: -z :max_len: -a :show_all=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'Show token(s).',
                                    '-a'                    : 'Show all tokens.',
                                    '-z <limit>'            : 'Limit output size.',
                                    '--fields f1,f2,f3'     : 'Output only given fields.',
                                    '--role-limit <limit>'  : 'Output max roles.',
                                    '--policy-limit <limit>': 'Output max policies.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token list [regex]',
                    'cmd'   :   '[search_regex]',
                    '_help' :   {
                                    'cmd'                   : 'list tokens',
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token --type <token_type> add {token}',
                    '_help' :   {
                                    'cmd'                       : 'Add new token',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token del {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete token',
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
                    '_cmd_usage_help' : 'Usage: otpme-token enable {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable token',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable token',
                                },
                },

    'auto_disable'          : {
                    '_cmd_usage_help' : 'Usage: otpme-token auto_disable {token} {time}',
                    'cmd'   :   '<|object|> <auto_disable> -u :unused=True:',
                    '_help' :   {
                                    'cmd'                   : 'Change auto disable value (e.g "1d" or "09:53 13.06.2023").',
                                    '-u'                    : 'Disable object if it was unused for the given time.',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token rename {token} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename token',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token move {src_user/token} {dst_user/token}',
                    'cmd'   :   '-r :replace=True: <|object|> <new_token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Move token.',
                                    '-r'                    : 'Replace destination token and keep its UUID.',
                                },
                },

    'add_dynamic_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_dynamic_group {token} {group_name}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add dynamic group to token.',
                                },
                },

    'remove_dynamic_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token remove_dynamic_group {token} {group_name}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove dynamic group from token.',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token config {token} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to token.',
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : 'Usage: otpme-token show_config',
                    'cmd'   :   '[|object|]',
                    '_help' :   {
                                    'cmd'                   : 'Show token config parameters',
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_extension {token} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'add extension to token',
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token remove_extension {token} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'remove extension from token',
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_attribute {token} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) attribute to token',
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token del_attribute {token} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) attribute from token',
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_object_class {token} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) object class to token',
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token del_object_class {token} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) object class from token',
                                },
                },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-token show_ldif {token}',
     #               'cmd'   :   '<|object|>',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of token',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_acl {token} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to token',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token del_acl {token} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from token',
                                },
                },

    'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token show_acls {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of token',
                                },
                },


    'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_acl_inheritance {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for token',
                                },
                },


    'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_acl_inheritance {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for token',
                                },
                },

    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token remove_orphans {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                },
                },

    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token description {token} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set token description',
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
                    '_cmd_usage_help' : 'Usage: otpme-token export {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export token config to stdout',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_policy {token} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to token',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token remove_policy {token} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from token',
                                },
                },


    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_policies {token}',
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

    'list_hosts'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_hosts {token}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : 'List hosts this token is assigend to.',
                                    '--return-type'         : 'Attribute to return.',
                                },
                },

    'list_nodes'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_nodes {token}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : 'List nodes this token is assigend to.',
                                    '--return-type'         : 'Attribute to return.',
                                },
                },

    'list_groups'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_groups {token}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : 'List groups this token is assigend to.',
                                    '--return-type'         : 'Attribute to return.',
                                },
                },

    'list_accessgroups'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_accessgroups {token}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : 'List accessgroups this token is assigend to.',
                                    '--return-type'         : 'Attribute to return.',
                                },
                },

    'list_roles'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_roles [--return-type <return_type>] [-r] {token}',
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

    'list_dynamic_groups'   : {
                    '_cmd_usage_help' : 'Usage: otpme-token list_dynamic_groups {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'List dynamic groups of token.',
                                },
                },

    'enable_auth_script'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_auth_script {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable token authorization script',
                                },
                },


    'disable_auth_script'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_auth_script {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable token authorization script',
                                },
                },


    'auth_script'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token auth_script {token} {auth_script}',
                    'cmd'   :   '<|object|> <auth_script> [script_options]',
                    '_help' :   {
                                    'cmd'                   : 'change token authorization script',
                                },
                },


    'enable_offline'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_offline {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable offline usage (caching) of token',
                                },
                },


    'disable_offline'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_offline {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable offline usage (caching) of token',
                                },
                },


    'offline_expiry'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token offline_expiry {token}',
                    'cmd'   :   '<|object|> <expiry>',
                    '_help' :   {
                                    'cmd'                   : 'set offline expiry timeout (caching) of token',
                                },
                },


    'offline_unused_expiry'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token offline_unused_expiry {token}',
                    'cmd'   :   '<|object|> <expiry>',
                    '_help' :   {
                                    'cmd'                   : 'set offline unused expiry timeout (caching) of token',
                                },
                },


    'enable_session_keep'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_session_keep {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable keeping of login session (e.g. on shutdown)',
                                },
                },


    'disable_session_keep'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_session_keep {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable keeping of login session',
                                },
                },


    'test'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token test {token} [otp|password]',
                    'cmd'   :   '<|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : 'test if given OTP/password can be verified by the token',
                                },
                },

    'temp_password'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token temp_password [--generate] [--duration 1h] [--remove] {token} [password]',
                    'cmd'   :   '--generate :auto_password=True: --duration :duration: --remove :remove=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : 'Set token temp password.',
                                    '--duration <1h>'       : 'Temp password validity duration.',
                                    '--generate'            : 'Generate temp password.',
                                    '--remove'              : 'Remove temp password.',
                                },
                },
    }
