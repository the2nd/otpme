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
    register_cmd_help(command="accessgroup", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-accessgroup {command} [accessgroup]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [accessgroup]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show accessgroup(s)',
                                    '-a'                    : 'Show all accessgroups.',
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
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup list [--attribute attribute] [-a]  [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                   : 'list accessgroups',
                                    '-a'                    : 'List all accessgroups.',
                                    '--attribute attribute' : 'Output given attribute.',
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new accessgroup',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup del {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete accessgroup',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup touch {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch accessgroup (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup enable {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable accessgroup',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup disable {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable accessgroup',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup rename {accessgroup} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename accessgroup',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup config {accessgroup} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to accessgroup.',
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_extension {accessgroup} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'add extension to accessgroup',
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_extension {accessgroup} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'remove extension from accessgroup',
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_attribute {accessgroup} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) attribute to accessgroup',
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup del_attribute {accessgroup} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) attribute from accessgroup',
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_object_class {accessgroup} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) object class to accessgroup',
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup del_object_class {accessgroup} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) object class from accessgroup',
                                },
                },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-accessgroup show_ldif {accessgroup}',
     #               'cmd'   :   '<|object|>',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of accessgroup',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_acl {accessgroup} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to accessgroup',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup del_acl {accessgroup} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from accessgroup',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup show_acls {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of accessgroup',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup enable_acl_inheritance {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for accessgroup',
                                },
                },

     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup disable_acl_inheritance {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for accessgroup',
                                },
                },

    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup move [--keep-acls] {accessgroup} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change accessgroups unit',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },

    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_orphans {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                },
                },

    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup description {accessgroup} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set accessgroup description',
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
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup export --password <password> {accessgroup}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export accessgroup config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_policy {accessgroup} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to accessgroup',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_policy {accessgroup} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from accessgroup',
                                },
                },

    'list_tokens'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup list_tokens {accessgroup}',
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'List assigned tokens.',
                                    '--return-type'             : 'Attribute to return.',
                                    '--token-types <hotp,totp>' : 'Token types to list.',
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup list_roles {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'List assigned roles.',
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup list_policies {accessgroup}',
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
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_role {accessgroup} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'add role to accessgroup',
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_role {accessgroup} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove role from accessgroup',
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_token [-i tty,gui,ssh] [--no-auto-sign] [--sign --tags {tag1,tag2,...}] {accessgroup} {token} [token_options]',
                    'cmd'   :   '-i :[login_interfaces]: --no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : 'Add token to accessgroup.',
                                    '-i <tty,gui,ssh>'      : 'Limit login to given interface(s).',
                                    '--sign'                : 'Sign the object with default tags.',
                                    '--tags <tag1,tag2>'    : 'Add tags to signature.',
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_token --keep-sign {accessgroup} {token}',
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove token from accessgroup.',
                                    '--keep-sign'           : 'Do not remove any signature.',
                                },
                },

    'enable_sessions'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup enable_sessions {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable sessions for accessgroup',
                                },
                },


    'disable_sessions'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup disable_sessions {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable sessions for accessgroup',
                                },
                },


    'enable_session_master'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup enable_session_master {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'make accessgroup the session master',
                                },
                },


    'disable_session_master'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup disable_session_master {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable session master for accessgroup',
                                },
                },


    'enable_timeout_pass_on'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup enable_timeout_pass_on {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable pass on of timeout values to child sessions',
                                },
                },


    'disable_timeout_pass_on'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup disable_timeout_pass_on {accessgroup}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable pass on of timeout values to child sessions',
                                },
                },


    'add_child_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_child_group {accessgroup} {accessgroup}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'add child accessgroup',
                                },
                },

    'remove_child_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_child_group {accessgroup} {accessgroup}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove child accessgroup',
                                },
                },


    'add_child_session'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup add_child_session {accessgroup} {accessgroup}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'add child session',
                                },
                },

    'remove_child_session'   : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup remove_child_session {accessgroup} {accessgroup}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove child session',
                                },
                },


     'max_sessions'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup max_sessions {accessgroup} [max_sessions]',
                    'cmd'   :   '<|object|> [max_sessions]',
                    '_help' :   {
                                    'cmd'                   : 'set max sessions that will be created for this accessgroup',
                                },
                },


     'relogin_timeout'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup relogin_timeout {accessgroup} [relogin_timeout]',
                    'cmd'   :   '<|object|> [relogin_timeout]',
                    '_help' :   {
                                    'cmd'                   : 'set relogin timeout for this accessgroup.',
                                },
                },


     'max_use'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup max_use {accessgroup} [max_use]',
                    'cmd'   :   '<|object|> [max_use]',
                    '_help' :   {
                                    'cmd'                   : 'set max authentication requests possible with one otp',
                                },
                },

     'max_fail'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup max_fail {accessgroup} [max_fail]',
                    'cmd'   :   '<|object|> [max_fail]',
                    '_help' :   {
                                    'cmd'                   : 'set max failed logins after a user gets locked for this accessgroup',
                                },
                },

     'max_fail_reset'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup max_fail_reset {accessgroup} [reset_time]',
                    'cmd'   :   '<|object|> [reset_time]',
                    '_help' :   {
                                    'cmd'                   : 'Set max fail reset time.',
                                },
                },

     'timeout'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup timeout {accessgroup} [timeout]',
                    'cmd'   :   '<|object|> [timeout]',
                    '_help' :   {
                                    'cmd'                   : 'set session timeout',
                                },
                },


     'unused_timeout'    : {
                    '_cmd_usage_help' : 'Usage: otpme-accessgroup unused_timeout {accessgroup} [unused_timeout]',
                    'cmd'   :   '<|object|> [unused_timeout]',
                    '_help' :   {
                                    'cmd'                   : 'set unused session timeout',
                                },
                },
    }
