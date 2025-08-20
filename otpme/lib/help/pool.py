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
    register_cmd_help(command="pool", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-pool {command} [pool]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-pool show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [pool]',
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --node-limit :max_nodes: --token-limit :max_tokens: --role-limit :max_roles: --policy-limit :max_policies: [|object|]',
                    '_help' :   {
                                    'cmd'                           : 'show pool(s)',
                                    '-a'                            : 'Show all pools.',
                                    '-z <limit>'                    : 'limit output size',
                                    '--fields f1,f2,f3'             : 'output only given fields',
                                    '--reverse'                     : 'Reverse the output order.',
                                    '--sort-by <attribute>'         : 'Sort output by <attribute>.',
                                    '--raw'                         : 'Output table without any headers/borders.',
                                    '--csv'                         : 'Output table as CSV.',
                                    '--csv-sep <separator>'         : 'Output table as CSV.',
                                    '--node-limit <limit>'          : 'Output <limit> member nodes.',
                                    '--token-limit <limit>'         : 'Output <limit> member tokens.',
                                    '--role-limit <limit>'          : 'Output <limit> member roles.',
                                    '--group-limit <limit>'         : 'Output <limit> member groups.',
                                    '--policy-limit <limit>'        : 'Output <limit> assigned policies.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List pools.',
                                    '-a'                        : 'List all pools.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool add {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                           : 'Add new pool.',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool del {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Delete pool.',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool touch {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch pool (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool enable {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable pool.',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool disable {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable pool.',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool rename {pool} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'Rename pool.',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool add_acl {pool} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Add ACL to pool.',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool del_acl {pool} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Delete ACL from pool.',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool show_acls {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Show ACLs of pool.',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool enable_acl_inheritance {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable ACL inheritance for pool.',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool disable_acl_inheritance {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable ACL inheritance for pool.',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool move [--keep-acls] {pool} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'Change pool unit.',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool remove_orphans {pool}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Remove orphan UUIDs.',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool description {pool} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'Set pool description.',
                                },
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
                    '_cmd_usage_help' : 'Usage: otpme-pool export --password <password> {pool}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Export pool config to stdout.',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_node'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool add_node {pool} {node}',
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add node to pool.',
                                },
                },

    'remove_node'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool remove_node {pool} {node}',
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove node from pool.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool add_policy {pool} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add policy to pool.',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-pool remove_policy {pool} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove policy from pool.',
                                },
                },

    'list_nodes'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool list_nodes {pool}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List assigned nodes.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-pool list_policies {pool}',
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
