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
    register_cmd_help(command="pool", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-pool {command} [pool]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-pool show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [pool]'),
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --node-limit :max_nodes: --token-limit :max_tokens: --role-limit :max_roles: --policy-limit :max_policies: [|object|]',
                    '_help' :   {
                                    'cmd'                           : _('Show pool(s)'),
                                    '-a'                            : _('Show all pools.'),
                                    '-z <limit>'                    : _('Limit output size'),
                                    '--fields f1,f2,f3'             : _('Output only given fields'),
                                    '--reverse'                     : _('Reverse the output order.'),
                                    '--sort-by <attribute>'         : _('Sort output by <attribute>.'),
                                    '--raw'                         : _('Output table without any headers/borders.'),
                                    '--csv'                         : _('Output table as CSV.'),
                                    '--csv-sep <separator>'         : _('Output table as CSV.'),
                                    '--node-limit <limit>'          : _('Output <limit> member nodes.'),
                                    '--token-limit <limit>'         : _('Output <limit> member tokens.'),
                                    '--role-limit <limit>'          : _('Output <limit> member roles.'),
                                    '--group-limit <limit>'         : _('Output <limit> member groups.'),
                                    '--policy-limit <limit>'        : _('Output <limit> assigned policies.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List pools.'),
                                    '-a'                        : _('List all pools.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool add {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                           : _('Add new pool.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool del {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete pool.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool touch {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch pool (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool enable {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable pool.'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool disable {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable pool.'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool rename {pool} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename pool.'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool add_acl {pool} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to pool.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool del_acl {pool} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from pool.'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool show_acls {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of pool.'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool enable_acl_inheritance {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for pool.'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool disable_acl_inheritance {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for pool.'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool move [--keep-acls] {pool} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change pool unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool remove_orphans {pool}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs.'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool description {pool} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set pool description.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-pool export --password <password> {pool}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export pool config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_node'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool add_node {pool} {node}'),
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add node to pool.'),
                                },
                },

    'remove_node'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool remove_node {pool} {node}'),
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove node from pool.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool add_policy {pool} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to pool.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pool remove_policy {pool} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from pool.'),
                                },
                },

    'list_nodes'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool list_nodes {pool}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned nodes.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pool list_policies {pool}'),
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
    }
