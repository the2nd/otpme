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
    register_cmd_help(command="share", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-share {command} [share]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-share show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [share]',
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --node-limit :max_nodes: --pool-limit :max_pools: --token-limit :max_tokens: --role-limit :max_roles: --policy-limit :max_policies: [|object|]',
                    '_help' :   {
                                    'cmd'                           : 'show share(s)',
                                    '-a'                            : 'Show all shares.',
                                    '-z <limit>'                    : 'limit output size',
                                    '--fields f1,f2,f3'             : 'output only given fields',
                                    '--reverse'                     : 'Reverse the output order.',
                                    '--sort-by <attribute>'         : 'Sort output by <attribute>.',
                                    '--raw'                         : 'Output table without any headers/borders.',
                                    '--csv'                         : 'Output table as CSV.',
                                    '--csv-sep <separator>'         : 'Output table as CSV.',
                                    '--node-limit <limit>'          : 'Output <limit> member nodes.',
                                    '--pool-limit <limit>'          : 'Output <limit> member pools.',
                                    '--token-limit <limit>'         : 'Output <limit> member tokens.',
                                    '--role-limit <limit>'          : 'Output <limit> member roles.',
                                    '--group-limit <limit>'         : 'Output <limit> member groups.',
                                    '--policy-limit <limit>'        : 'Output <limit> assigned policies.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List shares.',
                                    '-a'                        : 'List all shares.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share add [--crypt] [--no-key-gen] [--block-size <block_size>] [--key-len <key_len>] {share} {root_dir}',
                    'cmd'   :   '--crypt :encrypted=True: --no-key-gen :no_key_gen=True: --block-size :block_size: --key-len :key_len: <|object|> <root_dir>',
                    '_help' :   {
                                    'cmd'                       : 'Add new share.',
                                    '--crypt'                   : 'Add encrpyted share.',
                                    '--no-key-gen'              : 'Dont generate AES key.',
                                    '--key-len <key_len>'       : 'Generate AES key of length <key_len>.',
                                    '--block-size <blocksize>'  : 'Encrpyted share block size (default 4096).',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share del {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Delete share.',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share touch {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch share (e.g. migrate).',
                                },
                },

    'root_dir'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share root_dir {share} {/root/dir}',
                    'cmd'   :   '<|object|> <root_dir>',
                    '_help' :   {
                                    'cmd'                   : 'Set share root dir.',
                                },
                },

    'force_group'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share force_group {share} {group}',
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : 'Files and directories will always be owned by group.',
                                },
                },

    'force_create_mode'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share force_create_mode {share} {create_mode}',
                    'cmd'   :   '<|object|> <create_mode>',
                    '_help' :   {
                                    'cmd'                   : 'Set share file create mode.',
                                },
                },

    'force_directory_mode'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share force_directory_mode {share} {create_mode}',
                    'cmd'   :   '<|object|> <create_mode>',
                    '_help' :   {
                                    'cmd'                   : 'Set share directory create mode.',
                                },
                },

     'enable_ro'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share enable_ro {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Make share readonly.',
                                },
                },


     'disable_ro'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share disable_ro {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Make share read-write.',
                                },
                },

    'get_share_key'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share get_share_key {user} {user}',
                    'cmd'   :   '<|object|> <username>',
                    '_help' :   {
                                    'cmd'                   : 'Get encrypted share key from share.',
                                },
                },



    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share enable {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable share.',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share disable {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable share.',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share rename {share} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'Rename share.',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_acl {share} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Add ACL to share.',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share del_acl {share} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'Delete ACL from share.',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share show_acls {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Show ACLs of share.',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share enable_acl_inheritance {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Enable ACL inheritance for share.',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share disable_acl_inheritance {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Disable ACL inheritance for share.',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share move [--keep-acls] {share} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'Change share unit.',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_orphans {share}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Remove orphan UUIDs.',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share description {share} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'Set share description.',
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
                    '_cmd_usage_help' : 'Usage: otpme-share export --password <password> {share}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Export share config to stdout.',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_pool'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_pool {share} {pool}',
                    'cmd'   :   '<|object|> <pool_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add pool to share.',
                                },
                },

    'remove_pool'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_pool {share} {pool}',
                    'cmd'   :   '<|object|> <pool_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove pool from share.',
                                },
                },

    'add_node'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_node {share} {node}',
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add node to share.',
                                },
                },

    'remove_node'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_node {share} {node}',
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove node from share.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_policy {share} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add policy to share.',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_policy {share} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove policy from share.',
                                },
                },

    'add_master_password_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_master_password_token {share} {token}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Allow token to mount share with master password.',
                                },
                },

    'remove_master_password_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_master_password_token {share} {token}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove master password token from share.',
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_token {share} {token}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Add token to share.',
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_token {share} {token}',
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : 'Remove token from share.',
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share add_role {share} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Add role to share.',
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share remove_role {share} {role}',
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : 'Remove role from share.',
                                },
                },

    'list_pools'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share list_pools {share}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List assigned nodes.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_nodes'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share list_nodes {share}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List assigned nodes.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_users'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share list_users {share}',
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List users.',
                                    '--return-type'             : 'Attribute to return.',
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share list_tokens {share}',
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                       : 'List assigned tokens.',
                                    '--return-type'             : 'Attribute to return.',
                                    '--token-types <hotp,totp>' : 'Token types to list.',
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share list_roles -r {share}',
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'List assigned roles.',
                                    '-r'                    : 'List roles recursive..',
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-share list_policies {share}',
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
