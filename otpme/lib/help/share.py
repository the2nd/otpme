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
    register_cmd_help(command="share", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-share {command} [share]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-share show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [share]'),
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --node-limit :max_nodes: --hosts-litmit :max_hosts: --group-limit :max_groups: --pool-limit :max_pools: --token-limit :max_tokens: --role-limit :max_roles: --policy-limit :max_policies: --limit :limit: [|object|]',
                    '_help' :   {
                                    'cmd'                           : _('Show share(s)'),
                                    '-a'                            : _('Show all shares.'),
                                    '-z <limit>'                    : _('Limit output size'),
                                    '--fields f1,f2,f3'             : _('Output only given fields'),
                                    '--reverse'                     : _('Reverse the output order.'),
                                    '--sort-by <attribute>'         : _('Sort output by <attribute>.'),
                                    '--raw'                         : _('Output table without any headers/borders.'),
                                    '--csv'                         : _('Output table as CSV.'),
                                    '--csv-sep <separator>'         : _('Output table as CSV.'),
                                    '--node-limit <limit>'          : _('Output <limit> member nodes.'),
                                    '--host-limit <limit>'          : _('Output <limit> member hosts.'),
                                    '--pool-limit <limit>'          : _('Output <limit> member pools.'),
                                    '--token-limit <limit>'         : _('Output <limit> member tokens.'),
                                    '--role-limit <limit>'          : _('Output <limit> member roles.'),
                                    '--group-limit <limit>'         : _('Output <limit> member groups.'),
                                    '--policy-limit <limit>'        : _('Output <limit> assigned policies.'),
                                    '--limit <limit>'               : _('Limit number of items shown per object.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List shares.'),
                                    '-a'                        : _('List all shares.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share add [--force-group <group>] [--force-directory-mode <mode>] [--force-create-mode <mode>] [--crypt] [--no-key-gen] [--block-size <block_size>] [--key-len <key_len>] [--home-share] [--restore <restore_share>] [--restore-token <token>] share}'),
                    'cmd'   :   '--force-group :force_group: --force-directory-mode :force_directory_mode: --force-create-mode :force_create_mode: --crypt :encrypted=True: --no-key-gen :no_key_gen=True: --block-size :block_size: --key-len :key_len: --home-share :home_share=True: --restore :restore_share: --restore-token :restore_token: <|object|>',
                    '_help' :   {
                                    'cmd'                           : _('Add new share.'),
                                    '--home-share'                  : _('Add home share.'),
                                    '--force-group <group>'         : _('Force group.'),
                                    '--force-create-mode <mode>'    : _('Force create mode.'),
                                    '--force-directory-mode <mode>' : _('Force directory mode.'),
                                    '--crypt'                       : _('Add encrypted share.'),
                                    '--no-key-gen'                  : _('Don\'t generate AES key.'),
                                    '--key-len <key_len>'           : _('Generate AES key of length <key_len>.'),
                                    '--block-size <blocksize>'      : _('Encrypted share block size (default 4096).'),
                                    '--restore <restore_share>'     : _('Add restore share.'),
                                    '--restore-token <token>'       : _('Add token restore share.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share del {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete share.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share get_config {share} {parameter}'),
                    'cmd'   :   '<|object|> <parameter>',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share touch {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch share (e.g. migrate).'),
                                },
                },

    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share changelog {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },

    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share edit_changelog {share} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <comment>',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },

    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share del_changelog {share} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },
    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share clear_changelog {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

    'root_dir'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share root_dir {share} {/root/dir}'),
                    'cmd'   :   '<|object|> <root_dir>',
                    '_help' :   {
                                    'cmd'                   : _('Set share root dir.'),
                                },
                },

    'force_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share force_group {share} {group}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Files and directories will always be owned by group.'),
                                },
                },

    'force_create_mode'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share force_create_mode {share} {create_mode}'),
                    'cmd'   :   '<|object|> <create_mode>',
                    '_help' :   {
                                    'cmd'                   : _('Set share file create mode.'),
                                },
                },

    'force_directory_mode'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share force_directory_mode {share} {create_mode}'),
                    'cmd'   :   '<|object|> <create_mode>',
                    '_help' :   {
                                    'cmd'                   : _('Set share directory create mode.'),
                                },
                },

     'enable_ro'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share enable_ro {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Make share readonly.'),
                                },
                },


     'disable_ro'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share disable_ro {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Make share read-write.'),
                                },
                },

    'get_share_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share get_share_key {share} {user}'),
                    'cmd'   :   '<|object|> <username>',
                    '_help' :   {
                                    'cmd'                   : _('Get encrypted share key from share.'),
                                },
                },



    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share enable [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on new share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on new share permissions.'),
                                    '--persist-mount'       : _('Persist new share mount on hosts.'),
                                    '--no-persist-mount'    : _('Do not persist new share mount on hosts.'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share disable [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on revoked share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on revoked share permissions.'),
                                    '--persist-mount'       : _('Also remove persisted share mount on hosts.'),
                                    '--no-persist-mount'    : _('Keep persisted share mount on hosts (transient unmount only).'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share rename {share} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename share.'),
                                },
                },

    'mount_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share mount_script {share} {mount_script} -- [script_options]'),
                    'cmd'   :   '<|object|> <mount_script> [script_options]',
                    '_help' :   {
                                    'cmd'                   : _('Change share mount script'),
                                },
                },

    'enable_mount_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share enable_mount_script {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable share mount script'),
                                },
                },

    'disable_mount_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share disable_mount_script {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable share mount script'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_acl {share} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to share.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share del_acl {share} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from share.'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share show_acls {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of share.'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share enable_acl_inheritance {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for share.'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share disable_acl_inheritance {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for share.'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share move [--keep-acls] {share} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change share unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_orphans {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs.'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share description {share} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set share description.'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share info {share} [info]'),
                    'cmd'   :   '--language :language: <|object|> [info]',
                    '_help' :   {
                                    'cmd'                   : _('Set share info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share dump_info {share}'),
                    'cmd'   :   '--language :language: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump share info'),
                                    '--language <lang>'     : _('Dump info for language.'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share config -d -a {share} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to share.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-share show_config {share} [parameter]'),
                    'cmd'   :   '<|object|> [parameter]',
                    '_help' :   {
                                    'cmd'                   : _('Show share\'s config parameters'),
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
                    '_cmd_usage_help' : _('Usage: otpme-share export --password <password> {share}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export share config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_pool'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_pool {share} {pool}'),
                    'cmd'   :   '<|object|> <pool_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add pool to share.'),
                                },
                },

    'remove_pool'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_pool {share} {pool}'),
                    'cmd'   :   '<|object|> <pool_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove pool from share.'),
                                },
                },

    'add_host'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_host [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {host}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add host to share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on new share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on new share permissions.'),
                                    '--persist-mount'       : _('Persist new share mount on hosts.'),
                                    '--no-persist-mount'    : _('Do not persist new share mount on hosts.'),
                                },
                },

    'remove_host'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_host [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {host}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove host from share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on revoked share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on revoked share permissions.'),
                                    '--persist-mount'       : _('Also remove persisted share mount on hosts.'),
                                    '--no-persist-mount'    : _('Keep persisted share mount on hosts (transient unmount only).'),
                                },
                },

    'limit_hosts'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host limit_hosts [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Limit share access to assigend host (groups).'),
                                    '--share-notify'        : _('Send notification to all online hosts on revoked share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on revoked share permissions.'),
                                    '--persist-mount'       : _('Also remove persisted share mount on hosts.'),
                                    '--no-persist-mount'    : _('Keep persisted share mount on hosts (transient unmount only).'),
                                },
                },

    'unlimit_hosts'    : {
                    '_cmd_usage_help' : _('Usage: otpme-host unlimit_hosts [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Unlimit share access.'),
                                    '--share-notify'        : _('Send notification to all online hosts on new share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on new share permissions.'),
                                    '--persist-mount'       : _('Persist new share mount on hosts.'),
                                    '--no-persist-mount'    : _('Do not persist new share mount on hosts.'),
                                },
                },

    'add_node'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_node {share} {node}'),
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add node to share.'),
                                },
                },

    'remove_node'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_node {share} {node}'),
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove node from share.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_policy {share} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to share.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_policy {share} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from share.'),
                                },
                },

    'add_master_password_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_master_password_token {share} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Allow token to mount share with master password.'),
                                },
                },

    'remove_master_password_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_master_password_token {share} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove master password token from share.'),
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_token [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {token}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Add token to share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on new share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on new share permissions.'),
                                    '--persist-mount'       : _('Persist new share mount on hosts.'),
                                    '--no-persist-mount'    : _('Do not persist new share mount on hosts.'),
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_token [--remove-share-key] [--keep-share-key] [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {token}'),
                    'cmd'   :   '--keep-share-key :keep_share_key=True: --remove-share-key :keep_share_key=False: --share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on revoked share permissions.'),
                                    '--keep-share-key'      : _('Keep share key.'),
                                    '--remove-share-key'    : _('Remove share key.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on revoked share permissions.'),
                                    '--persist-mount'       : _('Also remove persisted share mount on hosts.'),
                                    '--no-persist-mount'    : _('Keep persisted share mount on hosts (transient unmount only).'),
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_role [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {role}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add role to share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on new share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on new share permissions.'),
                                    '--persist-mount'       : _('Persist new share mount on hosts.'),
                                    '--no-persist-mount'    : _('Do not persist new share mount on hosts.'),
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_role [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {role}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on revoked share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on revoked share permissions.'),
                                    '--persist-mount'       : _('Also remove persisted share mount on hosts.'),
                                    '--no-persist-mount'    : _('Keep persisted share mount on hosts (transient unmount only).'),
                                },
                },

    'add_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share add_group [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {group}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add (host) group to share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on new share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on new share permissions.'),
                                    '--persist-mount'       : _('Persist new share mount on hosts.'),
                                    '--no-persist-mount'    : _('Do not persist new share mount on hosts.'),
                                },
                },

    'remove_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share remove_group [--share-notify] [--no-share-notify] [--persist-mount] [--no-persist-mount] {share} {group}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --persist-mount :persist_mount=True: --no-persist-mount :persist_mount=False: <|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove (host) group from share.'),
                                    '--share-notify'        : _('Send notification to all online hosts on revoked share permissions.'),
                                    '--no-share-notify'     : _('Dont send notification to all online hosts on revoked share permissions.'),
                                    '--persist-mount'       : _('Also remove persisted share mount on hosts.'),
                                    '--no-persist-mount'    : _('Keep persisted share mount on hosts (transient unmount only).'),
                                },
                },

    'list_groups'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_groups {share}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List (host) groups assigend to this share.'),
                                },
                },

    'list_pools'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_pools [--return-type <return_type>] {share}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned pools.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_nodes'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_nodes {share}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned nodes.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_hosts'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_hosts {share}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned hosts.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_users {share}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_tokens {share}'),
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List assigned tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_roles -r {share}'),
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List assigned roles.'),
                                    '-r'                    : _('List roles recursive.'),
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-share list_policies {share}'),
                    'cmd'   :   '--return-type :return_type: --policy-types :[policy_types]: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                           : _('List assigned policies.'),
                                    '--return-type'                 : 'Attribute to return.',
                                    '--policy-types <type1,type2>'  : _('Policy types to list.'),
                                },
                },
    }
