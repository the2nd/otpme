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
    register_cmd_help(command="pass", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-pass {command} [password]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-pass show [--offline] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [password]'),
                    'cmd'   :   '--offline :offline=True: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --policy-limit :max_policies: --limit :limit: [|object|]',
                    '_help' :   {
                                    'cmd'                           : _('Show password object(s)'),
                                    '--offline'                     : _('Use the passwords kept on this host, without asking a node.'),
                                    '-a'                            : _('Show all password objects.'),
                                    '-z <limit>'                    : _('Limit output size'),
                                    '--fields f1,f2,f3'             : _('Output only given fields'),
                                    '--reverse'                     : _('Reverse the output order.'),
                                    '--sort-by <attribute>'         : _('Sort output by <attribute>.'),
                                    '--raw'                         : _('Output table without any headers/borders.'),
                                    '--csv'                         : _('Output table as CSV.'),
                                    '--csv-sep <separator>'         : _('Output table as CSV.'),
                                    '--policy-limit <limit>'        : _('Output <limit> assigned policies.'),
                                    '--limit <limit>'               : _('Limit number of items shown per object.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass list [--offline] [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--offline :offline=True: --attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List password objects.'),
                                    '--offline'                 : _('Use the passwords kept on this host, without asking a node.'),
                                    '-a'                        : _('List all password objects.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add [--node <node>] [--host <host>] [--device <device>] [--client <client>] [--username <username>] [--url <url>] [--notes <notes>] {password} [entry]'),
                    'cmd'   :   '--node :node: --host :host: --device :device: --client :client: --username :username: --url :url: --notes :notes: <|object|> [entry_name]',
                    '_help' :   {
                                    'cmd'                   : _('Add new password object, or add an entry to it.'),
                                    '--node <node>'         : _('The password belongs to this node.'),
                                    '--host <host>'         : _('The password belongs to this host.'),
                                    '--device <device>'     : _('The password belongs to this device.'),
                                    '--client <client>'     : _('The password belongs to this client.'),
                                    '--username <username>' : _('Username of the entry.'),
                                    '--url <url>'           : _('URL of the entry.'),
                                    '--notes <notes>'       : _('Notes of the entry.'),
                                },
                },

    'change_entry'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass change_entry [--username <username>] [--url <url>] [--notes <notes>] [--password] {password} {entry}'),
                    'cmd'   :   '--username :username: --url :url: --notes :notes: --password :new_password=True: <|object|> <entry_name>',
                    '_help' :   {
                                    'cmd'                   : _('Change entry of password object.'),
                                    '--username <username>' : _('New username of the entry.'),
                                    '--url <url>'           : _('New URL of the entry.'),
                                    '--notes <notes>'       : _('New notes of the entry.'),
                                    '--password'            : _('Ask for a new password.'),
                                },
                },

    'del_entry'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass del_entry {password} {entry}'),
                    'cmd'   :   '<|object|> <entry_name>',
                    '_help' :   {
                                    'cmd'                   : _('Delete entry of password object.'),
                                },
                },

    'show_password'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass show_password [--offline] {password} [entry]'),
                    'cmd'   :   '--offline :offline=True: <|object|> [entry_name]',
                    '_help' :   {
                                    'cmd'                   : _('Show entries of password object with their passwords.'),
                                    '--offline'             : _('Use the passwords kept on this host, without asking a node.'),
                                },
                },

    'list_entries'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass list_entries [--offline] {password}'),
                    'cmd'   :   '--offline :offline=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List entries of password object without their passwords.'),
                                    '--offline'             : _('Use the passwords kept on this host, without asking a node.'),
                                },
                },

    'update_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass update_keys {password} | --all [--unit <unit>]'),
                    'cmd'   :   '--all :all_passwords=True: --unit :unit: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Give the members of password_store_members the key and take it from the others.'),
                                    '--all'                 : _('All passwords you may give keys of (edit:keys).'),
                                    '--unit <unit>'         : _('With --all: only the passwords in this unit and the units below it.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass del [--no-trash] {password}'),
                    'cmd'   :   '--no-trash :add_to_trash=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete password object.'),
                                    '--no-trash'            : _('Delete without moving the object to the trash.'),
                                },
                },

    'add_node'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add_node {password} {node}'),
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add node to password object.'),
                                },
                },

    'remove_node'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass remove_node {password} {node}'),
                    'cmd'   :   '<|object|> <node_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove node from password object.'),
                                },
                },

    'add_host'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add_host {password} {host}'),
                    'cmd'   :   '<|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add host to password object.'),
                                },
                },

    'remove_host'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass remove_host {password} {host}'),
                    'cmd'   :   '<|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove host from password object.'),
                                },
                },

    'add_device'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add_device {password} {device}'),
                    'cmd'   :   '<|object|> <device_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add device to password object.'),
                                },
                },

    'remove_device'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass remove_device {password} {device}'),
                    'cmd'   :   '<|object|> <device_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove device from password object.'),
                                },
                },

    'add_client'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add_client {password} {client}'),
                    'cmd'   :   '<|object|> <client_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add client to password object.'),
                                },
                },

    'remove_client'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass remove_client {password} {client}'),
                    'cmd'   :   '<|object|> <client_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove client from password object.'),
                                },
                },

    'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass config -d -a {password} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to password object.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass get_config {password} {parameter}'),
                    'cmd'   :   '<|object|> <parameter>',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },
    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-pass show_config {password} [parameter]'),
                    'cmd'   :   '<|object|> [parameter]',
                    '_help' :   {
                                    'cmd'                   : _('Show password object config parameters'),
                                },
                },

    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass changelog {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },

    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass edit_changelog {password} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <comment>',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },

    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass del_changelog {password} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },

    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass clear_changelog {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass touch {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch password object (e.g. migrate).'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass rename {password} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename password object.'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add_acl {password} {role|token} {role_path|token_path} {acl[:value][,acl[:value]]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to password object.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pass del_acl {password} {acl[,acl]}'),
                    'cmd'   :   '<|object|> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from password object.'),
                                },
                },

     'list_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass list_acls {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List ACLs set on this password object.'),
                                },
                },

     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass enable_acl_inheritance {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for password object.'),
                                },
                },

     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass disable_acl_inheritance {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for password object.'),
                                },
                },

    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass move [--keep-acls] {password} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change password object unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },

    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pass remove_orphans {password}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs.'),
                                },
                },

    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass description {password} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set password object description.'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass info {password} [info]'),
                    'cmd'   :   '--language :language: <|object|> [info]',
                    '_help' :   {
                                    'cmd'                   : _('Set password object info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass dump_info {password}'),
                    'cmd'   :   '--language :language: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump password object info'),
                                    '--language <lang>'     : _('Dump info for language.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-pass export --password <password> {password}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export password object config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass add_policy {password} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to password object.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-pass remove_policy {password} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from password object.'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-pass list_policies {password}'),
                    'cmd'   :   '--return-type :return_type: --policy-types :[policy_types]: <|object|>',
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
