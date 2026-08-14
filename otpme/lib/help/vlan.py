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
    register_cmd_help(command="vlan", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-vlan {command} [vlan]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan show [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [vlan]'),
                    'cmd'   :   '--fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: --policy-limit :max_policies: --limit :limit: [|object|]',
                    '_help' :   {
                                    'cmd'                           : _('Show VLAN(s)'),
                                    '-a'                            : _('Show all VLANs.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-vlan list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List VLANs.'),
                                    '-a'                        : _('List all VLANs.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add {vlan} [vlan_id]'),
                    'cmd'   :   '<|object|> [vlan_id]',
                    '_help' :   {
                                    'cmd'                           : _('Add new VLAN.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan del {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete VLAN.'),
                                },
                },

    'vlan_id'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan vlan_id {vlan} [vlan_id]'),
                    'cmd'   :   '<|object|> [vlan_id]',
                    '_help' :   {
                                    'cmd'                   : _('Change VLAN ID. Without an ID the VLAN name is sent to the switch.'),
                                },
                },

    'add_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add_token {vlan} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Add token to VLAN.'),
                                },
                },

    'remove_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan remove_token {vlan} {token}'),
                    'cmd'   :   '<|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from VLAN.'),
                                },
                },

    'add_role'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add_role {vlan} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add role to VLAN.'),
                                },
                },

    'remove_role'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan remove_role {vlan} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from VLAN.'),
                                },
                },

    'add_host'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add_host {vlan} {host}'),
                    'cmd'   :   '<|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add host to VLAN.'),
                                },
                },

    'remove_host'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan remove_host {vlan} {host}'),
                    'cmd'   :   '<|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove host from VLAN.'),
                                },
                },

    'add_device'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add_device {vlan} {device}'),
                    'cmd'   :   '<|object|> <device_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add device to VLAN.'),
                                },
                },

    'remove_device'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan remove_device {vlan} {device}'),
                    'cmd'   :   '<|object|> <device_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove device from VLAN.'),
                                },
                },

    'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan config -d -a {vlan} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to VLAN.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan get_config {vlan} {parameter}'),
                    'cmd'   :   '<|object|> <parameter>',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },

    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan changelog {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },

    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan edit_changelog {vlan} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <comment>',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },

    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan del_changelog {vlan} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },

    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan clear_changelog {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan touch {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch VLAN (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan enable {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable VLAN.'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan disable {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable VLAN.'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan rename {vlan} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename VLAN.'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add_acl {vlan} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to VLAN.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan del_acl {vlan} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from VLAN.'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan show_acls {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of VLAN.'),
                                },
                },

     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan enable_acl_inheritance {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for VLAN.'),
                                },
                },

     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan disable_acl_inheritance {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for VLAN.'),
                                },
                },

    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan move [--keep-acls] {vlan} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change VLAN unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },

    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan remove_orphans {vlan}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs.'),
                                },
                },

    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan description {vlan} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set VLAN description.'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan info {vlan} [info]'),
                    'cmd'   :   '--language :language: <|object|> [info]',
                    '_help' :   {
                                    'cmd'                   : _('Set VLAN info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan dump_info {vlan}'),
                    'cmd'   :   '--language :language: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump VLAN info'),
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
                    '_cmd_usage_help' : _('Usage: otpme-vlan export --password <password> {vlan}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export VLAN config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan add_policy {vlan} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to VLAN.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan remove_policy {vlan} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from VLAN.'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-vlan list_policies {vlan}'),
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
