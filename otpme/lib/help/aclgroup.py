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
    register_cmd_help(command="aclgroup", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-aclgroup {command} [aclgroup]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [--limit <limit>] [--sort-by <attribute>] [--reverse] [--raw] [--csv] [--csv-sep <separator>] [aclgroup]'),
                    'cmd'   :   '--fields :"output_fields": -z :max_len: --sort-by :"sort_by": --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :"csv_sep": --policy-limit :max_policies: --limit :limit: [|object|]',
                    '_help' :   {
                                    'cmd'                           : _('Show ACL group(s)'),
                                    '-a'                            : _('Show all ACL groups.'),
                                    '-z <limit>'                    : _('Limit output size'),
                                    '--fields f1,f2,f3'             : _('Output only given fields'),
                                    '--reverse'                     : _('Reverse the output order.'),
                                    '--sort-by <attribute>'         : _('Sort output by <attribute>.'),
                                    '--raw'                         : _('Output table without any headers/borders.'),
                                    '--csv'                         : _('Output table as CSV.'),
                                    '--csv-sep <separator>'         : _('Separator between the CSV columns.'),
                                    '--policy-limit <limit>'        : _('Output <limit> assigned policies.'),
                                    '--limit <limit>'               : _('Limit number of items shown per object.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup list [--attribute attribute] [-a] [pattern]'),
                    'cmd'   :   '--attribute :"attribute": -a :show_all=True: ["search_regex"]',
                    '_help' :   {
                                    'cmd'                       : _('List ACL groups.'),
                                    '-a'                        : _('List all ACL groups.'),
                                    '--attribute <attribute>'   : _('Match the pattern against this attribute instead of the name.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup add {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                           : _('Add new ACL group.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup del [--no-trash] {aclgroup}'),
                    'cmd'   :   '--no-trash :add_to_trash=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL group.'),
                                    '--no-trash'            : _('Delete without moving the object to the trash.'),
                                },
                },

    'add_entry'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup add_entry {aclgroup} {object_type:acl[:value][,object_type:acl[:value]]}'),
                    'cmd'   :   '<|object|> <[entries]>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACLs to the ACL group, each for an object type.'),
                                },
                },

    'remove_entry'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup remove_entry {aclgroup} {object_type:acl[:value][,object_type:acl[:value]]}'),
                    'cmd'   :   '<|object|> <[entries]>',
                    '_help' :   {
                                    'cmd'                   : _('Remove ACLs from the ACL group.'),
                                },
                },

    'get_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup get_acls [-r] {aclgroup}'),
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the ACLs of the ACL group.'),
                                    '-r'                    : _('Also the ACLs it inherits from the ACL groups it is a member of.'),
                                },
                },

    'add_aclgroup'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup add_aclgroup {aclgroup} {member_aclgroup}'),
                    'cmd'   :   '<|object|> <"aclgroup_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add an ACL group to this one. This one gets its entries too.'),
                                },
                },

    'remove_aclgroup'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup remove_aclgroup {aclgroup} {member_aclgroup}'),
                    'cmd'   :   '<|object|> <"aclgroup_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove an ACL group from this one.'),
                                },
                },

    'list_aclgroups'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup list_aclgroups [-r] {aclgroup}'),
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List the ACL groups that were added to this one.'),
                                    '-r'                    : _('Also those added to them, and so on.'),
                                },
                },

    'find_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup find_acls {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Find the objects the ACL group is given on, and to whom.'),
                                },
                },

    'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup config [-d] [-a] {aclgroup} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <"parameter"> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to ACL group.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup get_config {aclgroup} {parameter}'),
                    'cmd'   :   '<|object|> <"parameter">',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },
    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup show_config {aclgroup} [parameter]'),
                    'cmd'   :   '<|object|> ["parameter"]',
                    '_help' :   {
                                    'cmd'                   : _('Show ACL group config parameters'),
                                },
                },

    'show_oid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup show_oid [--full] {aclgroup}'),
                    'cmd'   :   '--full :full=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the OID of the object.'),
                                    '--full'                : _('Show the full OID.'),
                                },
                },
    'show_uuid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup show_uuid {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the UUID of the object.'),
                                },
                },
    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup changelog {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },

    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup edit_changelog {aclgroup} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <"comment">',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },

    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup del_changelog {aclgroup} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },

    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup clear_changelog {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup touch {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch ACL group (e.g. migrate).'),
                                },
                },

    'auto_disable'          : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup auto_disable {aclgroup} {time}'),
                    'cmd'   :   '<|object|> <auto_disable>',
                    '_help' :   {
                                    'cmd'                   : _('Change auto disable value (e.g "+30D" or "09:53 13.06.2023", 0 removes it).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup enable {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL group.'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup disable {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL group.'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup rename {aclgroup} {new_name}'),
                    'cmd'   :   '<|object|> <"new_name">',
                    '_help' :   {
                                    'cmd'                   : _('Rename ACL group.'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup add_acl {aclgroup} {role|token} {role_path|token_path} {acl[:value][,acl[:value]]}'),
                    'cmd'   :   '<|object|> <"owner_type"> <"owner_name"> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to ACL group.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup del_acl {aclgroup} {acl[,acl]}'),
                    'cmd'   :   '<|object|> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from ACL group.'),
                                },
                },

     'list_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup list_acls {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List ACLs set on this ACL group.'),
                                },
                },

     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup enable_acl_inheritance {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for ACL group.'),
                                },
                },

     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup disable_acl_inheritance {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for ACL group.'),
                                },
                },

    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup move [--keep-acls] {aclgroup} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <"new_unit">',
                    '_help' :   {
                                    'cmd'                   : _('Change ACL group unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },

    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup remove_orphans {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs.'),
                                },
                },

    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup description {aclgroup} [description]'),
                    'cmd'   :   '<|object|> ["description"]',
                    '_help' :   {
                                    'cmd'                   : _('Set ACL group description.'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup info [--language <language>] {aclgroup} [info]'),
                    'cmd'   :   '--language :"language": <|object|> ["info"]',
                    '_help' :   {
                                    'cmd'                   : _('Set ACL group info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup dump_info [--language <language>] {aclgroup}'),
                    'cmd'   :   '--language :"language": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump ACL group info'),
                                    '--language <lang>'     : _('Dump info for language.'),
                                },
                },

    'show_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup show_info {aclgroup}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the languages that have an info'),
                                },
                },

    '_show_config'    : {
                    'cmd'   :   '<|object|>',
                },

    'export'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup export [--password <password>] {aclgroup}'),
                    'cmd'   :   '--password :"password": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export ACL group config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup add_policy {aclgroup} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to ACL group.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup remove_policy {aclgroup} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from ACL group.'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-aclgroup list_policies [--return-type <type>] [--policy-types <type1,type2>] {aclgroup}'),
                    'cmd'   :   '--return-type :"return_type": --policy-types :[policy_types]: <|object|>',
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
