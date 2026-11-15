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

from .. import register_cmd_help

def register():
    register_cmd_help(command="resolver", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-resolver [--type <resolver_type>] {command} [resolver]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [--limit <limit>] [--sort-by <attribute>] [--reverse] [--raw] [--csv] [--csv-sep <separator>] [resolver]'),
                    'cmd'   :   '--policy-limit :max_policies: --limit :limit: --fields :"output_fields": -z :max_len: --sort-by :"sort_by": --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :"csv_sep": [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show resolvers.'),
                                    '-a'                    : _('Show all resolvers.'),
                                    '-z <limit>'            : _('Limit output size.'),
                                    '--fields f1,f2,f3'     : _('Output only given fields.'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--limit <limit>'       : _('Limit number of items shown per object.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Separator between the CSV columns.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver list [--attribute attribute] [-a] [pattern]'),
                    'cmd'   :   '--attribute :"attribute": -a :show_all=True: ["search_regex"]',
                    '_help' :   {
                                    'cmd'                       : _('List resolvers.'),
                                    '-a'                        : _('List all resolvers.'),
                                    '--attribute <attribute>'   : _('Match the pattern against this attribute instead of the name.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver --type <resolver_type> add {resolver}'),
                    '_help' :   {
                                    'cmd'                       : _('Add new resolver.'),
                                    '--type <resolver_type>'    : _('Resolver type (e.g. ldap).'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del [--no-trash] {resolver}'),
                    'cmd'   :   '--no-trash :add_to_trash=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete resolver.'),
                                    '--no-trash'            : _('Delete without moving the object to the trash.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver touch {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch resolver (e.g. migrate).'),
                                },
                },

    'auto_disable'          : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver auto_disable [-u] {resolver} {time}'),
                    'cmd'   :   '-u :unused=True: <|object|> <auto_disable>',
                    '_help' :   {
                                    'cmd'                   : _('Change auto disable value (e.g "+30D" or "09:53 13.06.2023", 0 removes it).'),
                                    '-u'                    : _('Disable object if it was unused for the given time.'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver enable {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable resolver.'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver disable {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable resolver.'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver rename {resolver} {new_name}'),
                    'cmd'   :   '<|object|> <"new_name">',
                    '_help' :   {
                                    'cmd'                   : _('Rename resolver.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver get_config {resolver} {parameter}'),
                    'cmd'   :   '<|object|> <"parameter">',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },
    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver show_config {resolver} [parameter]'),
                    'cmd'   :   '<|object|> ["parameter"]',
                    '_help' :   {
                                    'cmd'                   : _('Show resolver config parameters'),
                                },
                },
    'show_oid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver show_oid [--full] {resolver}'),
                    'cmd'   :   '--full :full=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the OID of the object.'),
                                    '--full'                : _('Show the full OID.'),
                                },
                },
    'show_uuid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver show_uuid {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the UUID of the object.'),
                                },
                },
    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver changelog {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },
    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver edit_changelog {resolver} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <"comment">',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },
    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del_changelog {resolver} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },
    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver clear_changelog {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver config [-d] [-a] {resolver} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <"parameter"> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to resolver.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_acl {resolver} {role|token} {role_path|token_path} {acl[:value][,acl[:value]]}'),
                    'cmd'   :   '<|object|> <"owner_type"> <"owner_name"> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to resolver.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del_acl {resolver} {acl[,acl]}'),
                    'cmd'   :   '<|object|> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from resolver.'),
                                },
                },

     'list_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver list_acls {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List ACLs set on this resolver.'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver enable_acl_inheritance {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for resolver.'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver disable_acl_inheritance {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for resolver.'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver move [--keep-acls] {resolver} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <"new_unit">',
                    '_help' :   {
                                    'cmd'                   : _('Change resolver\'s unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver description {resolver} [description]'),
                    'cmd'   :   '<|object|> ["description"]',
                    '_help' :   {
                                    'cmd'                   : _('Set resolver description.'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver info [--language <language>] {resolver} [info]'),
                    'cmd'   :   '--language :"language": <|object|> ["info"]',
                    '_help' :   {
                                    'cmd'                   : _('Set resolver info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver dump_info [--language <language>] {resolver}'),
                    'cmd'   :   '--language :"language": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump resolver info'),
                                    '--language <lang>'     : _('Dump info for language.'),
                                },
                },

    '_list_valid_object_classes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_list_valid_attributes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_object_classes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_config'    : {
                    'cmd'   :   '<|object|>',
                },

    'export'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver export [--password <password>] {resolver}'),
                    'cmd'   :   '--password :"password": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export resolver config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver remove_orphans {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_policy {resolver} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to resolver.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver remove_policy {resolver} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from resolver.'),
                                },
                },

    'enable_sync_units' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver enable_sync_units {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable sync of units.'),
                                },
                },

    'disable_sync_units' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver disable_sync_units {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable sync of units.'),
                                },
                },

    'enable_deletions' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver enable_deletions {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable deletions of objects missing on resolver site.'),
                                },
                },

    'disable_deletions' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver disable_deletions {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable deletions of objects missing on resolver site.'),
                                },
                },

    'key_attribute' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver key_attribute {resolver} {object_type} {attribute}'),
                    'cmd'   :   '<|object|> <"object_type"> <"key_attribute">',
                    '_help' :   {
                                    'cmd'                   : _('Set key attribute used to sync objects (e.g. entryUUID).'),
                                },
                },

    'run'           : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver run [--object-types <object_types>] {resolver}'),
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Run resolver.'),
                                },
                },

    'sync_interval': {
                    '_cmd_usage_help' : _('Usage: otpme-resolver sync_interval {resolver} {sync_interval}'),
                    'cmd'   :   '<|object|> <"sync_interval">',
                    '_help' :   {
                                    'cmd'                       : _('Set resolver sync interval.'),
                                },
                },

    'get_objects': {
                    '_cmd_usage_help' : _('Usage: otpme-resolver get_objects [--object-types object_types] {resolver}'),
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                       : _('Get resolver objects.'),
                                    '--object-types user,group' : _('Get only the following object types.'),
                                },
                },

    'delete_objects': {
                    '_cmd_usage_help' : _('Usage: otpme-resolver delete_objects [--object-types object_types] {resolver}'),
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                       : _('Delete resolver objects.'),
                                    '--object-types user,group' : _('Delete only the following object types.'),
                                },
                },

    'test'          : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver test [--object-types <object_types>] {resolver}'),
                    'cmd'   :   '--object-types :[object_types]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Test resolver.'),
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver list_policies [--return-type <type>] [--policy-types <type1,type2>] {resolver}'),
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
