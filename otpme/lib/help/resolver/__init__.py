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

from .. import register_cmd_help

def register():
    register_cmd_help(command="resolver", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-resolver [--type <resolver_type>] {command} [resolver]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [resolver]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: -a :show_all=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show resolvers.'),
                                    '-a'                    : _('Show all resolvers.'),
                                    '-z <limit>'            : _('Limit output size.'),
                                    '--fields f1,f2,f3'     : _('Output only given fields.'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver list [regex]'),
                    'cmd'   :   '[search_regex]',
                    '_help' :   {
                                    'cmd'                   : _('List resolvers.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-resolver del {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete resolver.'),
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
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename resolver.'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver config {resolver} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to resolver.'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_acl {resolver} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to resolver.'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del_acl {resolver} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from resolver.'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver show_acls {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of resolver.'),
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


    'unit'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver unit {resolver} {unit}'),
                    'cmd'   :   '<|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change resolver\'s unit.'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver description {resolver} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set resolver description.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-resolver export {resolver}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export resolver config to stdout.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_policy {resolver} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to resolver.'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver remove_policy {resolver} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
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
                    'cmd'   :   '<|object|> <object_type> <key_attribute>',
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
                    'cmd'   :   '<|object|> <sync_interval>',
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
                    '_cmd_usage_help' : _('Usage: otpme-resolver list_policies {resolver}'),
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
