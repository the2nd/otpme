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
    register_cmd_help(command="unit", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-unit {command} [unit]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-unit show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [unit]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show unit(s)'),
                                    '-a'                    : _('Show all units.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List units.'),
                                    '-a'                        : _('List all units.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-unit show_config {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show unit\'s config parameters'),
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit add {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new unit'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit del {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete unit'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit touch {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch unit (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit enable {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable unit'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit disable {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable unit'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit rename {unit} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename unit'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit config {unit} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to unit.'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit add_extension {unit} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to unit'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit remove_extension {unit} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from unit'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit add_attribute {unit} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) attribute to unit'),
                                },
                },

     'modify_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit modify_attribute {unit} {attribute} {old_value} {new_value}'),
                    'cmd'   :   '<|object|> <attribute> <old_value> <new_value>',
                    '_help' :   {
                                    'cmd'                   : _('Modify (LDAP) attribute of unit'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit del_attribute {unit} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) attribute from unit'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit add_object_class {unit} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) object class to unit'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit del_object_class {unit} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) object class from unit'),
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit show_ldif {unit} -a attribute1,attribute2'),
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : _('Show LDIF representation of unit'),
                                    '-a'                    : _('Show only given LDIF attributes'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-unit add_acl [-r -a --objects <user,group,token>] {unit} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: --objects :[object_types]: <|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                           : _('Add ACL to unit'),
                                    '-r'                            : _('Set ACL recursive'),
                                    '-a'                            : _('Apply default ACLs to existing objects'),
                                    '--objects <user,group,token>'  : _('Add ACLs to this object types only'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-unit del_acl [-r -a --objects <user,group,token>] {unit} {acl}'),
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: --objects :[object_types]: <|object|> <acl>',
                    '_help' :   {
                                    'cmd'                           : _('Delete ACL from unit'),
                                    '-r'                            : _('Delete ACLs recursive'),
                                    '-a'                            : _('Delete default ACLs from existing objects'),
                                    '--objects <user,group,token>'  : _('Delete ACLs from this object types only'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit show_acls {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of unit'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit enable_acl_inheritance {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for unit'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit disable_acl_inheritance {unit}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for unit'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit move [-m] [-k] [-o user,group,...] [--keep-acls] {unit} {new_unit}'),
                    'cmd'   :   '-m :merge=True: -k :keep_old_unit=True: --keep-acls :keep_acls=True: -o :[object_types]: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change unit\'s unit.'),
                                    '-m'                    : _('Merge objects from src unit into dst unit.'),
                                    '-k'                    : _('Keep source unit.'),
                                    '--keep-acls'           : _('Keep object ACLs.'),
                                    '-o <user,group,...>'   : _('Move only given object types.'),
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-unit remove_orphans {unit}'),
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                    '-r'                    : _('Remove orphan UUIDs recursive'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit description {unit} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set unit description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-unit export --password <password> {unit}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export unit config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit add_policy {unit} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to unit'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-unit remove_policy {unit} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from unit'),
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-unit list_policies {unit}'),
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
