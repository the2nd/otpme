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
    register_cmd_help(command="unit", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-unit {command} [unit]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-unit show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [unit]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show unit(s)',
                                    '-a'                    : 'Show all units.',
                                    '-z <limit>'            : 'limit output size',
                                    '--fields f1,f2,f3'     : 'output only given fields',
                                    '--policy-limit <limit>': 'Output max policies.',
                                    '--reverse'             : 'Reverse the output order.',
                                    '--sort-by <attribute>' : 'Sort output by <attribute>.',
                                    '--raw'                 : 'Output table without any headers/borders.',
                                    '--csv'                 : 'Output table as CSV.',
                                    '--csv-sep <separator>' : 'Output table as CSV.',
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List units:',
                                    '-a'                        : 'List all units.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : 'Usage: otpme-unit show_config {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show units config parameters',
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit add {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new unit',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit del {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete unit',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit touch {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch unit (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit enable {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable unit',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit disable {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable unit',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit rename {unit} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename unit',
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit config {unit} {param} [value]',
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : 'Add config parameter to unit.',
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit add_extension {unit} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'add extension to unit',
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit remove_extension {unit} {extension}',
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : 'remove extension from unit',
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit add_attribute {unit} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) attribute to unit',
                                },
                },

     'modify_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit modify_attribute {unit} {attribute} {old_value} {new_value}',
                    'cmd'   :   '<|object|> <attribute> <old_value> <new_value>',
                    '_help' :   {
                                    'cmd'                   : 'modify (ldap) attribute of unit',
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit del_attribute {unit} {attribute}=[value]',
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) attribute from unit',
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit add_object_class {unit} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'add (ldap) object class to unit',
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit del_object_class {unit} {object_class}',
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : 'delete (ldap) object class from unit',
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit show_ldif {unit} -a attribute1,attribute2',
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : 'show ldif representation of unit',
                                    '-a'                    : 'show only given LDIF attributes',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-unit add_acl [-r -a --objects <user,group,token>] {unit} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: --objects :[object_types]: <|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                           : 'add ACL to unit',
                                    '-r'                            : 'set ACL recursive',
                                    '-a'                            : 'apply default ACLs to existing objects',
                                    '--objects <user,group,token>'  : 'add ACLs to this object types only',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-unit del_acl [-r -a --objects <user,group,token>] {unit} {acl}',
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: --objects :[object_types]: <|object|> <acl>',
                    '_help' :   {
                                    'cmd'                           : 'delete ACL from unit',
                                    '-r'                            : 'delete ACL recursive',
                                    '-a'                            : 'delete default ACLs from existing objects',
                                    '--objects <user,group,token>'  : 'delete ACLs from this object types only',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit show_acls {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of unit',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit enable_acl_inheritance {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for unit',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit disable_acl_inheritance {unit}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for unit',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit move [-m] [-k] [-o user,group,...] [--keep-acls] {unit} {new_unit}',
                    'cmd'   :   '-m :merge=True: -k :keep_old_unit=True: --keep-acls :keep_acls=True: -o :[object_types]: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'Change units unit.',
                                    '-m'                    : 'Merge objects from src unit into dst unit.',
                                    '-k'                    : 'Keep source unit.',
                                    '--keep-acls'           : 'Keep object ACLs.',
                                    '-o <user,group,...>'   : 'Move only given object types.',
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-unit remove_orphans {unit}',
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                    '-r'                    : 'remove orphan UUIDs recursive',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit description {unit} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set unit description',
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
                    '_cmd_usage_help' : 'Usage: otpme-unit export --password <password> {unit}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export unit config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit add_policy {unit} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to unit',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-unit remove_policy {unit} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from unit',
                                },
                },
    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-unit list_policies {unit}',
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
