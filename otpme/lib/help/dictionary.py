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
    register_cmd_help(command="dictionary", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-dictionary {command} [dict_name]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [dict_name]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show dictionaries',
                                    '-a'                    : 'Show all dictionaries.',
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
                    '_cmd_usage_help' : 'Usage: otpme-dictionary list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List dictionaries.',
                                    '-a'                        : 'List all dictionaries..',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary add {dict_name} [dict_type]',
                    'cmd'   :   '<|object|> [dict_type]',
                    '_help' :   {
                                    'cmd'                   : 'add new dictionary',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary del {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete dictionary',
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary touch {dictionary}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch dictionary (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary enable {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable dictionary',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary disable {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable dictionary',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary rename {dict_name} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename dictionary',
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary add_acl {dict_name} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to dictionary',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary del_acl {dict_name} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from dictionary',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary show_acls {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of dictionary',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary enable_acl_inheritance {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for dictionary',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary disable_acl_inheritance {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for dictionary',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary move [--keep-acls] {dict_name} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change dictionarys unit',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary description {dict_name} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set dictionary description',
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
                    '_cmd_usage_help' : 'Usage: otpme-dictionary export --password <password> {dict_name}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export dictionary config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary add_policy {dictionary} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to dictionary',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary remove_policy {dictionary} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from dictionary',
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary list_policies {dictionary}',
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
    'word_learning'   : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary word_learning {dict_name} {file}',
                    'cmd'   :   '<|object|> [dict_file]',
                    '_help' :   {
                                    'cmd'                   : '"learn" words from file',
                                },
                },


    'word_import'   : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary word_import {dict_name} {file}',
                    'cmd'   :   '<|object|> [dict_file]',
                    '_help' :   {
                                    'cmd'                   : 'import words from file',
                                },
                },

    'word_export'   : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary word_export {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export words to stdout',
                                },
                },

    'clear'         : {
                    '_cmd_usage_help' : 'Usage: otpme-dictionary clear {dict_name}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove all dictionary data',
                                },
                },
    }
