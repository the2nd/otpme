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
    register_cmd_help(command="script", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-script {command} [script]",

    'show'      : {
                    '_cmd_usage_help' : 'Usage: otpme-script show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [script]',
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'show script(s)',
                                    '-a'                    : 'Show all scripts.',
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
                    '_cmd_usage_help' : 'Usage: otpme-script list [--attribute attribute] [-a] [regex]',
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : 'List scripts.',
                                    '-a'                        : 'List all scripts.',
                                    '--attribute <attribute>'   : 'Output given attribute.'
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script add [-r] {name} {script}',
                    'cmd'   :   '-r :replace=True: <|object|> <script>',
                    '_help' :   {
                                    'cmd'                   : 'add new script',
                                    '-r'                    : 'replace existing script and keep its UUID',
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script del {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete script',
                                },
                },


    'copy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script add {src_script} {dst_script}',
                    'cmd'   :   '<|object|> <destination_script>',
                    '_help' :   {
                                    'cmd'                   : 'copy script and its signatures',
                                },
                },


    'sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script sign --stdin-pass [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--stdin-pass :stdin_pass=True: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Sign script',
                                    '--stdin-pass'          : 'Read passphrase for RSA private key from stdin',
                                    '--tags'                : 'Tags to add to the signature.',
                                },
                },


    'resign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script resign --stdin-pass {name}',
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Resign script signatures',
                                    '--stdin-pass'          : 'Read passphrase for RSA private key from stdin',
                                },
                },


    'get_sign_data'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script get_sign_data [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Get datga to be signed from script',
                                    '--tags'                : 'Add sign tags to the sign object.',
                                },
                },


    'add_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script add_sign [--tags tag1,tag2...] {name} {signature}',
                    'cmd'   :   '--tags :[tags]: <|object|> <signature>',
                    '_help' :   {
                                    'cmd'                   : 'add new signature to script',
                                    '--tags'                : 'Tags included in the signature.',
                                },
                },

    'del_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script del_sign [--user username] [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'delete signature from script',
                                    '--user'                : 'Select signature by username.',
                                    '--tags'                : 'Select signature by tags.',
                                },
                },


    'verify_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script verify_sign [--user username] [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'verify script signature(s)',
                                    '--user'                : 'Select signature by username.',
                                    '--tags'                : 'Select signature by tags.',
                                },
                },


    'get_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script get_sign [--user username] [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'get script signature(s)',
                                    '--user'                : 'Select signature by username.',
                                    '--tags'                : 'Select signature by tags.',
                                },
                },


    'touch'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script touch {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch script (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script enable {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable script',
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script disable {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable script',
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script rename {script} {new_name}',
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : 'rename script',
                                },
                },


    'add_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-script add_acl {script} {role|token} {role_path|token_path} {acl[:value]}',
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'add ACL to script',
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : 'Usage: otpme-script del_acl {script} {acl}',
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : 'delete ACL from script',
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script show_acls {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'show ACLs of script',
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script enable_acl_inheritance {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable ACL inheritance for script',
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script disable_acl_inheritance {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable ACL inheritance for script',
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script move [--keep-acls] {script} {unit}',
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : 'change scripts unit',
                                    '--keep-acls'           : 'Keep object ACLs.'
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : 'Usage: otpme-script remove_orphans {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'remove orphan UUIDs',
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script description {script} [description]',
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : 'set script description',
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
                    '_cmd_usage_help' : 'Usage: otpme-script export --password <password> {script}',
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'export script config to stdout',
                                    '--password <password>' : 'Encrypt object config with password.',
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script add_policy {script} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'add policy to script',
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : 'Usage: otpme-script remove_policy {script} {policy}',
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : 'remove policy from script',
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : 'Usage: otpme-script list_policies {script}',
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

    'dump'   : {
                    '_cmd_usage_help' : 'Usage: otpme-script dump {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'dump script to stdout',
                                },
                },


    'edit'   : {
                    '_cmd_usage_help' : 'Usage: otpme-script edit {script}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'edit script',
                                },
                },

    'run'   : {
                    '_ignore_unknown_opts'  : True,
                    '_cmd_usage_help' : 'Usage: otpme-script run --type key_script {script}',
                    'cmd'   :   '--type ::script_type:: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Run script',
                                    '--type'                : 'Run script as <type> script',
                                },
                },
    }
