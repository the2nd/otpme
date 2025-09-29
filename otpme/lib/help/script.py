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
    register_cmd_help(command="script", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-script {command} [script]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-script show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [script]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show script(s)'),
                                    '-a'                    : _('Show all scripts.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-script list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List scripts.'),
                                    '-a'                        : _('List all scripts.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script add [-r] {name} {script}'),
                    'cmd'   :   '-r :replace=True: <|object|> <script>',
                    '_help' :   {
                                    'cmd'                   : _('Add new script'),
                                    '-r'                    : _('Replace existing script and keep its UUID'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script del {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete script'),
                                },
                },


    'copy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script copy {src_script} {dst_script}'),
                    'cmd'   :   '<|object|> <destination_script>',
                    '_help' :   {
                                    'cmd'                   : _('Copy script and its signatures'),
                                },
                },


    'sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script sign --stdin-pass [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Sign script'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin'),
                                    '--tags'                : _('Tags to add to the signature.'),
                                },
                },


    'resign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script resign --stdin-pass {name}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Resign script signatures'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin'),
                                },
                },


    'get_sign_data'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script get_sign_data [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Get data to be signed from script'),
                                    '--tags'                : _('Add sign tags to the sign object.'),
                                },
                },


    'add_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script add_sign [--tags tag1,tag2...] {name} {signature}'),
                    'cmd'   :   '--tags :[tags]: <|object|> <signature>',
                    '_help' :   {
                                    'cmd'                   : _('Add new signature to script'),
                                    '--tags'                : _('Tags included in the signature.'),
                                },
                },

    'del_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script del_sign [--user username] [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete signature from script'),
                                    '--user'                : _('Select signature by username.'),
                                    '--tags'                : _('Select signature by tags.'),
                                },
                },


    'verify_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script verify_sign [--user username] [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Verify script signature(s)'),
                                    '--user'                : _('Select signature by username.'),
                                    '--tags'                : _('Select signature by tags.'),
                                },
                },


    'get_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script get_sign [--user username] [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Get script signature(s)'),
                                    '--user'                : _('Select signature by username.'),
                                    '--tags'                : _('Select signature by tags.'),
                                },
                },


    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script touch {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch script (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script enable {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable script'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script disable {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable script'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script rename {script} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename script'),
                                },
                },


    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-script add_acl {script} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to script'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-script del_acl {script} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from script'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script show_acls {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of script'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script enable_acl_inheritance {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for script'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script disable_acl_inheritance {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for script'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script move [--keep-acls] {script} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change script\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-script remove_orphans {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script description {script} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set script description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-script export --password <password> {script}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export script config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script add_policy {script} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to script'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-script remove_policy {script} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from script'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-script list_policies {script}'),
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

    'dump'   : {
                    '_cmd_usage_help' : _('Usage: otpme-script dump {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump script to stdout'),
                                },
                },


    'edit'   : {
                    '_cmd_usage_help' : _('Usage: otpme-script edit {script}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Edit script'),
                                },
                },

    'run'   : {
                    '_ignore_unknown_opts'  : True,
                    '_cmd_usage_help' : _('Usage: otpme-script run --type key_script {script}'),
                    'cmd'   :   '--type ::script_type:: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Run script'),
                                    '--type'                : _('Run script as <type> script'),
                                },
                },
    }
