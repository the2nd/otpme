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
    register_cmd_help(command="user", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-user {command} [user]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-user show [--fields <field1,field2,field3>] [--policy-limit <limit>] [-z <size_limit>] [-a] [-t] [user] [token]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: -t :show_templates=True: [|object|] [token_name]',
                    '_help' :   {
                                    'cmd'                   : _('Show user(s)'),
                                    '-a'                    : _('Show all users.'),
                                    '-t'                    : _('Show user templates.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List users.'),
                                    '-a'                        : _('List all users.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user add [--no-default-token] [--default-token <default_token>] [--default-token-type <token_type>] [--password <password>] [--group <group>] [--groups <group1,group2>] [--role <default_role>] [--roles <role1,role2>] [--attributes <attr1=val1,attr2=val2...> [-t] [--template <template_name>] [--no-qrcode] {user}'),
                    'cmd'   :   '--group :group: --groups :[groups]: --role :default_role: --roles :[default_roles]: --no-default-token :add_default_token=False: --default-token :default_token: --default-token-type :default_token_type: --password :password: --attributes :[ldif_attributes]: -t :template_object=True: --template :template_name: --no-qrcode :gen_qrcode=False: <|object|>',
                    '_help' :   {
                                    'cmd'                                   : _('Add new user.'),
                                    '--group <group>'                       : _('Users default group.'),
                                    '--groups <group1,group2>'              : _('Groups to add user to.'),
                                    '--role <default_role>'                 : _('Default role to add user\'s default token to.'),
                                    '--roles <role1,role2>'                 : _('Roles to add user to.'),
                                    '--no-default-token'                    : _('Do not create default token.'),
                                    '--no-qrcode'                           : _('Do not generate default token qrcode.'),
                                    '--default-token <token_name>'          : _('Get default token from TOKENSTORE.'),
                                    '--default-token-type <token_type>'     : _('Add default token of type <token_type>.'),
                                    '--password <password>'                 : _('Set password for default token (must be password token).'),
                                    '--attributes <attr1=val1,attr2=val2>'  : _('Add LDIF attributes to user.'),
                                    '--template'                            : _('Add user from template.'),
                                    '-t'                                    : _('Add user template.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user del {user}'),
                    'cmd'   :   '<|objects|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete user'),
                                },
                },

    'language'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user language {user} {language}'),
                    'cmd'   :   '<|object|> <language>',
                    '_help' :   {
                                    'cmd'                   : _('Set user\'s localization language.'),
                                },
                },

    'key_mode'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user key_mode {user} {key_mode}'),
                    'cmd'   :   '<|object|> <key_mode>',
                    '_help' :   {
                                    'cmd'                   : _('Set user key key mode (client or server)'),
                                },
                },

    'get_key_mode'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user get_key_mode {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Get user key key mode (client or server)'),
                                },
                },


    'gen_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user gen_keys [--server] [-b <bits>] [--pass-hash-type <hash_type>] [-n] {user}'),
                    'cmd'   :   '-b :key_len: --server :key_mode=server: --pass-hash-type :pass_hash_type: -n :encrypt_key=False: --stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                               : _('Generate user\'s RSA key pair'),
                                    '-b <bits>'                         : _('Key length in bits (e.g. 2048)'),
                                    '--server'                          : _('Generate key pair on server'),
                                    '-n'                                : _('Do not encrypt server side private key'),
                                    '--pass-hash-type <pass_hash_type>' : _('Hash type used to derive encryption key from password.'),
                                    '--stdin-pass'                      : _('Read passphrase for RSA private key from stdin'),
                                },
                },


    'del_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user del_keys {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                               : _('Delete user\'s RSA key pair'),
                                },
                },


    'key_pass'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user key_pass {user}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Change password of user\'s private key.'),
                                    '--stdin-pass'          : _('Read passphrase from stdin'),
                                },
                },

    'private_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user private_key {user}'),
                    'cmd'   :   '<|object|> <private_key>',
                    '_help' :   {
                                    'cmd'                   : _('Set user\'s RSA private key'),
                                },
                },


    'public_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user public_key {user}'),
                    'cmd'   :   '<|object|> <public_key>',
                    '_help' :   {
                                    'cmd'                   : _('Set user\'s RSA public key'),
                                },
                },


    'import_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user import_key [--server] [-n] [--stdin-key] {user} [private_key_file]'),
                    'cmd'   :   '--server :key_mode=server: -n :encrypt_key=False: --stdin-key :stdin_key=True: <|object|> [file:private_key]',
                    '_help' :   {
                                    'cmd'                   : _('Import user\'s RSA key'),
                                    '-n'                    : _('Don\'t encrypt private key'),
                                    '--server'              : _('Save key on server.'),
                                    '--stdin-key'           : _('Read RSA private key from stdin'),
                                },

                },

    'dump_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user dump_key [-p] [-n] [--stdin-pass] {user}'),
                    'cmd'   :   '-p :private=True: -n :decrypt=True: --stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump user\'s RSA key to stdout'),
                                    '-p'                    : _('Dump private key (or pointer)'),
                                    '-n'                    : _('Dump private key unencrypted (if possible)'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin'),
                                },

                },

    'gen_cert'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user gen_cert {user}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Generate user certificate'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin'),
                                },
                },


    'sign_data'    : {
                    # This command is not intended to be used by the user directly.
                    # It is called internally when running otpme-tool sign command.
                    'cmd'   :   '--data :data: --stdin-data :stdin_data=True: --digest :digest: --stdin-pass :stdin_pass=True: <|object|>',
                },


    'encrypt'    : {
                    # This command is not intended to be used by the user directly.
                    # It is called internally when running otpme-tool encrypt command.
                    'cmd'   :   '--data :data: --stdin-data :stdin_data=True: --stdin-pass :stdin_pass=True: <|object|>',
                },


    'decrypt'    : {
                    # This command is not intended to be used by the user directly.
                    # It is called internally when running otpme-tool decrypt command.
                    'cmd'   :   '--data :data: --stdin-data :stdin_data=True: --stdin-pass :stdin_pass=True: <|object|>',
                },


    'deploy_token'    : {
                    # This command is not intended to be used by the user directly.
                    # It is called internally when running otpme-token deploy command.
                    'cmd'   :   '<|object|> <token_name> <token_type>',
                },

    'add_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user add_token [-r] [--no-qrcode] [--enable-mschap] [--token-type <token_type>] [--name <token_name>] [--destination <dst_token>] [--password <password>] {user}'),
                    'cmd'   :   '-r :replace=True: --no-qrcode :gen_qrcode=False: --enable-mschap :enable_mschap=True: --name :token_name: --token-type :token_type: --destination :destination_token: --password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new token.'),
                                    '--name'                : _('Token name.'),
                                    '--token-type'          : _('Token type.'),
                                    '--password <password>' : _('Set token password (for password tokens).'),
                                    '-r'                    : _('Replace existing token and keep its UUID.'),
                                },
                },

    'del_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user del_token {user} {token}'),
                    'cmd'   :   '<|object|> <token_name>',
                    '_help' :   {
                                    'cmd'                   : _('Delete token'),
                                },
                },


    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user touch {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch user (e.g. migrate).'),
                                },
                },

    'enable_auto_mount'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user auto_mount {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable user to login even if e.g. accessgroup is disabled.'),
                                },
                },

    'disable_auto_mount'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user auto_mount {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable user to login even if e.g. accessgroup is disabled.'),
                                },
                },

    'enable_disabled_login'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user enable_disabled_login {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable user to login even if e.g. accessgroup is disabled.'),
                                },
                },

    'disable_disabled_login'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user disable_disabled_login {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable user to login even if e.g. accessgroup is disabled.'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user enable {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable user'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user disable {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable user'),
                                },
                },

    'auto_disable'          : {
                    '_cmd_usage_help' : _('Usage: otpme-user auto_disable {user} {time}'),
                    'cmd'   :   '<|object|> <auto_disable> -u :unused=True:',
                    '_help' :   {
                                    'cmd'                   : _('Change auto disable value (e.g "1d" or "09:53 13.06.2023").'),
                                    '-u'                    : _('Disable object if it was unused for the given time.'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user rename {user} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename user'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user config {user} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to user.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-user show_config {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show user config parameters'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user add_extension {user} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to user'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user remove_extension {user} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from user'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user add_attribute {user} {attribute}=[value]'),
                    'cmd'   :   '-i :position: <|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (ldap) attribute to user'),
                                    '-i <position>'         : _('Insert multi-value attribute at position.'),
                                },
                },

     'modify_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user modify_attribute {user} {attribute} {old_value} {new_value}'),
                    'cmd'   :   '<|object|> <attribute> <old_value> <new_value>',
                    '_help' :   {
                                    'cmd'                   : _('Modify (ldap) attribute of user'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user del_attribute {user} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (ldap) attribute from user'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user add_object_class {user} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (ldap) object class to user'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user del_object_class {user} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (ldap) object class from user'),
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user show_ldif {user} -a attribute1,attribute2'),
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : _('Show LDIF representation of user'),
                                    '-a'                    : _('Show only given LDIF attributes'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user add_acl [-r -a] {user} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: <|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to user'),
                                    '-r'                    : _('Set ACL recursive (to user tokens)'),
                                    '-a'                    : _('Apply default ACLs to existing tokens'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user del_acl  [-r -a] {user} {acl}'),
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: <|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from user'),
                                    '-r'                    : _('Delete ACL recursive (from user tokens)'),
                                    '-a'                    : _('Delete default ACLs from existing tokens'),
                                },
                },

    'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user show_acls {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of user'),
                                },
                },


    'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user enable_acl_inheritance {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for user'),
                                },
                },


    'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user disable_acl_inheritance {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for user'),
                                },
                },

    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user move [--keep-acls] {user} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change user\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.'),
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user remove_orphans {user}'),
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                    '-r'                    : _('Remove orphan UUIDs recursive'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user description {user} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set user description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-user export --password <password> {user}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export user config to stdout.'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user add_policy {user} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to user'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user remove_policy {user} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from user'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user list_policies {user}'),
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
    'group'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user group {user} {group}'),
                    'cmd'   :   '<|object|> <new_group>',
                    '_help' :   {
                                    'cmd'                   : _('Change user\'s default group'),
                                },
                },


    'unblock'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user unblock {user} [accessgroup]'),
                    'cmd'   :   '<|object|> [access_group]',
                    '_help' :   {
                                    'cmd'                   : _('Unblock user for an given accessgroup or for all'),
                                },
                },


    'auth_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user auth_script {user} {auth_script} -- [script_options]'),
                    'cmd'   :   '<|object|> <auth_script> [script_options]',
                    '_help' :   {
                                    'cmd'                   : _('Change user\'s authorization script'),
                                },
                },


    'enable_auth_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user enable_auth_script {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable user\'s authorization script'),
                                },
                },


    'disable_auth_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user disable_auth_script {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable user\'s authorization script'),
                                },
                },



    'get_key_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user get_key_script {user} [name|uuid]'),
                    'cmd'   :   '<|object|> [return_type]',
                    '_help' :   {
                                    'cmd'                   : _('Get user\'s key script name or UUID'),
                                },
                },

    'key_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user key_script {user} [key_script] -- [script_options]'),
                    'cmd'   :   '<|object|> [key_script] [script_options]',
                    '_help' :   {
                                    'cmd'                   : _('Change user\'s key script'),
                                },
                },

    'agent_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user agent_script {user} [agent_script] -- [script_options]'),
                    'cmd'   :   '<|object|> [agent_script] [script_options]',
                    '_help' :   {
                                    'cmd'                   : _('Change user\'s agent script'),
                                },
                },

    'login_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user login_script {user} [login_script] -- [script_options]'),
                    'cmd'   :   '<|object|> [login_script] [script_options]',
                    '_help' :   {
                                    'cmd'                   : _('Change user\'s login script'),
                                },
                },

    'enable_login_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user enable_login_script {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable user\'s login script'),
                                },
                },


    'disable_login_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user disable_login_script {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable user\'s login script'),
                                },
                },

    'enable_autosign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user enable_autosign {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable auto-sign feature of user.'),
                                },
                },


    'disable_autosign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-user disable_autosign {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable auto-sign feature of user.'),
                                },
                },
    'list_groups'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user list_groups {user}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                       : _('List user\'s groups.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user list_tokens {user}'),
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                       : _('List user\'s tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-user list_roles {user}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : _('List user\'s roles.'),
                                    '--return-type'         : _('Attribute to return.'),
                                },
                },
    'photo'      : {
                    '_cmd_usage_help' : _('Usage: otpme-user photo {user} {image_path}'),
                    'cmd'   :   '<|object|> <file:image_data>',
                    '_help' :   {
                                    'cmd'                   : _('Add user photo (jpeg).'),
                                },
                },

    'dump_photo'      : {
                    '_cmd_usage_help' : _('Usage: otpme-user dump_photo {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump user photo as base64.'),
                                },
                },

    'del_photo'      : {
                    '_cmd_usage_help' : _('Usage: otpme-user del_photo {user}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete user photo.'),
                                },
                },
    }
