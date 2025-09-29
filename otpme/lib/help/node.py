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
    register_cmd_help(command="node", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-node {command} [node]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-node show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [node]'),
                    'cmd'   :   '--policy-limit :max_policies: --role-limit :max_roles: --token-limit :max_tokens: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show node(s)'),
                                    '-a'                    : _('Show all nodes.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--token-limit <limit>' : _('Output <limit> tokens.'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--role-limit <limit>'  : _('Output max roles.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List nodes.'),
                                    '-a'                        : _('List all nodes.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node add {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new node'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node del {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete node'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node touch {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch node (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node enable {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable node'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node disable {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable node'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node config {node} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to node.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-node show_config {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show node config parameters'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_extension {node} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to node'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node remove_extension {node} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from node'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_attribute {node} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) attribute to node'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node del_attribute {node} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) attribute from node'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_object_class {node} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) object class to node'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node del_object_class {node} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) object class from node'),
                                },
                },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-node show_ldif {node} -a attribute1,attribute2',
     #               'cmd'   :   '<|object|> -a :[attributes]:',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of node',
     #                                  '-a'                    : 'show only given LDIF attributes',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_acl {node} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to node'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node del_acl {node} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from node'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node show_acls {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of node'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node enable_acl_inheritance {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for node'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node disable_acl_inheritance {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for node'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node move [--keep-acls] {node} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change node\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node remove_orphans {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node description {node} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set node description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-node export --password <password> {node}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export node config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_policy {node} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to node'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node remove_policy {node} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from node'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node list_policies {node}'),
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
    'list_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node list_users {node}'),
                    'cmd'   :   '--return-type :return_type: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('List users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node list_tokens {node}'),
                    'cmd'   :   '--return-type :return_type: --token-types :[token_types]: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('List assigned tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node list_roles {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List assigned roles.'),
                                },
                },
    'list_dynamic_groups'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node list_dynamic_groups {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List dynamic groups of node.'),
                                },
                },
    'dump_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node dump_cert {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump node cert to stdout'),
                                },
                },

    'dump_ca_chain'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node dump_ca_chain {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump node certificate chain of node cert to stdout'),
                                },
                },

    'renew_cert'   : {
                    'cmd'   :   '<|object|>',
                },

    'public_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node public_key {node} [public_key]'),
                    'cmd'   :   '<|object|> [public_key]',
                    '_help' :   {
                                    'cmd'                   : _('Change node\'s public key.'),
                                },
                },

    'vote_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node vote_script {node} {vote_script}'),
                    'cmd'   :   '<|object|> <vote_script> [script_options]',
                    '_help' :   {
                                    'cmd'                   : _('Change node vote script.'),
                                },
                },

    'enable_vote_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node enable_vote_script {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable node vote script.'),
                                },
                },

    'disable_vote_script'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node disable_vote_script {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable node vote script.'),
                                },
                },

    'enable_jotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node enable_jotp {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable realm join via JOTP.'),
                                },
                },

    'disable_jotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node disable_jotp {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable realm join via JOTP.'),
                                },
                },

    'enable_lotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node enable_lotp {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable realm leaving via LOTP.'),
                                },
                },

    'disable_lotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node disable_lotp {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable realm leaving via LOTP.'),
                                },
                },

    'enable_jotp_rejoin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node enable_jotp_rejoin {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable printing of rejoin JOTP on realm leave.'),
                                },
                },

    'disable_jotp_rejoin'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node disable_jotp_rejoin {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable printing of rejoin JOTP on realm leave.'),
                                },
                },

    'add_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_role {node} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add role to node.'),
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node remove_role {node} {role}'),
                    'cmd'   :   '<|object|> <role_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from node.'),
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_token [-i tty,gui,ssh] [--no-auto-sign] [--sign --tags {tag1,tag2,...}] {node} {token} [token_options]'),
                    'cmd'   :   '-i :[login_interfaces]: --no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <token_path> [token_options]',
                    '_help' :   {
                                    'cmd'                   : _('Add token to node.'),
                                    '-i <tty,gui,ssh>'      : _('Limit login to given interface(s).'),
                                    '--sign'                : _('Sign the object with default tags.'),
                                    '--tags <tag1,tag2>'    : _('Add tags to signature.'),
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node remove_token --keep-sign {node} {token}'),
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <token_path>',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from node'),
                                    '--keep-sign'           : _('Do not remove any signature.'),
                                },
                },

    'add_dynamic_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node add_dynamic_group {node} {group_name}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add dynamic group to node.'),
                                },
                },

    'remove_dynamic_group'   : {
                    '_cmd_usage_help' : _('Usage: otpme-node remove_dynamic_group {node} {group_name}'),
                    'cmd'   :   '<|object|> <group_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove dynamic group from node.'),
                                },
                },

    'limit_logins'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node limit_logins {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Limit logins.'),
                                },
                },

    'unlimit_logins'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node unlimit_logins {node}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Unlimit logins.'),
                                },
                },

    'get_ssh_authorized_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-node get_ssh_authorized_keys {node} [user]'),
                    'cmd'   :   '<|object|> [user]',
                    '_help' :   {
                                    'cmd'                   : _('Get SSH authorized keys for node.'),
                                },
                },
    }
