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
    register_cmd_help(command="ca", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-ca {command} [ca]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [ca]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show CA(s)'),
                                    '-a'                    : _('Show all CAs.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-ca list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                   : _('List CAs'),
                                    '-a'                    : _('List all CAs.'),
                                    '--attribute <attribute>' : _('Output given attribute.'),
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add {ca}'),
                    'cmd'   :   '--country :country: --state :state: --locality :locality: --organization :organization: --ou :ou: --email :email: --valid :valid: --key-len :key_len: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new CA'),
                                    '--valid'               : _('CA certificate validity in days.'),
                                    '--key-len'             : _('Key length for CA certificate in bits.'),
                                    '--country'             : _('Set CA certificate <country> field.'),
                                    '--state'               : _('Set CA certificate <state> field.'),
                                    '--locality'            : _('Set CA certificate <locality> field.'),
                                    '--organization'        : _('Set CA certificate <organization> field.'),
                                    '--ou'                  : _('Set CA certificate <ou> field.'),
                                    '--email'               : _('Set CA certificate <email> field.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca del {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete CA'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca touch {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch ca (e.g. migrate).',
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca enable {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable CA'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca disable {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable CA'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca rename {ca} {new_name}'),
                    'cmd'   :   '<|object|> <new_name>',
                    '_help' :   {
                                    'cmd'                   : _('Rename CA'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca config {ca} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to CA.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show_config {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show CA config parameters'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_extension {ca} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to CA'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca remove_extension {ca} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from CA'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_attribute {ca} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (ldap) attribute to CA'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca del_attribute {ca} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (ldap) attribute from CA'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_object_class {ca} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (ldap) object class to CA'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca del_object_class {ca} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (ldap) object class from CA'),
                                },
                },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-ca show_ldif {ca}',
     #               'cmd'   :   '<|object|>',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of CA',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_acl {ca} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to CA'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca del_acl {ca} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from CA'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show_acls {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of CA'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca enable_acl_inheritance {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for CA'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca disable_acl_inheritance {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for CA'),
                                },
                },


    #'move'    : {
    #                '_cmd_usage_help' : 'Usage: otpme-ca move {ca} {unit}',
    #                'cmd'   :   '<|object|> <new_unit>',
    #                '_help' :   {
    #                                'cmd'                   : 'change CAs unit',
    #                            },
    #            },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca remove_orphans {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca description {ca} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set CA description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-ca export --password <password> {ca}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export CA config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_policy {ca} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to CA'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca remove_policy {ca} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from CA'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca list_policies {ca}'),
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

    'dump_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_cert {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA cert to stdout'),
                                },
                },


    'dump_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_key [-p passphrase] {ca}'),
                    'cmd'   :   '<|object|> -p :passphrase:',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA\'s private key to stdout'),
                                    '-p <passphrase>'       : _('Export private key encrypted with "passphrase"'),
                                },
                },


    'dump_ca_chain'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_ca_chain {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA certificate chain of node cert to stdout'),
                                },
                },


    'crl_validity'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca crl_validity {ca} {days}'),
                    'cmd'   :   '<|object|> <crl_validity>',
                    '_help' :   {
                                    'cmd'                   : _('Set CRL validity in days'),
                                },
                },


    'dump_crl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_crl {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA CRL to stdout'),
                                },
                },


    'update_crl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca update_crl {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove outdated certificates from CA CRL'),
                                },
                },
    }
