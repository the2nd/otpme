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

from . import register_cmd_help

def register():
    register_cmd_help(command="ca", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-ca {command} [ca]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [--limit <limit>] [--sort-by <attribute>] [--reverse] [--raw] [--csv] [--csv-sep <separator>] [ca]'),
                    'cmd'   :   '--policy-limit :max_policies: --limit :limit: --fields :"output_fields": -z :max_len: --sort-by :"sort_by": --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :"csv_sep": [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show CA(s)'),
                                    '-a'                    : _('Show all CAs.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
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
                    '_cmd_usage_help' : _('Usage: otpme-ca list [--attribute attribute] [-a] [pattern]'),
                    'cmd'   :   '--attribute :"attribute": -a :show_all=True: ["search_regex"]',
                    '_help' :   {
                                    'cmd'                   : _('List CAs'),
                                    '-a'                    : _('List all CAs.'),
                                    '--attribute <attribute>' : _('Match the pattern against this attribute instead of the name.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca get_config {ca} {parameter}'),
                    'cmd'   :   '<|object|> <"parameter">',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },
    'show_oid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show_oid [--full] {ca}'),
                    'cmd'   :   '--full :full=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the OID of the object.'),
                                    '--full'                : _('Show the full OID.'),
                                },
                },
    'show_uuid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show_uuid {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the UUID of the object.'),
                                },
                },
    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca changelog {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },
    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca edit_changelog {ca} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <"comment">',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },
    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca del_changelog {ca} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },
    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca clear_changelog {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca touch {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Touch ca (e.g. migrate).',
                                },
                },


    'create_client_cert'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca create_client_cert [--csr <csr_file>] [--valid <days>] [--key-len <bits>] [--country <country>] [--state <state>] [--locality <locality>] [--organization <organization>] [--ou <ou>] [--email <email>] {ca} {cn} {cert_out_file} [key_out_file]'),
                    'cmd'   :   '--csr :file:cert_req: --country :"country": --state :"state": --locality :"locality": --organization :"organization": --ou :"ou": --email :"email": --valid :valid: --key-len :key_len: <|object|> <"cn"> <"cert_out_file"> ["key_out_file"]',
                    '_help' :   {
                                    'cmd'                   : _('Create client certificate.'),
                                    '--csr <csr_file>'      : _('Sign this certificate request; the key stays with it, and there is no key file.'),
                                    '--valid'               : _('Certificate validity in days.'),
                                    '--key-len'             : _('Key length for certificate in bits.'),
                                    '--country'             : _('Set certificate <country> field.'),
                                    '--state'               : _('Set certificate <state> field.'),
                                    '--locality'            : _('Set certificate <locality> field.'),
                                    '--organization'        : _('Set certificate <organization> field.'),
                                    '--ou'                  : _('Set certificate <ou> field.'),
                                    '--email'               : _('Set certificate <email> field.'),
                                },
                },

    'revoke'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca revoke {ca} {cert_file}'),
                    'cmd'   :   '<|object|> <file:cert>',
                    '_help' :   {
                                    'cmd'                   : _('Revoke a client certificate made with create_client_cert.'),
                                },
                },

    #'rename'    : {
    #                '_cmd_usage_help' : _('Usage: otpme-ca rename {ca} {new_name}'),
    #                'cmd'   :   '<|object|> <new_name>',
    #                '_help' :   {
    #                                'cmd'                   : _('Rename CA'),
    #                            },
    #            },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca config [-d] [-a] {ca} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <"parameter"> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to CA.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show_config {ca} [parameter]'),
                    'cmd'   :   '<|object|> ["parameter"]',
                    '_help' :   {
                                    'cmd'                   : _('Show CA config parameters'),
                                },
                },

     #'add_extension'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-ca add_extension {ca} {extension}'),
     #               'cmd'   :   '<|object|> <extension>',
     #               '_help' :   {
     #                               'cmd'                   : _('Add extension to CA'),
     #                           },
     #           },

     #'remove_extension'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-ca remove_extension {ca} {extension}'),
     #               'cmd'   :   '<|object|> <extension>',
     #               '_help' :   {
     #                               'cmd'                   : _('Remove extension from CA'),
     #                           },
     #           },

     #'add_attribute'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-ca add_attribute {ca} {attribute}=[value]'),
     #               'cmd'   :   '<|object|> <attribute>=[value]',
     #               '_help' :   {
     #                               'cmd'                   : _('Add (ldap) attribute to CA'),
     #                           },
     #           },

     #'del_attribute'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-ca del_attribute {ca} {attribute}=[value]'),
     #               'cmd'   :   '<|object|> <attribute>=[value]',
     #               '_help' :   {
     #                               'cmd'                   : _('Delete (ldap) attribute from CA'),
     #                           },
     #           },

     #'add_object_class'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-ca add_object_class {ca} {object_class}'),
     #               'cmd'   :   '<|object|> <object_class>',
     #               '_help' :   {
     #                               'cmd'                   : _('Add (ldap) object class to CA'),
     #                           },
     #           },

     #'del_object_class'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-ca del_object_class {ca} {object_class}'),
     #               'cmd'   :   '<|object|> <object_class>',
     #               '_help' :   {
     #                               'cmd'                   : _('Delete (ldap) object class from CA'),
     #                           },
     #           },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-ca show_ldif {ca}',
     #               'cmd'   :   '<|object|>',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of CA',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_acl {ca} {role|token} {role_path|token_path} {acl[:value][,acl[:value]]}'),
                    'cmd'   :   '<|object|> <"owner_type"> <"owner_name"> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to CA'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca del_acl {ca} {acl[,acl]}'),
                    'cmd'   :   '<|object|> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from CA'),
                                },
                },

     'list_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca list_acls {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List ACLs set on this CA.'),
                                },
                },


    # No enable_acl_inheritance and disable_acl_inheritance: they say
    # whether a move swaps the default ACLs, and a CA is not moved.

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
                    'cmd'   :   '<|object|> ["description"]',
                    '_help' :   {
                                    'cmd'                   : _('Set CA description'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca info [--language <language>] {ca} [info]'),
                    'cmd'   :   '--language :"language": <|object|> ["info"]',
                    '_help' :   {
                                    'cmd'                   : _('Set CA info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_info [--language <language>] {ca}'),
                    'cmd'   :   '--language :"language": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA info'),
                                    '--language <lang>'     : _('Dump info for language.'),
                                },
                },

    'show_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca show_info {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the languages that have an info'),
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
                    '_cmd_usage_help' : _('Usage: otpme-ca export [--password <password>] {ca}'),
                    'cmd'   :   '--password :"password": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export CA config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca add_policy {ca} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to CA'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-ca remove_policy {ca} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from CA'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca list_policies [--return-type <type>] [--policy-types <type1,type2>] {ca}'),
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

    'dump_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_cert {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA cert to stdout'),
                                },
                },


    'dump_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_key [-p passphrase] {ca}'),
                    'cmd'   :   '<|object|> -p :"passphrase":',
                    '_help' :   {
                                    'cmd'                   : _('Dump CA\'s private key to stdout'),
                                    '-p <passphrase>'       : _('Export private key encrypted with "passphrase"'),
                                },
                },


    'dump_ca_chain'   : {
                    '_cmd_usage_help' : _('Usage: otpme-ca dump_ca_chain {ca}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump the certificate chain of the CA to stdout'),
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
