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
    register_cmd_help(command="realm", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-realm {command} [realm]"),

    'init'      : {
                    '_cmd_usage_help' : _('Usage: otpme-realm init {realm} {site} {fqdn} [address]'),
                    'cmd'   :   '--country :ca_country: --state :ca_state: --locality :ca_locality: --organization :ca_organization: --ou :ca_ou: --email :ca_email: --ca-valid :ca_valid: --ca-key-len :ca_key_len: --site-valid :site_valid: --site-key-len :site_key_len: --node-valid :node_valid: --node-key-len :node_key_len: --no-dicts :no_dicts=True: --dicts ::[dictionaries]:: --id-ranges ::id_ranges:: <|object|> <realm_master> <site_fqdn> [site_address]',
                    '_help' :   {
                                    'cmd'                               : _('Init realm'),
                                    '--ca-valid'                        : _('CA certificates validity in days.'),
                                    '--ca-key-len'                      : _('Key length for CA certificates in bits.'),
                                    '--country'                         : _('Set CA certificate <country> field.'),
                                    '--state'                           : _('Set CA certificate <state> field.'),
                                    '--locality'                        : _('Set CA certificate <locality> field.'),
                                    '--organization'                    : _('Set CA certificate <organization> field.'),
                                    '--ou'                              : _('Set CA certificate <ou> field.'),
                                    '--email'                           : _('Set CA certificate <email> field.'),
                                    '--site-valid'                      : _('Master site certificate validity in days.'),
                                    '--site-key-len'                    : _('Key length for master site certificate in bits.'),
                                    '--node-valid'                      : _('Master node certificate validity in days.'),
                                    '--node-key-len'                    : _('Key length for master node certificate in bits.'),
                                    '--no-dicts'                        : _('Do not add any word dictionaries (strength checker).'),
                                    '--dicts <dict1,dict2>'             : _('Add the given word dictionaries (strength checker).'),
                                    '--id-ranges <id_range_1,id_range2>': _('ID ranges to add.'),
                                },
                },

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-realm show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [realm]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show realm(s)'),
                                    '-a'                    : _('Show all realms.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Output table as CSV.'),
                                },
                    #'job'   :   {
                    #                'object_missing' : {
                    #                                        'type'                  : 'process',
                    #                                        'method'                : 'lib.cli.show_realms',
                    #                                        'args'                  : {},
                    #                                        'oargs'                 : {
                    #                                                                    'max_len'       : {},
                    #                                                                    'output_fields' : {
                    #                                                                                        'handler'   : 'lib.cli.conv_comma_list',
                    #                                                                                    },
                    #                                                                    'search_regex'  : {},
                    #                                                                },
                    #                                },
                    #                'object_exists' : {
                    #                                        'type'                  : None,
                    #                                        'method'                : '.show',
                    #                                        'args'                  : {},
                    #                                        'oargs'                 : {},
                    #                                },
                    #            },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List realms.'),
                                    '-a'                        : _('List all realms.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add {realm} {address}'),
                    'cmd'   :   '<|object|> <address>',
                    '_help' :   {
                                    'cmd'                   : _('Add new realm trust relationship'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm del {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete realm trust relationship'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm touch {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch realm (e.g. migrate).'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add_extension {realm} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to realm'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm remove_extension {realm} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from realm'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add_attribute {realm} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) attribute to realm'),
                                },
                },

     'modify_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm modify_attribute {realm} {attribute} {old_value} {new_value}'),
                    'cmd'   :   '<|object|> <attribute> <old_value> <new_value>',
                    '_help' :   {
                                    'cmd'                   : _('Modify (LDAP) attribute of realm'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm del_attribute {realm} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) attribute from realm'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add_object_class {realm} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) object class to realm'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm del_object_class {realm} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) object class from realm'),
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm show_ldif {realm} -a attribute1,attribute2'),
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : _('Show LDIF representation of realm'),
                                    '-a'                    : _('Show only given LDIF attributes'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add_acl {realm} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to realm'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-realm del_acl {realm} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from realm'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm show_acls {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of realm'),
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-realm remove_orphans {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm description {realm} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set realm description'),
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

    '_show_hash_types'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_extensions'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_valid_search_attributes'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_token_types'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_policy_types'    : {
                    'cmd'   :   '<|object|>',
                },

    '_show_resolver_types'    : {
                    'cmd'   :   '<|object|>',
                },

    'export'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm export --password <password> {realm}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export realm config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add_policy {realm} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to realm'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm remove_policy {realm} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from realm'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-realm list_policies {realm}'),
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
    'dump_ca_data'  : {
                    '_cmd_usage_help' : _('Usage: otpme-realm dump_ca_data {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump realm CA data (Certs and CRLs)'),
                                },
                },


    'update_ca_data'  : {
                    '_cmd_usage_help' : _('Usage: otpme-realm update_ca_data {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Update realm CA data (Certs and CRLs)'),
                                },
                },


    'add_alias'   : {
                    '_cmd_usage_help' : _('Usage: otpme-realm add_alias {realm} {alias}'),
                    'cmd'   :   '<|object|> <alias>',
                    '_help' :   {
                                    'cmd'                   : _('Add realm alias'),
                                },
                },


    'del_alias'   : {
                    '_cmd_usage_help' : _('Usage: otpme-realm del_alias {realm} {alias}'),
                    'cmd'   :   '<|object|> <alias>',
                    '_help' :   {
                                    'cmd'                   : _('Delete realm alias'),
                                },
                },


    'enable_auth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm enable_auth {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable authentication with realm'),
                                },
                },

    'disable_auth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm disable_auth {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable authentication with realm'),
                                },
                },



    'enable_sync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm enable_sync {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable synchronization with realm'),
                                },
                },

    'disable_sync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-realm disable_sync {realm}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable synchronization with realm'),
                                },
                },


    #'secret'    : {
    #                '_cmd_usage_help' : 'Usage: otpme-realm secret {realm} [secret]',
    #                'cmd'   :   '<|object|> [secret]',
    #                '_help' :   {
    #                                'cmd'                   : 'change realms secret',
    #                            },
    #            },


    #'show_secret'    : {
    #                '_cmd_usage_help' : 'Usage: otpme-realm show_secret {realm}',
    #                'cmd'   :   '<|object|>',
    #                '_help' :   {
    #                                'cmd'                   : 'show realms secret',
    #                            },
    #            },

    }
