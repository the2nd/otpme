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
    register_cmd_help(command="site", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-site {command} [site]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-site show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [site]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show site(s)'),
                                    '-a'                    : _('Show all sites.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-site list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List sites.'),
                                    '-a'                        : _('List all sites.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-site show_config {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show site\'s config parameters'),
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site add {site} {node_name} {site_fqdn} [site_address]'),
                    'cmd'   :   '--country :ca_country: --state :ca_state: --locality :ca_locality: --organization :ca_organization: --ou :ca_ou: --email :ca_email: --ca-valid :ca_valid: --ca-key-len :ca_key_len: --site-valid :site_valid: --site-key-len :site_key_len: --node-valid :node_valid: --node-key-len :node_key_len: --no-dicts :no_dicts=True: --dicts :[dictionaries]: --id-ranges ::id_ranges:: <|object|> <node_name> <site_fqdn> [site_address]',
                    '_help' :   {
                                    'cmd'                               : _('Add new site.'),
                                    '--ca-valid'                        : _('CA certificates validity in days.'),
                                    '--ca-key-len'                      : _('Key length for CA certificates in bits.'),
                                    '--country'                         : _('Set CA certificate <country> field.'),
                                    '--state'                           : _('Set CA certificate <state> field.'),
                                    '--locality'                        : _('Set CA certificate <locality> field.'),
                                    '--organization'                    : _('Set CA certificate <organization> field.'),
                                    '--ou'                              : _('Set CA certificate <ou> field.'),
                                    '--email'                           : _('Set CA certificate <email> field.'),
                                    '--site-valid'                      : _('Site certificate validity in days.'),
                                    '--site-key-len'                    : _('Key length for site certificate in bits.'),
                                    '--node-valid'                      : _('Master node certificate validity in days.'),
                                    '--node-key-len'                    : _('Key length for master node certificate in bits.'),
                                    '--no-dicts'                        : _('Do not add any word dictionaries (strength checker).'),
                                    '--dicts <dict1,dict2>'             : _('Add the given word dictionaries (strength checker).'),
                                    '--id-ranges <id_range_1,id_range2>': _('ID ranges to add.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site del {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete site.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site touch {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch site (e.g. migrate).'),
                                },
                },

    # FIXME: do we need this anymore?
    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site enable {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable site'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site disable {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable site'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site config {site} {param} [value]'),
                    'cmd'   :   '<|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to site.'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_extension {site} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to site'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site remove_extension {site} {extension}'),
                    'cmd'   :   '<|object|> <extension>',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from site'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_attribute {site} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) attribute to site'),
                                },
                },

     'modify_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site modify_attribute {site} {attribute} {old_value} {new_value}'),
                    'cmd'   :   '<|object|> <attribute> <old_value> <new_value>',
                    '_help' :   {
                                    'cmd'                   : _('Modify (LDAP) attribute of site'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_attribute {site} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) attribute from site'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_object_class {site} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) object class to site'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_object_class {site} {object_class}'),
                    'cmd'   :   '<|object|> <object_class>',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) object class from site'),
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site show_ldif {site} -a attribute1,attribute2'),
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : _('Show LDIF representation of site'),
                                    '-a'                    : _('Show only given LDIF attributes'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_acl [-r -a --objects <user,group,token>] {site} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: --objects :[object_types]: <|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                           : _('Add ACL to site'),
                                    '-r'                            : _('Set ACL recursive'),
                                    '-a'                            : _('Apply default ACLs to existing objects'),
                                    '--objects <user,group,token>'  : _('Add ACLs to this object types only'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_acl [-r -a --objects <user,group,token>] {site} {acl}'),
                    'cmd'   :   '-r :recursive_acls=True: -a :apply_default_acls=True: --objects :[object_types]: <|object|> <acl>',
                    '_help' :   {
                                    'cmd'                           : _('Delete ACL from site'),
                                    '-r'                            : _('Delete ACL recursive'),
                                    '-a'                            : _('Delete default ACLs from existing objects'),
                                    '--objects <user,group,token>'  : _('Delete ACLs from this object types only'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site show_acls {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('show ACLs of site'),
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site remove_orphans {site}'),
                    'cmd'   :   '-r :recursive=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                    '-r'                    : _('Remove orphan UUIDs recursive'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site description {site} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('set site description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-site export --password <password> {site}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export site config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_policy {site} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('add policy to site'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site remove_policy {site} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('remove policy from site'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site list_policies {site}'),
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
                    '_cmd_usage_help' : _('Usage: otpme-site dump_cert {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('dump site cert to stdout'),
                                },
                },


    'dump_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site dump_key [-p passphrase] {site}'),
                    'cmd'   :   '<|object|> -p :passphrase:',
                    '_help' :   {
                                    'cmd'                   : _('Dump site\'s private key to stdout'),
                                    '-p <passphrase>'       : _('Export private key encrypted with "passphrase"'),
                                },
                },

    'radius_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site radius_cert {site} {radius_cert}'),
                    'cmd'   :   '<|object|> <file:radius_cert>',
                    '_help' :   {
                                    'cmd'                   : _('Change radius certificate.'),
                                },
                },

    'radius_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site radius_key {site} {radius_key}'),
                    'cmd'   :   '<|object|> <file:radius_key>',
                    '_help' :   {
                                    'cmd'                   : _('Change radius certificate key.'),
                                },
                },

    'del_radius_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_radius_cert {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete radius certificate.'),
                                },
                },

    'del_radius_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_radius_key {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete radius key.'),
                                },
                },

    'sso_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_cert {site} {sso_cert}'),
                    'cmd'   :   '<|object|> <file:sso_cert>',
                    '_help' :   {
                                    'cmd'                   : _('Change SSO certificate.'),
                                },
                },

    'sso_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_key {site} {sso_key}'),
                    'cmd'   :   '<|object|> <file:sso_key>',
                    '_help' :   {
                                    'cmd'                   : _('Change SSO certificate key.'),
                                },
                },

    'del_sso_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_sso_cert {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete SSO certificate.'),
                                },
                },

    'del_sso_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_sso_key {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete SSO key.'),
                                },
                },

    'sso_secret'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_secret {site} {sso_secret}'),
                    'cmd'   :   '<|object|> <secret>',
                    '_help' :   {
                                    'cmd'                   : _('Change SSO secret.'),
                                },
                },

    'sso_csrf_secret'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_csrf_secret {site} {sso_csrf_secret}'),
                    'cmd'   :   '<|object|> <secret>',
                    '_help' :   {
                                    'cmd'                   : _('Change SSO CSRF secret.'),
                                },
                },

    'cluster_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site cluster_key {site} {cluster_key}'),
                    'cmd'   :   '<|object|> <cluster_key>',
                    '_help' :   {
                                    'cmd'                   : _('Change cluster key.'),
                                },
                },

    'add_fido2_ca_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_fido2_ca_cert {site} {ca_cert}'),
                    'cmd'   :   '<|object|> <file:ca_cert>',
                    '_help' :   {
                                    'cmd'                   : _('Add fido2 CA cert.'),
                                },
                },

    'del_fido2_ca_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_fido2_ca_cert {site} {ca_subject}'),
                    'cmd'   :   '<|object|> <subject>',
                    '_help' :   {
                                    'cmd'                   : _('Delete fido2 CA cert.'),
                                },
                },

    'list_fido2_ca_certs'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site list_fido2_ca_certs {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List fido2 CA certs.'),
                                },
                },

    'dump_ca_chain'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site dump_ca_chain {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump site certificate chain of site cert to stdout'),
                                },
                },

    'revoke_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site revoke_cert {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Revoke site\'s certificate'),
                                },
                },


    'renew_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site renew_cert {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Renew site\'s certificate'),
                                },
                },


    #'secret'    : {
    #                '_cmd_usage_help' : 'Usage: otpme-site secret {site} [secret]'),
    #                'cmd'   :   '<|object|> [secret]',
    #                '_help' :   {
    #                                'cmd'                   : _('Change realms secret'),
    #                            },
    #            },


    #'show_secret'    : {
    #                '_cmd_usage_help' : 'Usage: otpme-site show_secret {site}'),
    #                'cmd'   :   '<|object|>',
    #                '_help' :   {
    #                                'cmd'                   : _('Show realms secret'),
    #                            },
    #            },


    'add_trust'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_trust {site} {trusted_site}'),
                    'cmd'   :   '<|object|> <site_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add trust relationship'),
                                },
                },

    'del_trust'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_trust {site} {trusted_site}'),
                    'cmd'   :   '<|object|> <site_name>',
                    '_help' :   {
                                    'cmd'                   : _('Delete trust relationship'),
                                },
                },


    'address'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site address {site} [ip_address]'),
                    'cmd'   :   '<|object|> [address]',
                    '_help' :   {
                                    'cmd'                   : _('Change site\'s IP address'),
                                },
                },

    'auth_fqdn'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site auth_fqdn {site} [fqdn]'),
                    'cmd'   :   '<|object|> [fqdn]',
                    '_help' :   {
                                    'cmd'                   : _('Change site\'s auth fqdn.'),
                                },
                },

    'mgmt_fqdn'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site mgmt_fqdn {site} [fqdn]'),
                    'cmd'   :   '<|object|> [fqdn]',
                    '_help' :   {
                                    'cmd'                   : _('Change site\'s mgmt fqdn.'),
                                },
                },

    'enable_auth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site enable_auth {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable authentication with site'),
                                },
                },

    'disable_auth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site disable_auth {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable authentication with site'),
                                },
                },


    'enable_sync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site enable_sync {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable synchronization with site'),
                                },
                },

    'disable_sync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site disable_sync {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable synchronization with site'),
                                },
                },
    }
