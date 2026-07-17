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
    register_cmd_help(command="site", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-site {command} [site]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-site show [--policy-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [site]'),
                    'cmd'   :   '--policy-limit :max_policies: --limit :limit: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show site(s)'),
                                    '-a'                    : _('Show all sites.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--limit <limit>'       : _('Limit number of items shown per object.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-site show_config {site} [parameter]'),
                    'cmd'   :   '<|object|> [parameter]',
                    '_help' :   {
                                    'cmd'                   : _('Show site\'s config parameters'),
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site add {site} {node_name} {site_fqdn} {site_address}'),
                    'cmd'   :   '--country :ca_country: --state :ca_state: --locality :ca_locality: --organization :ca_organization: --ou :ca_ou: --email :ca_email: --ca-valid :ca_valid: --ca-key-len :ca_key_len: --site-valid :site_valid: --site-key-len :site_key_len: --node-valid :node_valid: --node-key-len :node_key_len: --no-dicts :no_dicts=True: --dicts :[dictionaries]: --id-ranges ::id_ranges:: <|object|> <node_name> <site_fqdn> <site_address>',
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

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site get_config {site} {parameter}'),
                    'cmd'   :   '<|object|> <parameter>',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },
    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site changelog {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },
    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site edit_changelog {site} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <comment>',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },
    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_changelog {site} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },
    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site clear_changelog {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-site config -d -a {site} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to site.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
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
                                    'cmd'                   : _('Set site description'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site info {site} [info]'),
                    'cmd'   :   '--language :language: <|object|> [info]',
                    '_help' :   {
                                    'cmd'                   : _('Set site info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site dump_info {site}'),
                    'cmd'   :   '--language :language: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump site info'),
                                    '--language <lang>'     : _('Dump info for language.'),
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

    'site_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site site_cert {site} [site_cert]'),
                    'cmd'   :   '<|object|> [file:site_cert]',
                    '_help' :   {
                                    'cmd'                   : _('Change site certificate.'),
                                },
                },

    'radius_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site radius_cert [--key {radius_key}] {--ca-cert {radius_ca_cert}] {site} [radius_cert]'),
                    'cmd'   :   '--key :file:radius_key: --ca-cert :file:radius_ca_cert: <|object|> [file:radius_cert]',
                    '_help' :   {
                                    'cmd'                   : _('Change radius certificate.'),
                                },
                },

    'radius_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site radius_key {site} [radius_key]'),
                    'cmd'   :   '<|object|> [file:radius_key]',
                    '_help' :   {
                                    'cmd'                   : _('Change radius certificate key.'),
                                },
                },

    'radius_ca_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site radius_ca_cert {site} [radius_ca_cert]'),
                    'cmd'   :   '<|object|> [file:radius_ca_cert]',
                    '_help' :   {
                                    'cmd'                   : _('Change radius CA certificate.'),
                                },
                },

    'sso_cert'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_cert --key {sso_key} {site} [sso_cert]'),
                    'cmd'   :   '--key :file:sso_key: <|object|> [file:sso_cert]',
                    '_help' :   {
                                    'cmd'                   : _('Change SSO certificate.'),
                                },
                },

    'sso_key'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_key {site} [sso_key]'),
                    'cmd'   :   '<|object|> [file:sso_key]',
                    '_help' :   {
                                    'cmd'                   : _('Change SSO certificate key.'),
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

    'oidc_pairwise_secret'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site oidc_pairwise_secret {site} [secret]'),
                    'cmd'   :   '--force :force=True: <|object|> [secret]',
                    '_help' :   {
                                    'cmd'                   : _('Rotate OIDC pairwise sub HMAC secret. Auto-generates if no secret given. WARNING: invalidates every existing pairwise sub on RPs.'),
                                    '-f'                    : _('Do not ask for confirmation.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-site auth_fqdn {site} {fqdn}'),
                    'cmd'   :   '<|object|> <fqdn>',
                    '_help' :   {
                                    'cmd'                   : _('Change site\'s auth fqdn.'),
                                },
                },

    'mgmt_fqdn'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site mgmt_fqdn {site} {fqdn}'),
                    'cmd'   :   '<|object|> <fqdn>',
                    '_help' :   {
                                    'cmd'                   : _('Change site\'s mgmt fqdn.'),
                                },
                },

    'sso_fqdn'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site sso_fqdn {site} {fqdn}'),
                    'cmd'   :   '<|object|> <fqdn>',
                    '_help' :   {
                                    'cmd'                   : _('Change site\'s SSO fqdn.'),
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

    'enable_oidc'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site enable_oidc {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable OIDC for site'),
                                },
                },

    'disable_oidc'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site disable_oidc {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable OIDC for site'),
                                },
                },

    'renew_oidc_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site renew_oidc_key [--key-type rsa|rsa-3072|rsa-4096|ec|ec-p256|ec-p384|ec-p521|ed25519] [--kty RSA|EC|OKP] [--size <int|curve>] [--alg RS256|ES256|EdDSA|...] {site}'),
                    'cmd'   :   '--key-type :key_type: --kty :kty: --size :size: --alg :alg: <|object|>',
                    '_help' :   {
                                    'cmd'                       : _('Rotate OIDC keys for site (default: rsa-2048/RS256).'),
                                    '--key-type <preset>'       : _('High-level preset (rsa, rsa-3072, rsa-4096, ec, ec-p256, ec-p384, ec-p521, ed25519). Mutually exclusive with --kty/--size/--alg.'),
                                    '--kty <RSA|EC|OKP>'        : _('Key type for direct configuration.'),
                                    '--size <bits|curve>'       : _('RSA bits (2048/3072/4096) or EC curve (P-256/P-384/P-521) or OKP curve (Ed25519).'),
                                    '--alg <alg>'               : _('Signing algorithm (RS256/RS384/RS512/ES256/ES384/ES512/EdDSA).'),
                                },
                },

    'revoke_oidc_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site revoke_oidc_key {site} {kid}'),
                    'cmd'   :   '<|object|> <kid>',
                    '_help' :   {
                                    'cmd'                   : _('Revoke OIDC key (compromise scenario; if active a replacement is generated)'),
                                },
                },

    'show_oidc_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-site show_oidc_keys {site}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show OIDC keys for site'),
                                },
                },

    'add_sso_host'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site add_sso_host {site} {host_name}'),
                    'cmd'   :   '<|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add SSO host.'),
                                },
                },

    'del_sso_host'   : {
                    '_cmd_usage_help' : _('Usage: otpme-site del_sso_host {site} {nost_name}'),
                    'cmd'   :   '<|object|> <host_name>',
                    '_help' :   {
                                    'cmd'                   : _('Delete SSO host.'),
                                },
                },

    }
