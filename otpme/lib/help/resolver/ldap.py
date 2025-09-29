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
    register_cmd_help(command="resolver", help_dict=cmd_help, mod_name="ldap")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add [--template <template>] {resolver}'),
                    'cmd'   :   '--template :ldap_template: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new resolver.'),
                                    '--template <template>' : _('Use settings from given template.'),
                                },
                },

    'ldap_base'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver ldap_base {resolver} {ldap_base}'),
                    'cmd'   :   '<|object|> <ldap_base>',
                    '_help' :   {
                                    'cmd'                   : _('Set LDAP base.'),
                                },
                },

    'login_dn'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver login_dn {resolver} {login_dn}'),
                    'cmd'   :   '<|object|> <login_dn>',
                    '_help' :   {
                                    'cmd'                   : _('Set DN used to login to LDAP server.'),
                                },
                },


    'login_password'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver login_password {resolver} [password]'),
                    'cmd'   :   '<|object|> [login_password]',
                    '_help' :   {
                                    'cmd'                   : _('Set password used to login to LDAP server.'),
                                },
                },


    'add_server'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_server {resolver} {server_uri}'),
                    'cmd'   :   '<|object|> <server_uri>',
                    '_help' :   {
                                    'cmd'                   : _('Add LDAP server URI (e.g. ldaps://ldap.domain.tld, ldaps://ldap2.domain.tld:389).'),
                                },
                },

    'del_server' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del_server {resolver} {server_uri}'),
                    'cmd'   :   '<|object|> <server_uri>',
                    '_help' :   {
                                    'cmd'                   : _('Delete LDAP server URI.'),
                                },
                },


    'add_ldap_filter'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_ldap_filter {resolver} {object_type} {ldap_filter}'),
                    'cmd'   :   '<|object|> <object_type> <ldap_filter>',
                    '_help' :   {
                                    'cmd'                   : _('Add LDAP filter to search given object type.'),
                                },
                },

    'del_ldap_filter' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del_ldap_filter {resolver} {object_type} {ldap_filter}'),
                    'cmd'   :   '<|object|> <object_type> <ldap_filter>',
                    '_help' :   {
                                    'cmd'                   : _('Delete LDAP filter for given object type.'),
                                },
                },

    'add_ldap_attribute'   : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver add_ldap_attribute {resolver} {object_type} {src_attr} [dst_attr]'),
                    'cmd'   :   '<|object|> <object_type> <src_attr> [dst_attr]',
                    '_help' :   {
                                    'cmd'                   : _('Add LDAP attribute to be mapped to the given object type.'),
                                },
                },

    'del_ldap_attribute' : {
                    '_cmd_usage_help' : _('Usage: otpme-resolver del_ldap_attribute {resolver} {object_type} {ldap_attribute}'),
                    'cmd'   :   '<|object|> <object_type> <src_attr>',
                    '_help' :   {
                                    'cmd'                   : _('Delete LDAP attribute for given object type.'),
                                },
                },

    }
