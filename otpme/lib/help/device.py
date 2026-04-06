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
    register_cmd_help(command="device", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-device {command} [device]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-device show [--policy-limit <limit>] [--token-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-t] [-a] [device]'),
                    'cmd'   :   '--policy-limit :max_policies: --fields :output_fields: -z :max_len: --sort-by :sort_by: --reverse :reverse=True: -a :show_all=True: -t :show_templates=True: --raw :header=False: --csv :csv=True: --csv-sep :csv_sep: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show device(s)'),
                                    '-a'                    : _('Show all devices.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-device list [--attribute attribute] [-a] [regex]'),
                    'cmd'   :   '--attribute :attribute: -a :show_all=True: [search_regex]',
                    '_help' :   {
                                    'cmd'                       : _('List devices.'),
                                    '-a'                        : _('List all devices.'),
                                    '--attribute <attribute>'   : _('Output given attribute.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device add {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new device'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device del {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete device'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device touch {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch device (e.g. migrate).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device enable {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable device'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device disable {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable device'),
                                },
                },

    'mac'       : {
                    '_cmd_usage_help' : _('Usage: otpme-device mac {device} {mac_address}'),
                    'cmd'   :   '<|object|> <mac_address>',
                    '_help' :   {
                                    'cmd'                   : _('Set devices MAC address.'),
                                },
                },

    'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device config -d -a {device} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <parameter> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to device.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-device show_config {device} [parameter]'),
                    'cmd'   :   '<|object|> [parameter]',
                    '_help' :   {
                                    'cmd'                   : _('Show device config parameters'),
                                },
                },

     #'add_extension'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-device add_extension {device} {extension}'),
     #               'cmd'   :   '<|object|> <extension>',
     #               '_help' :   {
     #                               'cmd'                   : _('Add extension to device'),
     #                           },
     #           },

     #'remove_extension'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-device remove_extension {device} {extension}'),
     #               'cmd'   :   '<|object|> <extension>',
     #               '_help' :   {
     #                               'cmd'                   : _('Remove extension from device'),
     #                           },
     #           },

     #'add_attribute'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-device add_attribute {device} {attribute}=[value]'),
     #               'cmd'   :   '<|object|> <attribute>=[value]',
     #               '_help' :   {
     #                               'cmd'                   : _('Add (LDAP) attribute to device'),
     #                           },
     #           },

     #'del_attribute'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-device del_attribute {device} {attribute}=[value]'),
     #               'cmd'   :   '<|object|> <attribute>=[value]',
     #               '_help' :   {
     #                               'cmd'                   : _('Delete (LDAP) attribute from device'),
     #                           },
     #           },

     #'add_object_class'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-device add_object_class {device} {object_class}'),
     #               'cmd'   :   '<|object|> <object_class>',
     #               '_help' :   {
     #                               'cmd'                   : _('Add (LDAP) object class to device'),
     #                           },
     #           },

     #'del_object_class'    : {
     #               '_cmd_usage_help' : _('Usage: otpme-device del_object_class {device} {object_class}'),
     #               'cmd'   :   '<|object|> <object_class>',
     #               '_help' :   {
     #                               'cmd'                   : _('Delete (LDAP) object class from device'),
     #                           },
     #           },

     #'show_ldif'    : {
     #               '_cmd_usage_help' : 'Usage: otpme-device show_ldif {device} -a attribute1,attribute2',
     #               'cmd'   :   '<|object|> -a :[attributes]:',
     #               '_help' :   {
     #                               'cmd'                   : 'show ldif representation of device',
     #                               '-a'                    : 'show only given LDIF attributes',
     #                           },
     #           },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-device add_acl {device} {role|token} {role_path|token_path} {acl[:value]}'),
                    'cmd'   :   '<|object|> <owner_type> <owner_name> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to device'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-device del_acl {device} {acl}'),
                    'cmd'   :   '<|object|> <acl>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from device'),
                                },
                },

     'show_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device show_acls {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show ACLs of device'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device enable_acl_inheritance {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for device'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device disable_acl_inheritance {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for device'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device move [--keep-acls] {device} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <new_unit>',
                    '_help' :   {
                                    'cmd'                   : _('Change device\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-device remove_orphans {device}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device description {device} [description]'),
                    'cmd'   :   '<|object|> [description]',
                    '_help' :   {
                                    'cmd'                   : _('Set device description'),
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
                    '_cmd_usage_help' : _('Usage: otpme-device export --password <password> {device}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export device config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device add_policy {device} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to device'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-device remove_policy {device} {policy}'),
                    'cmd'   :   '<|object|> <policy_name>',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from device'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-device list_policies {device}'),
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
    }
