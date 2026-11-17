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
    register_cmd_help(command="group", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-group {command} [group]"),

    'show'      : {
                    '_cmd_usage_help' : _('Usage: otpme-group show [--policy-limit <limit>] [--role-limit <limit>] [--token-limit <limit>] [--host-limit <limit>] [--fields <field1,field2,field3>] [-z <size_limit>] [-a] [--limit <limit>] [--sort-by <attribute>] [--reverse] [--raw] [--csv] [--csv-sep <separator>] [group]'),
                    'cmd'   :   '--policy-limit :max_policies: --role-limit :max_roles: --token-limit :max_tokens: --host-limit :max_hosts: --limit :limit: --fields :"output_fields": -z :max_len: --sort-by :"sort_by": --reverse :reverse=True: -a :show_all=True: --raw :header=False: --csv :csv=True: --csv-sep :"csv_sep": [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show group(s)'),
                                    '-a'                    : _('Show all groups.'),
                                    '-z <limit>'            : _('Limit output size'),
                                    '--fields f1,f2,f3'     : _('Output only given fields'),
                                    '--reverse'             : _('Reverse the output order.'),
                                    '--sort-by <attribute>' : _('Sort output by <attribute>.'),
                                    '--role-limit <limit>'  : _('Output max roles.'),
                                    '--token-limit <limit>' : _('Output max tokens.'),
                                    '--host-limit <limit>'  : _('Output max hosts.'),
                                    '--policy-limit <limit>': _('Output max policies.'),
                                    '--limit <limit>'       : _('Limit number of items shown per object.'),
                                    '--raw'                 : _('Output table without any headers/borders.'),
                                    '--csv'                 : _('Output table as CSV.'),
                                    '--csv-sep <separator>' : _('Separator between the CSV columns.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group list [--attribute attribute] [-a] [pattern]'),
                    'cmd'   :   '--attribute :"attribute": -a :show_all=True: ["search_regex"]',
                    '_help' :   {
                                    'cmd'                       : _('List groups.'),
                                    '-a'                        : _('List all groups.'),
                                    '--attribute <attribute>'   : _('Match the pattern against this attribute instead of the name.')
                                },
                },

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group add [--attributes <attr1=val1,attr2=val2>] {group}'),
                    'cmd'   :   '--attributes :[ldif_attributes]: <|object|>',
                    '_help' :   {
                                    'cmd'                                   : _('Add new group'),
                                    '--attributes <attr1=val1,attr2=val2>'  : _('Set attributes of the posix extension, e.g. gidNumber=5000.'),
                                },
                },

    'del'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group del [--no-trash] {group}'),
                    'cmd'   :   '--no-trash :add_to_trash=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Delete group'),
                                    '--no-trash'            : _('Delete without moving the object to the trash.'),
                                },
                },

    'get_config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group get_config {group} {parameter}'),
                    'cmd'   :   '<|object|> <"parameter">',
                    '_help' :   {
                                    'cmd'                   : _('Get config parameter.'),
                                },
                },
    'show_oid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group show_oid [--full] {group}'),
                    'cmd'   :   '--full :full=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the OID of the object.'),
                                    '--full'                : _('Show the full OID.'),
                                },
                },
    'show_uuid'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group show_uuid {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the UUID of the object.'),
                                },
                },
    'changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group changelog {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show object changelog.'),
                                },
                },
    'edit_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group edit_changelog {group} {entry_id} {comment}'),
                    'cmd'   :   '<|object|> <entry_id> <"comment">',
                    '_help' :   {
                                    'cmd'                   : _('Edit changelog entry comment.'),
                                },
                },
    'del_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group del_changelog {group} {entry_id}'),
                    'cmd'   :   '<|object|> <entry_id>',
                    '_help' :   {
                                    'cmd'                   : _('Remove changelog entry comment.'),
                                },
                },
    'clear_changelog'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group clear_changelog {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Clear object changelog.'),
                                },
                },

    'touch'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group touch {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Touch group (e.g. migrate).'),
                                },
                },

    'auto_disable'          : {
                    '_cmd_usage_help' : _('Usage: otpme-group auto_disable {group} {time}'),
                    'cmd'   :   '<|object|> <auto_disable>',
                    '_help' :   {
                                    'cmd'                   : _('Change auto disable value (e.g "+30D" or "09:53 13.06.2023", 0 removes it).'),
                                },
                },

    'enable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group enable [--share-notify] [--no-share-notify] [--no-persist-mount] {group}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --no-persist-mount :persist_mount=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable group'),
                                    '--share-notify'        : _('Tell the users of the affected shares, so that their hosts mount or unmount them.'),
                                    '--no-share-notify'     : _('Do not tell them; without either option the share decides.'),
                                    '--no-persist-mount'    : _('Mount now, but an offline login does not mount the share.'),
                                },
                },

    'disable'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group disable [--share-notify] [--no-share-notify] [--no-persist-mount] {group}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --no-persist-mount :persist_mount=False: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable group'),
                                    '--share-notify'        : _('Tell the users of the affected shares, so that their hosts mount or unmount them.'),
                                    '--no-share-notify'     : _('Do not tell them; without either option the share decides.'),
                                    '--no-persist-mount'    : _('Unmount now, but an offline login still mounts the share.'),
                                },
                },

    'rename'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group rename {group} {new_name}'),
                    'cmd'   :   '<|object|> <"new_name">',
                    '_help' :   {
                                    'cmd'                   : _('Rename group'),
                                },
                },

     'config'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group config [-d] [-a] {group} {param} [value]'),
                    'cmd'   :   '-d :delete=True: -a :append=True: <|object|> <"parameter"> [value]',
                    '_help' :   {
                                    'cmd'                   : _('Add config parameter to group.'),
                                    '-a'                    : _('Append value to config parameter.'),
                                    '-d'                    : _('Delete config parameter.'),
                                },
                },

    'show_config'      : {
                    '_cmd_usage_help' : _('Usage: otpme-group show_config {group} [parameter]'),
                    'cmd'   :   '<|object|> ["parameter"]',
                    '_help' :   {
                                    'cmd'                   : _('Show group config parameters'),
                                },
                },

     'add_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_extension {group} {extension}'),
                    'cmd'   :   '<|object|> <"extension">',
                    '_help' :   {
                                    'cmd'                   : _('Add extension to group'),
                                },
                },

     'remove_extension'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_extension {group} {extension}'),
                    'cmd'   :   '<|object|> <"extension">',
                    '_help' :   {
                                    'cmd'                   : _('Remove extension from group'),
                                },
                },

     'add_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_attribute {group} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) attribute to group'),
                                },
                },

     'modify_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group modify_attribute {group} {attribute} {old_value} {new_value}'),
                    'cmd'   :   '<|object|> <"attribute"> <old_value> <new_value>',
                    '_help' :   {
                                    'cmd'                   : _('Modify (LDAP) attribute of group'),
                                },
                },

     'del_attribute'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group del_attribute {group} {attribute}=[value]'),
                    'cmd'   :   '<|object|> <attribute>=[value]',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) attribute from group'),
                                },
                },

     'add_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_object_class {group} {object_class}'),
                    'cmd'   :   '<|object|> <"object_class">',
                    '_help' :   {
                                    'cmd'                   : _('Add (LDAP) object class to group'),
                                },
                },

     'del_object_class'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group del_object_class {group} {object_class}'),
                    'cmd'   :   '<|object|> <"object_class">',
                    '_help' :   {
                                    'cmd'                   : _('Delete (LDAP) object class from group'),
                                },
                },

     'show_ldif'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group show_ldif {group} [-a attribute1,attribute2]'),
                    'cmd'   :   '<|object|> -a :[attributes]:',
                    '_help' :   {
                                    'cmd'                   : _('Show LDIF representation of group'),
                                    '-a'                    : _('Show only given LDIF attributes'),
                                },
                },

    'add_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_acl {group} {role|token} {role_path|token_path} {acl[:value][,acl[:value]]}'),
                    'cmd'   :   '<|object|> <"owner_type"> <"owner_name"> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Add ACL to group'),
                                },
                },

    'del_acl'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group del_acl {group} {acl[,acl]}'),
                    'cmd'   :   '<|object|> <[acls]>',
                    '_help' :   {
                                    'cmd'                   : _('Delete ACL from group'),
                                },
                },

     'list_acls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_acls {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('List ACLs set on this group.'),
                                },
                },


     'enable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group enable_acl_inheritance {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable ACL inheritance for group'),
                                },
                },


     'disable_acl_inheritance'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group disable_acl_inheritance {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable ACL inheritance for group'),
                                },
                },


    'move'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group move [--keep-acls] {group} {unit}'),
                    'cmd'   :   '--keep-acls :keep_acls=True: <|object|> <"new_unit">',
                    '_help' :   {
                                    'cmd'                   : _('Change group\'s unit'),
                                    '--keep-acls'           : _('Keep object ACLs.')
                                },
                },


    'remove_orphans'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_orphans {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Remove orphan UUIDs'),
                                },
                },


    'description'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group description {group} [description]'),
                    'cmd'   :   '<|object|> ["description"]',
                    '_help' :   {
                                    'cmd'                   : _('Set group description'),
                                },
                },

    'info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group info [--language <language>] {group} [info]'),
                    'cmd'   :   '--language :"language": <|object|> ["info"]',
                    '_help' :   {
                                    'cmd'                   : _('Set group info'),
                                    '--language <lang>'     : _('Change info for language.'),
                                },
                },

    'dump_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group dump_info [--language <language>] {group}'),
                    'cmd'   :   '--language :"language": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump group info'),
                                    '--language <lang>'     : _('Dump info for language.'),
                                },
                },

    'show_info'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group show_info {group}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Show the languages that have an info'),
                                },
                },

    'list_sync_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_sync_users [--return-type <type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                       : _('List sync users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_users [--return-type <type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                       : _('List users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_default_group_users'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_default_group_users [--return-type <type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                       : _('List default group users.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },
    'list_tokens'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_tokens [--return-type <type>] [--token-types <hotp,totp>] {group}'),
                    'cmd'   :   '--return-type :"return_type": --token-types :[token_types]: [|object|]',
                    'ovals' :   {
                                'return_type'   : ['rel_path', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : _('List assigned tokens.'),
                                    '--return-type'             : _('Attribute to return.'),
                                    '--token-types <hotp,totp>' : _('Token types to list.'),
                                },
                },
    'list_roles'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_roles [--return-type <type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : _('List assigned roles.'),
                                    '--return-type'         : _('Attribute to return.'),
                                },
                },
    'find_scopes'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group find_scopes [--return-type <return_type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": <|object|>',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : _('Find scopes this group is assigned to.'),
                                    '--return-type'         : _('Attribute to return.'),
                                },
                },
    'find_shares'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group find_shares [--return-type <return_type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": <|object|>',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                   : _('Find shares this group is assigned to.'),
                                    '--return-type'         : _('Attribute to return.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-group export [--password <password>] {group}'),
                    'cmd'   :   '--password :"password": <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Export group config to stdout'),
                                    '--password <password>' : _('Encrypt object config with password.'),
                                },
                },

    'add_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_policy {group} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add policy to group'),
                                },
                },

    'remove_policy'    : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_policy {group} {policy}'),
                    'cmd'   :   '<|object|> <"policy_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove policy from group'),
                                },
                },

    'list_policies'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_policies [--return-type <type>] [--policy-types <type1,type2>] {group}'),
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
    'add_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_role {group} {role}'),
                    'cmd'   :   '<|object|> <"role_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add role to group'),
                                },
                },

    'remove_role'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_role {group} {role}'),
                    'cmd'   :   '<|object|> <"role_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove role from group'),
                                },
                },

    'add_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_token [--sign] [--tags {tag1,tag2,...}] [--no-auto-sign] {group} {token}'),
                    'cmd'   :   '--no-auto-sign :auto_sign=False: --sign :sign=True: --tags :[tags]: <|object|> <"token_path">',
                    '_help' :   {
                                    'cmd'                   : _('Add token to group.'),
                                    '--sign'                : _('Sign the object with default tags.'),
                                    '--tags <tag1,tag2>'    : _('Add tags to signature.'),
                                    '--no-auto-sign'        : _('Do not sign this time.'),
                                },
                },

    'remove_token'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_token [--keep-sign] {group} {token}'),
                    'cmd'   :   '--keep-sign :keep_sign=True: <|object|> <"token_path">',
                    '_help' :   {
                                    'cmd'                   : _('Remove token from group.'),
                                    '--keep-sign'           : _('Do not remove any signature.'),
                                },
                },

    'add_sync_user'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_sync_user {group} {user}'),
                    'cmd'   :   '<|object|> <"user_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add sync user to group.'),
                                },
                },

    'remove_sync_user'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_sync_user {group} {user}'),
                    'cmd'   :   '<|object|> <"user_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove sync user from group.'),
                                },
                },

    'add_host'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group add_host [--share-notify] [--no-share-notify] [--no-persist-mount] {group} {host}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --no-persist-mount :persist_mount=False: <|object|> <"host_name">',
                    '_help' :   {
                                    'cmd'                   : _('Add host to group.'),
                                    '--share-notify'        : _('Tell the users of the affected shares, so that their hosts mount or unmount them.'),
                                    '--no-share-notify'     : _('Do not tell them; without either option the share decides.'),
                                    '--no-persist-mount'    : _('Mount now, but an offline login does not mount the share.'),
                                },
                },

    'remove_host'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group remove_host [--share-notify] [--no-share-notify] [--no-persist-mount] {group} {host}'),
                    'cmd'   :   '--share-notify :share_notifications=True: --no-share-notify :share_notifications=False: --no-persist-mount :persist_mount=False: <|object|> <"host_name">',
                    '_help' :   {
                                    'cmd'                   : _('Remove host from group.'),
                                    '--share-notify'        : _('Tell the users of the affected shares, so that their hosts mount or unmount them.'),
                                    '--no-share-notify'     : _('Do not tell them; without either option the share decides.'),
                                    '--no-persist-mount'    : _('Unmount now, but an offline login still mounts the share.'),
                                },
                },

    'list_hosts'   : {
                    '_cmd_usage_help' : _('Usage: otpme-group list_hosts [--return-type <type>] {group}'),
                    'cmd'   :   '--return-type :"return_type": [|object|]',
                    'ovals' :   {
                                'return_type'   : ['name', 'read_oid', 'full_oid', 'uuid'],
                                },
                    '_help' :   {
                                    'cmd'                       : _('List assigned hosts.'),
                                    '--return-type'             : _('Attribute to return.'),
                                },
                },

    }
