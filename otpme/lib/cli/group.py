# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.group import get_acls
from otpme.lib.classes.group import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "groupname",
                "unit",
                "status",
                "roles",
                "tokens",
                "sync_users",
                "policies",
                "inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'enabled',
                        'unit',
                        'description',
                        'acl_inheritance_enabled',
                        ]
    read_acls, write_acls = get_acls(split=True)
    read_value_acls, write_value_acls = get_value_acls(split=True)
    for acl in read_value_acls:
        for x in read_value_acls[acl]:
            x_acl = "%s:%s" % (acl, x)
            read_acls.append(x_acl)
    for acl in write_value_acls:
        for x in write_value_acls[acl]:
            x_acl = "%s:%s" % (acl, x)
            write_acls.append(x_acl)
    register_cli(name="group",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, group_order, group_data, acls, max_roles=5,
    max_tokens=5, max_sync_users=5, max_policies=5, output_fields=[],
    acl_checker=None, **kwargs):
    """ Build table rows for groups. """
    _result = []
    for group_uuid in group_order:
        row = []
        group_name = group_data[group_uuid]['name']
        unit_uuid = group_data[group_uuid]['unit'][0]
        try:
            enabled = group_data[group_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            description = group_data[group_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = group_data[group_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            group_acls = acls[group_uuid]
        except:
            group_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(group_acls)

        # Groupname.
        if "groupname" in output_fields:
            row.append(group_name)
        # Unit.
        if "unit" in output_fields:
            unit_string = get_unit_string(unit_uuid)
            row.append(unit_string)
        # Status.
        if "status" in output_fields:
            if check_acl("view:status") \
            or check_acl("enable:object") \
            or check_acl("disable:object"):
                if enabled:
                    enabled_string = "Enabled"
                else:
                    enabled_string = "Disabled"
                row.append(enabled_string)
            else:
                row.append("-")
        # Roles/Tokens.
        get_roles = False
        role_access = False
        if "roles" in output_fields:
            processed_tokens = []
            if check_acl("view:role"):
                role_access = True
                get_roles = True
        token_roles = {}
        role_tokens_count = 0
        group_tokens_count = 0
        role_tokens_result = []
        if get_roles:
            member_roles = []
            return_attrs = ['site', 'name', 'enabled']
            roles_count, roles_result = backend.search(object_type="role",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="group",
                                                join_search_attr="uuid",
                                                join_search_val=group_uuid,
                                                join_attribute="role",
                                                order_by="name",
                                                max_results=max_roles,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for role_uuid in roles_result:
                role_site = roles_result[role_uuid]['site']
                role_name = roles_result[role_uuid]['name']
                role_enabled = roles_result[role_uuid]['enabled'][0]
                role_status_string = ""
                if not role_enabled:
                    role_status_string = " (D)"
                if role_site == config.site:
                    role_string = ("%s %s" % (role_name,
                                            role_status_string))
                else:
                    role_string = ("%s (%s) %s" % (role_name,
                                                role_site,
                                                role_status_string))
                member_roles.append(role_string)

                return_attrs = ['name', 'name', 'enabled']
                role_tokens_count, \
                role_tokens_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="role",
                                                join_search_attr="uuid",
                                                join_search_val=role_uuid,
                                                join_attribute="token",
                                                order_by="name",
                                                max_results=max_tokens,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
                for token_uuid in role_tokens_result:
                    token_roles[token_uuid] = role_uuid
                processed_roles = len(member_roles)
                if processed_roles == max_roles:
                    if roles_count > max_roles:
                        x = ("(%s of %s roles total)"
                            % (processed_roles, roles_count))
                        member_roles.append(x)
                    break
            row.append("\n".join(member_roles))
        else:
            if role_access:
                row.append("")
            else:
                row.append("-")
        # Tokens.
        get_tokens = False
        token_access = False
        if "tokens" in output_fields:
            if check_acl("view:token"):
                token_access = True
                get_tokens = True
        if get_tokens:
            member_tokens = []
            group_member_tokens = []
            return_attrs = ['rel_path', 'enabled']
            group_tokens_count, \
            group_tokens_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="group",
                                                join_search_attr="uuid",
                                                join_search_val=group_uuid,
                                                join_attribute="token",
                                                order_by="rel_path",
                                                max_results=max_tokens,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for token_uuid in group_tokens_result:
                group_member_tokens.append(token_uuid)
                if len(processed_tokens) >= max_tokens:
                    break
                token_rel_path = group_tokens_result[token_uuid]['rel_path']
                token_enabled = group_tokens_result[token_uuid]['enabled'][0]
                token_string = token_rel_path
                if not token_enabled:
                    token_string += " (D)"
                member_tokens.append(token_string)
                processed_tokens.append(token_uuid)

            if group_tokens_count > max_tokens:
                x = ("(%s of %s tokens total)"
                    % (len(processed_tokens), group_tokens_count))
                member_tokens.append(x)

            row.append("\n".join(member_tokens))
        else:
            if token_access:
                row.append("")
            else:
                row.append("-")
        # Users.
        get_sync_users = False
        user_access = False
        processed_users = []
        if "sync_users" in output_fields:
            if check_acl("view:sync_users"):
                user_access = True
                get_sync_users = True
        if get_sync_users:
            member_users = []
            return_attrs = ['name', 'enabled']
            group_users_count, \
            group_users_result = backend.search(object_type="user",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="group",
                                                join_search_attr="uuid",
                                                join_search_val=group_uuid,
                                                join_attribute="sync_user",
                                                order_by="rel_path",
                                                max_results=max_sync_users,
                                                return_query_count=True,
                                                return_attributes=return_attrs,
                                                realm=realm,
                                                site=site)
            for user_uuid in group_users_result:
                if len(processed_users) >= max_sync_users:
                    break
                user_name = group_users_result[user_uuid]['name']
                user_enabled = group_users_result[user_uuid]['enabled'][0]
                user_string = user_name
                if not user_enabled:
                    user_string += " (D)"
                member_users.append(user_string)
                processed_users.append(user_uuid)

            if group_users_count > max_sync_users:
                x = ("(%s of %s users total)"
                    % (len(processed_users), group_users_count))
                member_users.append(x)

            row.append("\n".join(member_users))
        else:
            if user_access:
                row.append("")
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="group",
                                                    object_uuid=group_uuid,
                                                    max_policies=max_policies)
                row.append(policies_string)
            else:
                row.append("-")
        # Inherit.
        if "inherit" in output_fields:
            if check_acl("view:acl_inheritance") \
            or check_acl("enable:acl_inheritance") \
            or check_acl("disable:acl_inheritance"):
                if acl_inheritance_enabled:
                    acl_inheritance_string = "Enabled"
                else:
                    acl_inheritance_string = "Disabled"
                row.append(acl_inheritance_string)
            else:
                row.append("-")
        # Description.
        if "description" in output_fields:
            if check_acl("view:description") \
            or check_acl("edit:description"):
                if description is None:
                    description_string = ""
                else:
                    description_string = description
                row.append(description_string)
            else:
                row.append("-")
        # Build row entry.
        entry = {
                'uuid'              : group_uuid,
                'name'              : group_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
