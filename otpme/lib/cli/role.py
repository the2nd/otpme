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
from otpme.lib.classes.role import get_roles
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.group import get_acls
from otpme.lib.classes.group import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "role",
                "unit",
                "status",
                "roles",
                "tokens",
                "sync_users",
                "accessgroups",
                "groups",
                "policies",
                "inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'rel_path',
                        'enabled',
                        'description',
                        'unit',
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
    register_cli(name="role",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, role_order, role_data, acls, max_roles=5,
    max_tokens=5, max_sync_users=5, max_ags=5, max_groups=5, max_policies=5,
    output_fields=[], acl_checker=None, **kwargs):
    """ Build table rows for roles. """
    _result = []
    for role_uuid in role_order:
        row = []
        role_name = role_data[role_uuid]['name']
        unit_uuid = role_data[role_uuid]['unit'][0]
        try:
            enabled = role_data[role_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            description = role_data[role_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = role_data[role_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            role_acls = acls[role_uuid]
        except:
            role_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(role_acls)

        # Rolename.
        if "role" in output_fields:
            row.append(role_name)
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
        # Roles.
        if "roles" in output_fields:
            if check_acl("view:role") \
            or check_acl("add:role") \
            or check_acl("remove:role"):
                # Get all roles of this role.
                return_attrs = ['site', 'name', 'enabled']
                role_roles_result = backend.search(object_type="role",
                                        join_object_type="role",
                                        join_search_attr="uuid",
                                        join_search_val=role_uuid,
                                        join_attribute="role",
                                        attribute="uuid",
                                        value="*",
                                        return_attributes=return_attrs)
                role_roles = []
                roles_count = len(role_roles_result)
                for x in role_roles_result:
                    role_status_string = ""
                    x_role_name = role_roles_result[x]['name']
                    x_role_site = role_roles_result[x]['site']
                    x_role_enabled = role_roles_result[x]['enabled'][0]
                    if not x_role_enabled:
                        role_status_string = " (D)"
                    if x_role_site != config.site:
                        role_string = "%s/%s%s" % (x_role_site,
                                                x_role_name,
                                                role_status_string)
                    else:
                        role_string = "%s%s" % (x_role_name, role_status_string)
                    role_roles.append(role_string)
                    processed_roles = len(role_roles)
                    if processed_roles == max_roles:
                        if roles_count > max_roles:
                            x = ("(%s of %s roles total)"
                                % (processed_roles, roles_count))
                            role_roles.append(x)
                        break
                row.append("\n".join(role_roles))
            else:
                row.append("-")
        # Tokens.
        if "tokens" in output_fields:
            if check_acl("view:token") \
            or check_acl("add:token") \
            or check_acl("remove:token"):
                # Get all tokens of this role.
                return_attrs = ['rel_path', 'enabled']
                tokens_count, \
                role_tokens_result = backend.search(object_type="token",
                                            join_object_type="role",
                                            join_search_attr="uuid",
                                            join_search_val=role_uuid,
                                            join_attribute="token",
                                            attribute="uuid",
                                            value="*",
                                            max_results=max_tokens,
                                            return_query_count=True,
                                            return_attributes=return_attrs)
                role_tokens = []
                for x in role_tokens_result:
                    token_status_string = ""
                    x_token_rel_path = role_tokens_result[x]['rel_path']
                    x_token_enabled = role_tokens_result[x]['enabled'][0]
                    if not x_token_enabled:
                        token_status_string = " (D)"
                    token_string = "%s%s" % (x_token_rel_path,
                                            token_status_string)
                    role_tokens.append(token_string)
                    processed_tokens = len(role_tokens)
                    if processed_tokens == max_tokens:
                        if tokens_count > max_tokens:
                            x = ("(%s of %s tokens total)"
                                % (processed_tokens, tokens_count))
                            role_tokens.append(x)
                        break
                row.append("\n".join(role_tokens))
            else:
                row.append("-")
        # Tokens.
        if "sync_users" in output_fields:
            if check_acl("view:sync_user") \
            or check_acl("add:sync_user") \
            or check_acl("remove:sync_user"):
                # Get all tokens of this role.
                return_attrs = ['name', 'enabled']
                users_count, \
                role_users_result = backend.search(object_type="user",
                                            join_object_type="role",
                                            join_search_attr="uuid",
                                            join_search_val=role_uuid,
                                            join_attribute="sync_user",
                                            attribute="uuid",
                                            value="*",
                                            max_results=max_sync_users,
                                            return_query_count=True,
                                            return_attributes=return_attrs)
                role_users = []
                for x in role_users_result:
                    user_status_string = ""
                    x_user_name = role_users_result[x]['name']
                    x_user_enabled = role_users_result[x]['enabled'][0]
                    if not x_user_enabled:
                        user_status_string = " (D)"
                    token_string = "%s%s" % (x_user_name,
                                            user_status_string)
                    role_users.append(token_string)
                    processed_users = len(role_users)
                    if processed_users == max_sync_users:
                        if tokens_count > max_sync_users:
                            x = ("(%s of %s tokens total)"
                                % (processed_users, tokens_count))
                            role_users.append(x)
                        break
                row.append("\n".join(role_users))
            else:
                row.append("-")
        # Accessgroups.
        if "accessgroups" in output_fields:
            if check_acl("view:accessgroup") \
            or check_acl("add:accessgroup") \
            or check_acl("remove:accessgroup"):
                # Get all ags this role is in.
                role_ags = []
                role_ag_strings = []
                return_attrs = ['name', 'enabled']
                role_ags_count, \
                role_ags_result = backend.search(object_type="accessgroup",
                                        attribute="role",
                                        value=role_uuid,
                                        max_results=max_ags,
                                        return_query_count=True,
                                        return_attributes=return_attrs)
                processed_ags = 0
                for x_uuid in role_ags_result:
                    ag_name = role_ags_result[x_uuid]['name']
                    ag_enabled = role_ags_result[x_uuid]['enabled'][0]
                    ag_status_string = ""
                    if not ag_enabled:
                        ag_status_string = " (D)"
                    ag_string = "%s%s" % (ag_name, ag_status_string)
                    role_ags.append(x_uuid)
                    role_ag_strings.append(ag_string)
                    processed_ags += 1
                    if max_ags > 0:
                        if processed_ags == max_ags:
                            break
                # Get groups from parent roles.
                parent_role_ags = []
                return_attrs = ['name', 'uuid']
                role_roles = get_roles(role_uuid=role_uuid,
                                        parent=True,
                                        recursive=True,
                                        return_attributes=return_attrs)
                for x_role_data in role_roles:
                    x_role_name = x_role_data['name']
                    x_role_site = x_role_data['site']
                    x_role_uuid = x_role_data['uuid']
                    return_attrs = ['name', 'enabled']
                    parent_role_ags_count, \
                    parent_ags_result = backend.search(object_type="accessgroup",
                                                        attribute="role",
                                                        value=x_role_uuid,
                                                        max_results=max_ags,
                                                        return_query_count=True,
                                                        return_attributes=return_attrs)
                    role_ags_count += parent_role_ags_count
                    for x_uuid in parent_ags_result:
                        if x_uuid in role_ags:
                            continue
                        if x_uuid in parent_role_ags:
                            continue
                        ag_name = parent_ags_result[x_uuid]['name']
                        ag_enabled = parent_ags_result[x_uuid]['enabled'][0]
                        ag_status_string = ""
                        if not ag_enabled:
                            ag_status_string = " (D)"
                        if x_role_site != config.site:
                            ag_string = ("%s (%s/%s)"
                                        % (ag_name, x_role_site, x_role_name))
                        else:
                            ag_string = "%s (%s)" % (ag_name, x_role_name)
                        if ag_status_string:
                            ag_string = "%s (%s)" % (ag_string,
                                                    ag_status_string)
                        parent_role_ags.append(x_uuid)
                        if max_ags > 0:
                            if processed_ags == max_ags:
                                break
                        processed_ags += 1
                        role_ag_strings.append(ag_string)
                if processed_ags == max_ags:
                    if role_ags_count > max_ags:
                        x = ("(%s of %s accessgroups)"
                            % (processed_ags, role_ags_count))
                        role_ag_strings.append(x)
                row.append("\n".join(role_ag_strings))
            else:
                row.append("-")
        # Groups.
        if "groups" in output_fields:
            if check_acl("view:group") \
            or check_acl("add:group") \
            or check_acl("remove:group"):
                # Get all groups this role is in.
                role_groups = []
                role_group_stings = []
                return_attrs = ['name', 'enabled']
                role_groups_count, \
                role_groups_result = backend.search(object_type="group",
                                        attribute="role",
                                        value=role_uuid,
                                        max_results=max_groups,
                                        return_query_count=True,
                                        return_attributes=return_attrs)
                processed_groups = 0
                for x_uuid in role_groups_result:
                    group_name = role_groups_result[x_uuid]['name']
                    group_enabled = role_groups_result[x_uuid]['enabled'][0]
                    group_status_string = ""
                    if not group_enabled:
                        group_status_string = " (D)"
                    group_string = "%s%s" % (group_name, group_status_string)
                    role_groups.append(x_uuid)
                    role_group_stings.append(group_string)
                    processed_groups += 1
                    if max_groups > 0:
                        if processed_groups == max_groups:
                            break
                # Get groups from parent roles.
                parent_role_groups = []
                return_attrs = ['name', 'uuid']
                role_roles = get_roles(role_uuid=role_uuid,
                                        parent=True,
                                        recursive=True,
                                        return_attributes=return_attrs)
                for x_role_data in role_roles:
                    x_role_name = x_role_data['name']
                    x_role_site = x_role_data['site']
                    x_role_uuid = x_role_data['uuid']
                    return_attrs = ['name', 'enabled']
                    parent_role_groups_count, \
                    parent_groups_result = backend.search(object_type="group",
                                                        attribute="role",
                                                        value=x_role_uuid,
                                                        max_results=max_groups,
                                                        return_query_count=True,
                                                        return_attributes=return_attrs)
                    role_groups_count += parent_role_groups_count
                    for x_uuid in parent_groups_result:
                        if x_uuid in role_groups:
                            continue
                        if x_uuid in parent_role_groups:
                            continue
                        group_name = parent_groups_result[x_uuid]['name']
                        group_enabled = parent_groups_result[x_uuid]['enabled'][0]
                        group_status_string = ""
                        if not group_enabled:
                            group_status_string = " (D)"
                        if x_role_site != config.site:
                            group_string = ("%s (%s/%s)"
                                        % (group_name, x_role_site, x_role_name))
                        else:
                            group_string = "%s (%s)" % (group_name, x_role_name)
                        if group_status_string:
                            group_string = "%s (%s)" % (group_string,
                                                        group_status_string)
                        parent_role_groups.append(x_uuid)
                        if max_groups > 0:
                            if processed_groups == max_groups:
                                break
                        processed_groups += 1
                        role_group_stings.append(group_string)
                if processed_groups == max_groups:
                    if role_groups_count > max_groups:
                        x = ("(%s of %s groups)"
                            % (processed_groups, role_groups_count))
                        role_group_stings.append(x)
                row.append("\n".join(role_group_stings))
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="accessgroup",
                                                    object_uuid=role_uuid,
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
                'uuid'              : role_uuid,
                'name'              : role_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
