# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.scope import get_acls
from otpme.lib.classes.scope import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "scope",
                "unit",
                "status",
                "auto_member",
                "roles",
                "tokens",
                "clients",
                "groups",
                "scope_id",
                "policies",
                #"inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'rel_path',
                        'enabled',
                        'auto_member',
                        'description',
                        'unit',
                        'scope_id',
                        #'acl_inheritance_enabled',
                        ]
    read_acls, write_acls = get_acls(split=True)
    read_value_acls, write_value_acls = get_value_acls(split=True)
    for acl in read_value_acls:
        for x in read_value_acls[acl]:
            x_acl = f"{acl}:{x}"
            read_acls.append(x_acl)
    for acl in write_value_acls:
        for x in write_value_acls[acl]:
            x_acl = f"{acl}:{x}"
            write_acls.append(x_acl)
    # Remove duplicates.
    read_acls = set(read_acls)
    write_acls = set(write_acls)
    register_cli(name="scope",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=10)

def row_getter(realm, site, scope_order, scope_data, acls,
    limit=None, max_scopes=5, max_tokens=5, max_roles=5, max_policies=5,
    max_clients=5, max_groups=5, output_fields=None, acl_checker=None,
    **kwargs):
    """ Build table rows for scopes. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(scope_order) == 1:
            limit = 30
    if limit is not None:
        max_tokens = limit
        max_roles = limit
        max_policies = limit
        max_clients = limit
        max_groups = limit
    for scope_uuid in scope_order:
        row = []
        scope_name = scope_data[scope_uuid]['name']
        unit_uuid = scope_data[scope_uuid]['unit'][0]
        try:
            scope_id = scope_data[scope_uuid]['scope_id'][0]
        except Exception:
            scope_id = None
        try:
            auto_member = scope_data[scope_uuid]['auto_member'][0]
        except Exception:
            auto_member = False
        try:
            enabled = scope_data[scope_uuid]['enabled'][0]
        except Exception:
            enabled = False
        try:
            description = scope_data[scope_uuid]['description'][0]
        except Exception:
            description = None
        #try:
        #    acl_inheritance_enabled = scope_data[scope_uuid]['acl_inheritance_enabled'][0]
        #except:
        #    acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            scope_acls = acls[scope_uuid]
        except Exception:
            scope_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(scope_acls)

        # Rolename.
        if "scope" in output_fields:
            row.append(scope_name)
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
                    enabled_string = _("Enabled")
                else:
                    enabled_string = _("Disabled")
                row.append(enabled_string)
            else:
                row.append("-")
        # Auto member.
        if "auto_member" in output_fields:
            if check_acl("view:auto_member") \
            or check_acl("enable:auto_member") \
            or check_acl("disable:auto_member"):
                if auto_member:
                    enabled_string = _("Enabled")
                else:
                    enabled_string = _("Disabled")
                row.append(enabled_string)
            else:
                row.append("-")
        # Roles.
        if "roles" in output_fields:
            if check_acl("view:roles") \
            or check_acl("add:role") \
            or check_acl("remove:role"):
                # Get all roles of this role.
                return_attrs = ['site', 'name', 'enabled']
                role_roles_result = backend.search(object_type="role",
                                        join_object_type="scope",
                                        join_search_attr="uuid",
                                        join_search_val=scope_uuid,
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
                    if x_role_site == config.site:
                        role_string = f"{x_role_name} {role_status_string}"
                    else:
                        role_string = f"{x_role_name} ({x_role_site}) {role_status_string}"
                    role_roles.append(role_string)
                    processed_roles = len(role_roles)
                    if processed_roles == max_roles:
                        if roles_count > max_roles:
                            msg = _("({processed_roles} of {roles_count} roles total)")
                            msg = msg.format(processed_roles=processed_roles, roles_count=roles_count)
                            x = msg
                            role_roles.append(x)
                        break
                row.append("\n".join(role_roles))
            else:
                row.append("-")
        # Tokens.
        if "tokens" in output_fields:
            if check_acl("view:tokens") \
            or check_acl("add:token") \
            or check_acl("remove:token"):
                # Get all tokens of this role.
                return_attrs = ['rel_path', 'enabled']
                tokens_count, \
                tokens_result = backend.search(object_type="token",
                                            join_object_type="scope",
                                            join_search_attr="uuid",
                                            join_search_val=scope_uuid,
                                            join_attribute="token",
                                            attribute="uuid",
                                            value="*",
                                            max_results=max_tokens,
                                            return_query_count=True,
                                            return_attributes=return_attrs)
                role_tokens = []
                for x in tokens_result:
                    token_status_string = ""
                    x_token_rel_path = tokens_result[x]['rel_path']
                    x_token_enabled = tokens_result[x]['enabled'][0]
                    if not x_token_enabled:
                        token_status_string = " (D)"
                    token_string = f"{x_token_rel_path}{token_status_string}"
                    role_tokens.append(token_string)
                    processed_tokens = len(role_tokens)
                    if processed_tokens == max_tokens:
                        if tokens_count > max_tokens:
                            msg = _("({processed_tokens} of {tokens_count} tokens total)")
                            msg = msg.format(processed_tokens=processed_tokens, tokens_count=tokens_count)
                            x = msg
                            role_tokens.append(x)
                        break
                row.append("\n".join(role_tokens))
            else:
                row.append("-")
        # Clients.
        if "clients" in output_fields:
            if check_acl("view:clients") \
            or check_acl("add:client") \
            or check_acl("remove:client"):
                # Get all clients of this role.
                return_attrs = ['name', 'enabled']
                clients_count, \
                clients_result = backend.search(object_type="client",
                                            join_object_type="scope",
                                            join_search_attr="uuid",
                                            join_search_val=scope_uuid,
                                            join_attribute="client",
                                            attribute="uuid",
                                            value="*",
                                            max_results=max_clients,
                                            return_query_count=True,
                                            return_attributes=return_attrs)
                role_clients = []
                for x in clients_result:
                    client_status_string = ""
                    x_client_name = clients_result[x]['name']
                    x_client_enabled = clients_result[x]['enabled'][0]
                    if not x_client_enabled:
                        client_status_string = " (D)"
                    client_string = f"{x_client_name}{client_status_string}"
                    role_clients.append(client_string)
                    processed_clients = len(role_clients)
                    if processed_clients == max_clients:
                        if clients_count > max_clients:
                            msg = _("({processed_clients} of {clients_count} clients total)")
                            msg = msg.format(processed_clients=processed_clients, clients_count=clients_count)
                            x = msg
                            role_clients.append(x)
                        break
                row.append("\n".join(role_clients))
            else:
                row.append("-")
        # Groups (scope's group whitelist).
        if "groups" in output_fields:
            if check_acl("view:groups") \
            or check_acl("add:group") \
            or check_acl("remove:group"):
                return_attrs = ['name', 'enabled']
                groups_count, \
                groups_result = backend.search(object_type="group",
                                            join_object_type="scope",
                                            join_search_attr="uuid",
                                            join_search_val=scope_uuid,
                                            join_attribute="group",
                                            attribute="uuid",
                                            value="*",
                                            max_results=max_groups,
                                            return_query_count=True,
                                            return_attributes=return_attrs)
                scope_groups = []
                for x in groups_result:
                    group_status_string = ""
                    x_group_name = groups_result[x]['name']
                    x_group_enabled = groups_result[x]['enabled'][0]
                    if not x_group_enabled:
                        group_status_string = " (D)"
                    group_string = f"{x_group_name}{group_status_string}"
                    scope_groups.append(group_string)
                    processed_groups = len(scope_groups)
                    if processed_groups == max_groups:
                        if groups_count > max_groups:
                            msg = _("({processed_groups} of {groups_count} groups total)")
                            msg = msg.format(processed_groups=processed_groups, groups_count=groups_count)
                            x = msg
                            scope_groups.append(x)
                        break
                row.append("\n".join(scope_groups))
            else:
                row.append("-")
        # Scope ID.
        if "scope_id" in output_fields:
            row.append(scope_id)
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="scope",
                                                    object_uuid=scope_uuid,
                                                    max_policies=max_policies)
                row.append(policies_string)
            else:
                row.append("-")
        ## Inherit.
        #if "inherit" in output_fields:
        #    if check_acl("view:acl_inheritance") \
        #    or check_acl("enable:acl_inheritance") \
        #    or check_acl("disable:acl_inheritance"):
        #        if acl_inheritance_enabled:
        #            acl_inheritance_string = _("Enabled")
        #        else:
        #            acl_inheritance_string = _("Disabled")
        #        row.append(acl_inheritance_string)
        #    else:
        #        row.append("-")
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
                'uuid'              : scope_uuid,
                'name'              : scope_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
