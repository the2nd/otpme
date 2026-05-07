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

from otpme.lib import oid
from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.client import get_acls
from otpme.lib.classes.client import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "clientname",
                "unit",
                "status",
                "accessgroup",
                "roles",
                "tokens",
                "scopes",
                "dot1x",
                "oidc",
                "logins",
                "addresses",
                "auth_cache",
                "auth_cache_timeout",
                "policies",
                #"inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'enabled',
                        'address',
                        'unit',
                        'description',
                        'accessgroup',
                        'logins_limited',
                        'auth_cache_enabled',
                        'auth_cache_timeout',
                        'dot1x_auth',
                        'oidc_auth',
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
    register_cli(name="client",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, client_order, client_data, acls, max_tokens=5,
    max_roles=5, max_policies=5, max_scopes=5, output_fields=None,
    acl_checker=None, **kwargs):
    """ Build table rows for clients. """
    if output_fields is None:
        output_fields = []
    _result = []
    for client_uuid in client_order:
        row = []
        client_name = client_data[client_uuid]['name']
        try:
            enabled = client_data[client_uuid]['enabled'][0]
        except Exception:
            enabled = False
        try:
            unit_uuid = client_data[client_uuid]['unit'][0]
        except Exception:
            unit_uuid = None
        try:
            addresses = client_data[client_uuid]['address']
        except Exception:
            addresses = None
        try:
            auth_cache_enabled = client_data[client_uuid]['auth_cache_enabled']
        except Exception:
            auth_cache_enabled = False
        try:
            auth_cache_timeout = client_data[client_uuid]['auth_cache_timeout'][0]
        except Exception:
            auth_cache_timeout = "Not set"
        try:
            logins_limited = client_data[client_uuid]['logins_limited'][0]
        except Exception:
            logins_limited = False
        try:
            access_group = client_data[client_uuid]['accessgroup'][0]
        except Exception:
            access_group = None
        try:
            dot1x_auth = client_data[client_uuid]['dot1x_auth'][0]
        except Exception:
            dot1x_auth = False
        try:
            oidc_auth = client_data[client_uuid]['oidc_auth'][0]
        except Exception:
            oidc_auth = False
        try:
            description = client_data[client_uuid]['description'][0]
        except Exception:
            description = None
        #try:
        #    acl_inheritance_enabled = client_data[client_uuid]['acl_inheritance_enabled'][0]
        #except Exception:
        #    acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            client_acls = acls[client_uuid]
        except Exception:
            client_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(client_acls)

        # Clientname.
        if "clientname" in output_fields:
            row.append(client_name)
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
        # Accessgroup.
        if "accessgroup" in output_fields:
            if check_acl("view:accessgroups") \
            or check_acl("edit:accessgroup"):
                if access_group:
                    ag_oid = backend.get_oid(access_group)
                    ag_oid = oid.get(ag_oid)
                    row.append(ag_oid.name)
                else:
                    row.append("")
            else:
                row.append("-")
        # Roles/Tokens.
        get_roles = False
        role_access = False
        processed_roles = []
        if "roles" in output_fields:
            if check_acl("view:roles"):
                role_access = True
                get_roles = True
        group_tokens_count = 0
        if get_roles:
            member_roles = []
            return_attrs = ['name', 'rel_path', 'enabled', 'site']
            roles_count, roles_result = backend.search(object_type="role",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="client",
                                                join_search_attr="uuid",
                                                join_search_val=client_uuid,
                                                join_attribute="role",
                                                order_by="rel_path",
                                                max_results=max_roles,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for role_uuid in roles_result:
                role_site = roles_result[role_uuid]['site']
                role_rel_path = roles_result[role_uuid]['rel_path']
                role_enabled = roles_result[role_uuid]['enabled'][0]
                role_status_string = ""
                if not role_enabled:
                    role_status_string = " (D)"
                role_string = f"{role_rel_path} ({role_site}) {role_status_string}"
                member_roles.append(role_string)

                processed_roles = len(member_roles)
                if processed_roles == max_roles:
                    if roles_count > max_roles:
                        msg = _("({processed_roles} of {roles_count} roles total)")
                        msg = msg.format(processed_roles=processed_roles, roles_count=roles_count)
                        x = msg
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
        processed_tokens = []
        if "tokens" in output_fields:
            if check_acl("view:tokens"):
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
                                                join_object_type="client",
                                                join_search_attr="uuid",
                                                join_search_val=client_uuid,
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
                msg = _("({tokens_len} of {tokens_count} tokens total)")
                msg = msg.format(tokens_len=len(processed_tokens), tokens_count=group_tokens_count)
                x = msg
                member_tokens.append(x)

            row.append("\n".join(member_tokens))
        else:
            if token_access:
                row.append("")
            else:
                row.append("-")
        # Scopes.
        get_scopes = False
        scope_access = False
        if "scopes" in output_fields:
            if check_acl("view:scopes"):
                scope_access = True
                get_scopes = True
        group_tokens_count = 0
        if get_scopes:
            member_scopes = []
            return_attrs = ['name', 'enabled', 'site']
            scopes_count, scopes_result = backend.search(object_type="scope",
                                                    attribute="client",
                                                    value=client_uuid,
                                                    order_by="name",
                                                    max_results=max_scopes,
                                                    return_query_count=True,
                                                    return_attributes=return_attrs)
            for scope_uuid in scopes_result:
                scope_name = scopes_result[scope_uuid]['name']
                scope_enabled = scopes_result[scope_uuid]['enabled'][0]
                scope_status_string = ""
                if not scope_enabled:
                    scope_status_string = " (D)"
                scope_string = f"{scope_name} {scope_status_string}"
                member_scopes.append(scope_string)

                processed_scopes = len(member_scopes)
                if processed_scopes == max_scopes:
                    if scopes_count > max_scopes:
                        msg = _("({processed_scopes} of {scopes_count} scopes total)")
                        msg = msg.format(processed_scopes=processed_scopes, scopes_count=scopes_count)
                        x = msg
                        member_scopes.append(x)
                    break
            row.append("\n".join(member_scopes))
        else:
            if scope_access:
                row.append("")
            else:
                row.append("-")
        # Dot1x auth.
        if "dot1x" in output_fields:
            if check_acl("view:dot1x_auth") \
            or check_acl("enable:dot1x_auth") \
            or check_acl("disable:dot1x_auth"):
                if dot1x_auth:
                    dot1x_string = _("Enabled")
                else:
                    dot1x_string = _("Disabled")
                row.append(dot1x_string)
            else:
                row.append("-")
        # OIDC auth.
        if "oidc" in output_fields:
            if check_acl("view:oidc_auth") \
            or check_acl("enable:oidc_auth") \
            or check_acl("disable:oidc_auth"):
                if oidc_auth:
                    oidc_string = _("Enabled")
                else:
                    oidc_string = _("Disabled")
                row.append(oidc_string)
            else:
                row.append("-")
        # Logins limited.
        if "logins" in output_fields:
            if check_acl("view:logins_limited") \
            or check_acl("limit_logins") \
            or check_acl("unlimit_logins"):
                if logins_limited:
                    row.append(_("Limited"))
                else:
                    row.append(_("Unlimited"))
            else:
                row.append("-")
        # Addresses.
        if "addresses" in output_fields:
            if check_acl("view:address") \
            or check_acl("add:address") \
            or check_acl("remove:address"):
                if addresses:
                    row.append("\n".join(addresses))
                else:
                    row.append("")
            else:
                row.append("-")
        # Auth cache status.
        if "auth_cache" in output_fields:
            if check_acl("view:auth_cache") \
            or check_acl("add:auth_cache") \
            or check_acl("remove:auth_cache"):
                if auth_cache_enabled:
                    row.append(_("Enabled"))
                else:
                    row.append(_("Disabled"))
            else:
                row.append("-")
        # Auth cache timeout.
        if "auth_cache_timeout" in output_fields:
            if check_acl("view:auth_cache_timeout") \
            or check_acl("add:auth_cache_timeout") \
            or check_acl("remove:auth_cache_timeout"):
                row.append(auth_cache_timeout)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="client",
                                                    object_uuid=client_uuid,
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
                'uuid'              : client_uuid,
                'name'              : client_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
