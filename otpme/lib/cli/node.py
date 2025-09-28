# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.node import get_acls
from otpme.lib.classes.node import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "host",
                "unit",
                "status",
                "roles",
                "tokens",
                "logins",
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
                        'accessgroup',
                        'logins_limited',
                        'acl_inheritance_enabled',
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
    register_cli(name="node",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, host_order, host_data, acls, object_type=None,
    max_roles=5, max_tokens=5, max_policies=5, output_fields=[],
    acl_checker=None, **kwargs):
    """ Build table rows for hosts/nodes. """
    _result = []
    for host_uuid in host_order:
        row = []
        host_name = host_data[host_uuid]['name']
        try:
            enabled = host_data[host_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            unit_uuid = host_data[host_uuid]['unit'][0]
        except:
            unit_uuid = None
        try:
            logins_limited = host_data[host_uuid]['logins_limited'][0]
        except:
            logins_limited = False
        try:
            description = host_data[host_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = host_data[host_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            host_acls = acls[host_uuid]
        except:
            host_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(host_acls)

        row = []
        # Hostname.
        if "host" in output_fields:
            row.append(host_name)
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
        role_tokens_result = []
        if get_roles:
            member_roles = []
            return_attrs = ['rel_path', 'enabled', 'site']
            roles_count, roles_result = backend.search(object_type="role",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type=object_type,
                                                join_search_attr="uuid",
                                                join_search_val=host_uuid,
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

                return_attrs = ['name', 'rel_path', 'enabled']
                role_tokens_count, \
                role_tokens_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="role",
                                                join_search_attr="uuid",
                                                join_search_val=role_uuid,
                                                join_attribute="token",
                                                order_by="rel_path",
                                                max_results=max_tokens,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
                for token_uuid in role_tokens_result:
                    token_roles[token_uuid] = role_uuid
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
        if "tokens" in output_fields:
            if check_acl("view:token"):
                token_access = True
                get_tokens = True
        if get_tokens:
            host_tokens = []
            return_attrs = ['rel_path', 'enabled']
            host_tokens_count, \
            host_tokens_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type=object_type,
                                                join_search_attr="uuid",
                                                join_search_val=host_uuid,
                                                join_attribute="token",
                                                order_by="rel_path",
                                                max_results=max_tokens,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for token_uuid in host_tokens_result:
                if len(processed_tokens) >= max_tokens:
                    break
                token_rel_path = host_tokens_result[token_uuid]['rel_path']
                token_enabled = host_tokens_result[token_uuid]['enabled'][0]
                token_string = token_rel_path
                if not token_enabled:
                    token_string += " (D)"
                host_tokens.append(token_string)
                processed_tokens.append(token_uuid)

            if host_tokens_count > max_tokens:
                msg = _("({tokens_len} of {tokens_count} tokens total)")
                msg = msg.format(tokens_len=len(processed_tokens), tokens_count=tokens_count)
                x = msg
                host_tokens.append(x)

            row.append("\n".join(host_tokens))
        else:
            if token_access:
                row.append("")
            else:
                row.append("-")
        # Logins limited.
        if "logins" in output_fields:
            if check_acl("view:logins_limited") \
            or check_acl("limit_logins") \
            or check_acl("unlimit_logins"):
                if logins_limited:
                    row.append("Limited")
                else:
                    row.append("Unlimited")
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type=object_type,
                                                    object_uuid=host_uuid,
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
                'uuid'              : host_uuid,
                'name'              : host_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
