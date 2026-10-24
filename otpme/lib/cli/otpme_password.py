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
from otpme.lib.classes.otpme_password import get_acls
from otpme.lib.classes.otpme_password import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "password",
                "unit",
                "nodes",
                "hosts",
                "devices",
                "clients",
                "policies",
                "inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'unit',
                        'description',
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
    # Remove duplicates.
    read_acls = set(read_acls)
    write_acls = set(write_acls)
    register_cli(name="pass",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, pass_order, pass_data, acls,
    limit=None, max_policies=5, max_nodes=5, max_hosts=5,
    max_devices=5, max_clients=5, output_fields=None,
    acl_checker=None, **kwargs):
    """ Build table rows for password objects. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(pass_order) == 1:
            limit = 30
    if limit is not None:
        max_policies = limit
        max_nodes = limit
        max_hosts = limit
        max_devices = limit
        max_clients = limit
    for pass_uuid in pass_order:
        row = []
        pass_name = pass_data[pass_uuid]['name']
        unit_uuid = pass_data[pass_uuid]['unit'][0]
        try:
            description = pass_data[pass_uuid]['description'][0]
        except Exception:
            description = None
        try:
            acl_inheritance_enabled = pass_data[pass_uuid]['acl_inheritance_enabled'][0]
        except Exception:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            pass_acls = acls[pass_uuid]
        except Exception:
            pass_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(pass_acls)

        # Password name.
        if "password" in output_fields:
            row.append(pass_name)
        # Unit.
        if "unit" in output_fields:
            unit_string = get_unit_string(unit_uuid)
            row.append(unit_string)
        # The objects the password belongs to. Read through the object
        # index, like the VLAN table does it.
        member_types = (
                        ('nodes', 'node', max_nodes),
                        ('hosts', 'host', max_hosts),
                        ('devices', 'device', max_devices),
                        ('clients', 'client', max_clients),
                        )
        for x_field, x_type, x_max in member_types:
            if x_field not in output_fields:
                continue
            if not check_acl(f"view:{x_field}") \
            and not check_acl(f"add:{x_type}") \
            and not check_acl(f"remove:{x_type}"):
                row.append("-")
                continue
            return_attrs = ['name', 'enabled', 'site']
            x_count, \
            x_result = backend.search(object_type=x_type,
                                    join_object_type="pass",
                                    join_search_attr="uuid",
                                    join_search_val=pass_uuid,
                                    join_attribute=x_type,
                                    attribute="uuid",
                                    value="*",
                                    max_results=x_max,
                                    return_query_count=True,
                                    return_attributes=return_attrs)
            x_members = []
            for x_uuid in x_result:
                x_name = x_result[x_uuid]['name']
                x_site = x_result[x_uuid]['site']
                x_enabled = x_result[x_uuid]['enabled'][0]
                x_status = ""
                if not x_enabled:
                    x_status = " (D)"
                if x_site != config.site:
                    x_name = f"{x_name} ({x_site})"
                x_members.append(f"{x_name}{x_status}")
                if len(x_members) == x_max:
                    if x_count > x_max:
                        msg = _("({processed} of {total} total)")
                        msg = msg.format(processed=len(x_members), total=x_count)
                        x_members.append(msg)
                    break
            row.append("\n".join(x_members))
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
            or check_acl("assign:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="pass",
                                                    object_uuid=pass_uuid,
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
                'uuid'              : pass_uuid,
                'name'              : pass_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
