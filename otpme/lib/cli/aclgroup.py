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
from otpme.lib.classes.aclgroup import get_acls
from otpme.lib.classes.aclgroup import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "aclgroupname",
                "unit",
                "status",
                "entries",
                "aclgroups",
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
                        'entry',
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
    register_cli(name="aclgroup",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, aclgroup_order, aclgroup_data, acls,
    limit=None, max_policies=5, max_entries=10, max_aclgroups=5,
    output_fields=None, acl_checker=None, **kwargs):
    """ Build table rows for ACL groups. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(aclgroup_order) == 1:
            limit = 30
    if limit is not None:
        max_policies = limit
        max_entries = limit
        max_aclgroups = limit
    for aclgroup_uuid in aclgroup_order:
        row = []
        aclgroup_name = aclgroup_data[aclgroup_uuid]['name']
        unit_uuid = aclgroup_data[aclgroup_uuid]['unit'][0]
        try:
            enabled = aclgroup_data[aclgroup_uuid]['enabled'][0]
        except Exception:
            enabled = False
        try:
            entries = sorted(aclgroup_data[aclgroup_uuid]['entry'])
        except Exception:
            entries = []
        try:
            description = aclgroup_data[aclgroup_uuid]['description'][0]
        except Exception:
            description = None
        try:
            acl_inheritance_enabled = aclgroup_data[aclgroup_uuid]['acl_inheritance_enabled'][0]
        except Exception:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            aclgroup_acls = acls[aclgroup_uuid]
        except Exception:
            aclgroup_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(aclgroup_acls)

        # ACL group name.
        if "aclgroupname" in output_fields:
            row.append(aclgroup_name)
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
        # Entries.
        if "entries" in output_fields:
            if check_acl("view:entries") \
            or check_acl("add:entry") \
            or check_acl("remove:entry"):
                x_entries = entries[:max_entries]
                if len(entries) > max_entries:
                    msg = _("({processed} of {total} total)")
                    msg = msg.format(processed=max_entries, total=len(entries))
                    x_entries.append(msg)
                row.append("\n".join(x_entries))
            else:
                row.append("-")
        # Member groups. Read through the object index, the same join the
        # VLAN table uses for its members.
        if "aclgroups" in output_fields:
            if check_acl("view:aclgroups") \
            or check_acl("add:aclgroup") \
            or check_acl("remove:aclgroup"):
                return_attrs = ['name', 'enabled', 'site']
                x_count, \
                x_result = backend.search(object_type="aclgroup",
                                        join_object_type="aclgroup",
                                        join_search_attr="uuid",
                                        join_search_val=aclgroup_uuid,
                                        join_attribute="aclgroup",
                                        attribute="uuid",
                                        value="*",
                                        max_results=max_aclgroups,
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
                    if len(x_members) == max_aclgroups:
                        if x_count > max_aclgroups:
                            msg = _("({processed} of {total} total)")
                            msg = msg.format(processed=len(x_members), total=x_count)
                            x_members.append(msg)
                        break
                row.append("\n".join(x_members))
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
            or check_acl("assign:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="aclgroup",
                                                    object_uuid=aclgroup_uuid,
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
                'uuid'              : aclgroup_uuid,
                'name'              : aclgroup_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
