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

from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.vlan import get_acls
from otpme.lib.classes.vlan import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "vlanname",
                "unit",
                "status",
                "vlan_id",
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
                        'vlan_id',
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
    register_cli(name="vlan",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, vlan_order, vlan_data, acls,
    limit=None, max_policies=5, output_fields=None,
    acl_checker=None, **kwargs):
    """ Build table rows for VLANs. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(vlan_order) == 1:
            limit = 30
    if limit is not None:
        max_policies = limit
    for vlan_uuid in vlan_order:
        row = []
        vlan_name = vlan_data[vlan_uuid]['name']
        unit_uuid = vlan_data[vlan_uuid]['unit'][0]
        try:
            enabled = vlan_data[vlan_uuid]['enabled'][0]
        except Exception:
            enabled = False
        try:
            vlan_id = vlan_data[vlan_uuid]['vlan_id'][0]
        except Exception:
            vlan_id = None
        try:
            description = vlan_data[vlan_uuid]['description'][0]
        except Exception:
            description = None
        try:
            acl_inheritance_enabled = vlan_data[vlan_uuid]['acl_inheritance_enabled'][0]
        except Exception:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            vlan_acls = acls[vlan_uuid]
        except Exception:
            vlan_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(vlan_acls)

        # VLAN name.
        if "vlanname" in output_fields:
            row.append(vlan_name)
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
        # VLAN ID.
        if "vlan_id" in output_fields:
            if check_acl("view:vlan_id") \
            or check_acl("edit:vlan_id"):
                if vlan_id is None:
                    # Without an ID the VLAN name goes on the wire.
                    vlan_id_string = ""
                else:
                    vlan_id_string = vlan_id
                row.append(vlan_id_string)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="vlan",
                                                    object_uuid=vlan_uuid,
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
                'uuid'              : vlan_uuid,
                'name'              : vlan_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
