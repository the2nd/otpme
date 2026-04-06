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

#from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.device import get_acls
from otpme.lib.classes.device import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "device",
                "unit",
                "status",
                "mac",
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
                        'mac_address',
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
    # Remove duplicates.
    read_acls = set(read_acls)
    write_acls = set(write_acls)
    register_cli(name="device",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, device_order, device_data, acls, object_type=None,
    max_roles=5, max_tokens=5, max_sync_users=5, max_sync_groups=5,
    max_policies=5, output_fields=[], acl_checker=None, **kwargs):
    """ Build table rows for devices. """
    _result = []
    for device_uuid in device_order:
        row = []
        device_name = device_data[device_uuid]['name']
        try:
            enabled = device_data[device_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            unit_uuid = device_data[device_uuid]['unit'][0]
        except:
            unit_uuid = None
        try:
            mac_address = device_data[device_uuid]['mac_address'][0]
        except:
            mac_address = None
        try:
            description = device_data[device_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = device_data[device_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            device_acls = acls[device_uuid]
        except:
            device_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(device_acls)

        row = []
        # Hostname.
        if "device" in output_fields:
            row.append(device_name)
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
        # Logins limited.
        if "mac" in output_fields:
            if check_acl("view:mac_address"):
                row.append(mac_address)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type=object_type,
                                                    object_uuid=device_uuid,
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
                'uuid'              : device_uuid,
                'name'              : device_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
