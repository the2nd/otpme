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
from otpme.lib.classes.device import get_acls
from otpme.lib.classes.device import get_value_acls
from otpme.lib.classes.role import get_roles as _get_roles

from otpme.lib.exceptions import *

table_headers = [
                "device",
                "unit",
                "status",
                "mac",
                "roles",
                "accessgroups",
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
    limit=None, max_roles=5, max_policies=5, output_fields=None,
    acl_checker=None, **kwargs):
    """ Build table rows for devices. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(device_order) == 1:
            limit = 30
    if limit is not None:
        max_roles = limit
        max_policies = limit
    for device_uuid in device_order:
        row = []
        device_name = device_data[device_uuid]['name']
        try:
            enabled = device_data[device_uuid]['enabled'][0]
        except Exception:
            enabled = False
        try:
            unit_uuid = device_data[device_uuid]['unit'][0]
        except Exception:
            unit_uuid = None
        try:
            mac_address = device_data[device_uuid]['mac_address'][0]
        except Exception:
            mac_address = None
        try:
            description = device_data[device_uuid]['description'][0]
        except Exception:
            description = None
        try:
            acl_inheritance_enabled = device_data[device_uuid]['acl_inheritance_enabled'][0]
        except Exception:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            device_acls = acls[device_uuid]
        except Exception:
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
        # The accessgroups a device gets access by depend on its roles,
        # so both columns share the role lookup.
        get_roles = False
        show_roles = False
        if "roles" in output_fields:
            if check_acl("view:roles"):
                get_roles = True
                show_roles = True
        show_ags = False
        if "accessgroups" in output_fields:
            if check_acl("view:accessgroups"):
                get_roles = True
                show_ags = True
        device_roles = []
        all_device_roles = []
        if get_roles:
            device_roles = backend.search(object_type="role",
                                        attribute="device",
                                        value=device_uuid,
                                        return_type="uuid")
            all_device_roles = list(device_roles)
            for uuid in device_roles:
                parent_roles = _get_roles(role_uuid=uuid,
                                        parent=True,
                                        recursive=True,
                                        return_type="uuid")
                for x in parent_roles:
                    if x in all_device_roles:
                        continue
                    all_device_roles.append(x)
        # Roles.
        if "roles" in output_fields:
            if show_roles:
                member_roles = []
                roles_result = {}
                if device_roles:
                    return_attrs = ['rel_path', 'site', 'enabled']
                    roles_result = backend.search(object_type="role",
                                                attribute="uuid",
                                                values=device_roles,
                                                order_by="rel_path",
                                                return_attributes=return_attrs)
                roles_count = len(roles_result)
                for role_uuid in roles_result:
                    role_site = roles_result[role_uuid]['site']
                    role_rel_path = roles_result[role_uuid]['rel_path']
                    try:
                        role_enabled = roles_result[role_uuid]['enabled'][0]
                    except Exception:
                        role_enabled = False
                    role_status_string = ""
                    if not role_enabled:
                        role_status_string = " (D)"
                    role_string = f"{role_rel_path} ({role_site}) {role_status_string}"
                    member_roles.append(role_string)
                    if len(member_roles) == max_roles:
                        if roles_count > max_roles:
                            msg = _("({processed_roles} of {roles_count} roles total)")
                            msg = msg.format(processed_roles=len(member_roles),
                                            roles_count=roles_count)
                            member_roles.append(msg)
                        break
                row.append("\n".join(member_roles))
            else:
                row.append("-")
        # Accessgroups.
        if "accessgroups" in output_fields:
            if show_ags:
                # A device is granted access by the accessgroups it is a
                # member of and by the ones its roles are in (see
                # AccessGroup.is_assigned_device()). The latter are shown
                # in brackets.
                return_attrs = ['name', 'site', 'enabled']
                device_ags = backend.search(object_type="accessgroup",
                                        attribute="device",
                                        value=device_uuid,
                                        return_attributes=return_attrs)
                role_ags = {}
                if all_device_roles:
                    role_ags = backend.search(object_type="accessgroup",
                                            attribute="role",
                                            values=all_device_roles,
                                            return_attributes=return_attrs)
                ag_strings = []
                all_ags = list(device_ags)
                for ag_uuid in role_ags:
                    if ag_uuid in device_ags:
                        continue
                    all_ags.append(ag_uuid)
                for ag_uuid in all_ags:
                    if ag_uuid in device_ags:
                        ag_data = device_ags
                    else:
                        ag_data = role_ags
                    ag_name = ag_data[ag_uuid]['name']
                    ag_site = ag_data[ag_uuid]['site']
                    try:
                        ag_enabled = ag_data[ag_uuid]['enabled'][0]
                    except Exception:
                        ag_enabled = False
                    if ag_site == config.site:
                        ag_string = ag_name
                    else:
                        ag_string = f"{ag_site}/{ag_name}"
                    if not ag_enabled:
                        ag_string = f"{ag_string} (D)"
                    if ag_uuid not in device_ags:
                        ag_string = f"({ag_string})"
                    ag_strings.append(ag_string)
                row.append("\n".join(ag_strings))
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
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
