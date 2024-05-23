# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.cli import register_cli
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.group import get_acls
from otpme.lib.classes.group import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "unitname",
                "status",
                "policies",
                "inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'policy',
                        'enabled',
                        'unit',
                        'auth_script',
                        'description',
                        'auth_script_enabled',
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
    register_cli(name="unit",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=None)

def row_getter(realm, site, unit_order, unit_data, acls,
    output_fields=[], acl_checker=None, max_policies=5, **kwargs):
    """ Build table rows for units. """
    _result = []
    for unit_uuid in unit_order:
        row = []
        unit_name = unit_data[unit_uuid]['name']
        try:
            enabled = unit_data[unit_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            unit_unit_uuid = unit_data[unit_uuid]['unit'][0]
        except:
            unit_unit_uuid = None
        try:
            policies = unit_data[unit_uuid]['policy']
        except:
            policies = None
        try:
            description = unit_data[unit_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = unit_data[unit_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            unit_acls = acls[unit_uuid]
        except:
            unit_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(unit_acls)

        # Set unit name based on tree level (leading whitespace count).
        if "unitname" in output_fields:
            #unit_x = " " * tree_level
            #if tree_level > 0:
            #    #unit_x += "└─"
            #    unit_x += "└"
            #unit_x += unit_name
            #row.append(unit_x)
            row.append(unit_name)
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
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = ""
                if policies:
                    policies_string = get_policies_string(object_type="unit",
                                                        object_uuid=unit_uuid,
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
                'name'              : unit_name,
                'uuid'              : unit_uuid,
                'unit_uuid'         : unit_unit_uuid,
                'row'               : row,
                }
        _result.append(entry)
    return _result
