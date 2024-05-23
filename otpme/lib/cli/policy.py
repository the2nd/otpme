# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.policy import get_acls
from otpme.lib.classes.policy import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "policy",
                "unit",
                "type",
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
                        'enabled',
                        'unit',
                        'description',
                        'policy_type',
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
    for sub_type in config.get_sub_object_types("policy"):
        x_module_path = "otpme.lib.policy.%s.%s" % (sub_type, sub_type)
        x_module = importlib.import_module(x_module_path)
        x_get_acls = getattr(x_module, "get_acls")
        x_get_value_acls = getattr(x_module, "get_value_acls")
        x_read_acls, x_write_acls = x_get_acls(split=True)
        read_acls += x_read_acls
        write_acls += x_write_acls
        x_read_value_acls, x_write_value_acls = x_get_value_acls(split=True)
        for acl in x_read_value_acls:
            for x in x_read_value_acls[acl]:
                x_acl = "%s:%s" % (acl, x)
                read_acls.append(x_acl)
        for acl in x_write_value_acls:
            for x in x_write_value_acls[acl]:
                x_acl = "%s:%s" % (acl, x)
                write_acls.append(x_acl)

    register_cli(name="policy",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, policy_order, policy_data, acls,
    output_fields=[], acl_checker=None, max_policies=5, **kwargs):
    """ Build table rows for policies. """
    _result = []
    for policy_uuid in policy_order:
        row = []
        policy_name = policy_data[policy_uuid]['name']
        unit_uuid = policy_data[policy_uuid]['unit'][0]
        try:
            enabled = policy_data[policy_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            policy_type = policy_data[policy_uuid]['policy_type'][0]
        except:
            policy_type = False
        try:
            description = policy_data[policy_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = policy_data[policy_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            policy_acls = acls[policy_uuid]
        except:
            policy_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(policy_acls)

        # Policyname.
        if "policy" in output_fields:
            row.append(policy_name)
        # Unit.
        if "unit" in output_fields:
            unit_string = get_unit_string(unit_uuid)
            row.append(unit_string)
        # Policy type.
        if "type" in output_fields:
            row.append(policy_type)
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
                policies_string = get_policies_string(object_type="policy",
                                                    object_uuid=policy_uuid,
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
                'uuid'              : policy_uuid,
                'name'              : policy_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
