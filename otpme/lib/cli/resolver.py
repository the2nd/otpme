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
from otpme.lib.classes.resolver import get_acls
from otpme.lib.classes.resolver import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "resolver",
                "unit",
                "type",
                "status",
                "sync_deletions",
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
                        'resolver_type',
                        'sync_deletions',
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
    for sub_type in config.get_sub_object_types("resolver"):
        x_module_path = "otpme.lib.resolver.%s.%s" % (sub_type, sub_type)
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
    register_cli(name="resolver",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, resolver_order, resolver_data, acls,
    acl_checker=None, output_fields=[], max_policies=5, **kwargs):
    """ Build table rows for resolvers. """
    _result = []
    for resolver_uuid in resolver_order:
        row = []
        resolver_name = resolver_data[resolver_uuid]['name']
        unit_uuid = resolver_data[resolver_uuid]['unit'][0]
        resolver_type = resolver_data[resolver_uuid]['resolver_type'][0]
        try:
            enabled = resolver_data[resolver_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            sync_deletions = resolver_data[resolver_uuid]['sync_deletions'][0]
        except:
            sync_deletions = None
        try:
            description = resolver_data[resolver_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = resolver_data[resolver_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            resolver_acls = acls[resolver_uuid]
        except:
            resolver_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(resolver_acls)

        # Dict name.
        if "resolver" in output_fields:
            row.append(resolver_name)
        # Unit.
        if "unit" in output_fields:
            unit_string = get_unit_string(unit_uuid)
            row.append(unit_string)
        # Dictionary type.
        if "type" in output_fields:
            row.append(resolver_type)
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
        # Sync deletions status.
        if "sync_deletions" in output_fields:
            if sync_deletions:
                row.append("Enabled")
            else:
                row.append("Disabled")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="resolver",
                                                    object_uuid=resolver_uuid,
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
                'uuid'              : resolver_uuid,
                'name'              : resolver_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
