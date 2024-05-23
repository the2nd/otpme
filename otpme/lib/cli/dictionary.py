# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.humanize import units
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.client import get_acls
from otpme.lib.classes.client import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "dictionary",
                "unit",
                "type",
                "status",
                "size",
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
                        'dict_size',
                        'description',
                        'dictionary_type',
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
    register_cli(name="dictionary",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, dict_order, dict_data, acls,
    acl_checker=None, output_fields=[], max_policies=5, **kwargs):
    """ Build table rows for dictionaries. """
    _result = []
    for dict_uuid in dict_order:
        row = []
        dict_name = dict_data[dict_uuid]['name']
        unit_uuid = dict_data[dict_uuid]['unit'][0]
        dictionary_type = dict_data[dict_uuid]['dictionary_type'][0]
        try:
            enabled = dict_data[dict_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            dict_size = dict_data[dict_uuid]['dict_size'][0]
        except:
            dict_size = None
        try:
            description = dict_data[dict_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = dict_data[dict_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            dict_acls = acls[dict_uuid]
        except:
            dict_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(dict_acls)

        # Dict name.
        if "dictionary" in output_fields:
            row.append(dict_name)
        # Unit.
        if "unit" in output_fields:
            unit_string = get_unit_string(unit_uuid)
            row.append(unit_string)
        # Dictionary type.
        if "type" in output_fields:
            row.append(dictionary_type)
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
        # Size.
        if "size" in output_fields:
            if dict_size is None:
                dict_size = "N/A"
            else:
                dict_size = units.int2size(dict_size)
            row.append(dict_size)
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="dictionary",
                                                    object_uuid=dict_uuid,
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
                'uuid'              : dict_uuid,
                'name'              : dict_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
