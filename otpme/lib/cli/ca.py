# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.ca import get_acls
from otpme.lib.classes.ca import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "ca",
                "unit",
                "status",
                "country",
                "state",
                "locality",
                "organization",
                "ou",
                "email",
                "policies",
                "inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'country',
                        'state',
                        'locality',
                        'organization',
                        'ou',
                        'email',
                        'enabled',
                        'uuid',
                        'unit',
                        'description',
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
    register_cli(name="ca",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, ca_order, ca_data, acls,
    output_fields=[], acl_checker=None, max_policies=5, **kwargs):
    """ Build table rows for CAs. """
    _result = []
    for ca_uuid in ca_order:
        row = []
        ca_name = ca_data[ca_uuid]['name']
        try:
            enabled = ca_data[ca_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            unit_uuid = ca_data[ca_uuid]['unit'][0]
        except:
            unit_uuid = None
        try:
            country = ca_data[ca_uuid]['country'][0]
        except:
            country = None
        try:
            state = ca_data[ca_uuid]['state'][0]
        except:
            state = None
        try:
            locality = ca_data[ca_uuid]['locality'][0]
        except:
            locality = None
        try:
            organization = ca_data[ca_uuid]['organization'][0]
        except:
            organization = None
        try:
            ou = ca_data[ca_uuid]['ou'][0]
        except:
            ou = None
        try:
            email = ca_data[ca_uuid]['email'][0]
        except:
            email = None
        try:
            description = ca_data[ca_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = ca_data[ca_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            ca_acls = acls[ca_uuid]
        except:
            ca_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(ca_acls)

        # CA name.
        if "ca" in output_fields:
            row.append(ca_name)
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
                    enabled_string = "Enabled"
                else:
                    enabled_string = "Disabled"
                row.append(enabled_string)
            else:
                row.append("-")
        # Country.
        if "country" in output_fields:
            if country:
                country = country
            else:
                country = ""
            row.append(country)
        # State.
        if "state" in output_fields:
            if state:
                state = state
            else:
                state = ""
            row.append(state)
        # Locality.
        if "locality" in output_fields:
            if locality:
                locality = locality
            else:
                locality = ""
            row.append(locality)
        # Organization.
        if "organization" in output_fields:
            if organization:
                organization = organization
            else:
                organization = ""
            row.append(organization)
        # OU.
        if "ou" in output_fields:
            if ou:
                ou = ou
            else:
                ou = ""
            row.append(ou)
        # E-Mail.
        if "email" in output_fields:
            if email:
                email = email
            else:
                email = ""
            row.append(email)
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="ca",
                                                    object_uuid=ca_uuid,
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
                'uuid'              : ca_uuid,
                'name'              : ca_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
