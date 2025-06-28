# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.cli import get_auth_script_string
from otpme.lib.classes.user import get_acls
from otpme.lib.classes.user import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "username",
                "unit",
                "group",
                "status",
                "authscript",
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
    register_cli(name="user",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                sort_by="name",
                max_len=10)

def row_getter(realm, site, user_order, user_data, acls,
    acl_checker=None, output_fields=[], max_policies=5, **kwargs):
    """ Build table rows for users. """
    _result = []
    for user_uuid in user_order:
        row = []
        user_name = user_data[user_uuid]['name']
        try:
            unit_uuid = user_data[user_uuid]['unit'][0]
        except KeyError:
            unit_uuid = None
        try:
            enabled = user_data[user_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            auth_script_uuid = user_data[user_uuid]['auth_script'][0]
        except:
            auth_script_uuid = None
        try:
            auth_script_enabled = user_data[user_uuid]['auth_script_enabled'][0]
        except:
            auth_script_enabled = None
        try:
            description = user_data[user_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = user_data[user_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            user_acls = acls[user_uuid]
        except:
            user_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(user_acls)

        # Username.
        if "username" in output_fields:
            row.append(user_name)
        # Unit.
        if "unit" in output_fields:
            unit_string = "N/A"
            if unit_uuid is not None:
                unit_string = get_unit_string(unit_uuid)
            row.append(unit_string)
        # Group.
        if "group" in output_fields:
            if check_acl("view_public:group") \
            or check_acl("edit:group"):
                return_attrs = ['name', 'enabled']
                group_result = backend.search(object_type="group",
                                        attribute="user",
                                        value=user_uuid,
                                        return_attributes=return_attrs)
                group_string = "N/A"
                if group_result:
                    group_uuid = list(dict(group_result).keys())[0]
                    group_name = group_result[group_uuid]['name']
                    group_enabled = group_result[group_uuid]['enabled'][0]
                    group_status_string = ""
                    if not group_enabled:
                        group_status_string = " (D)"
                    group_string = "%s%s" % (group_name, group_status_string)
                row.append(group_string)
            else:
                row.append("-")
        # Status.
        if "status" in output_fields:
            if check_acl("view_public:status") \
            or check_acl("enable:object") \
            or check_acl("disable:object"):
                if enabled:
                    enabled_string = "Enabled"
                else:
                    enabled_string = "Disabled"
                row.append(enabled_string)
            else:
                row.append("-")
        # Authscript.
        if "authscript" in output_fields:
            if check_acl("view_all:auth_script") \
            or check_acl("enable:auth_script") \
            or check_acl("disable:auth_script") \
            or check_acl("edit"):
                if auth_script_uuid:
                    try:
                        auth_script_string = get_auth_script_string(auth_script_uuid)
                    except UnknownObject as e:
                        auth_script_string = "Script missing (%s)" % auth_script_uuid
                    if not auth_script_enabled:
                        auth_script_string = "%s (d)" % auth_script_string
                else:
                    auth_script_string = ""
                row.append(auth_script_string)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view_public:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="user",
                                                    object_uuid=user_uuid,
                                                    max_policies=max_policies)
                row.append(policies_string)
            else:
                row.append("-")
        # Inherit.
        if "inherit" in output_fields:
            if check_acl("view_public:acl_inheritance") \
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
            if check_acl("view_public:description") \
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
                'uuid'              : user_uuid,
                'name'              : user_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
