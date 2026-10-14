# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.realm import get_acls
from otpme.lib.classes.realm import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "realm",
                "type",
                "auth",
                "sync",
                "policies",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'description',
                        'auth_enabled',
                        'sync_enabled',
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
    register_cli(name="realm",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, realm_order, realm_data, acls,
    limit=None, output_fields=None, acl_checker=None, max_policies=5,
    **kwargs):
    """ Build table rows for realms. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(realm_order) == 1:
            limit = 30
    if limit is not None:
        max_policies = limit
    for realm_uuid in realm_order:
        row = []
        realm_name = realm_data[realm_uuid]['name']
        try:
            sync_enabled = realm_data[realm_uuid]['sync_enabled'][0]
        except Exception:
            sync_enabled = False
        try:
            auth_enabled = realm_data[realm_uuid]['auth_enabled'][0]
        except Exception:
            auth_enabled = False
        try:
            description = realm_data[realm_uuid]['description'][0]
        except Exception:
            description = None

        # Get object ACLs.
        try:
            realm_acls = acls[realm_uuid]
        except Exception:
            realm_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(realm_acls)

        # Realmname.
        if "realm" in output_fields:
            row.append(realm_name)

        # Type.
        if "type" in output_fields:
            if realm_name == config.realm:
                realm_type = _("Local")
            else:
                realm_type = _("Remote")
            row.append(realm_type)

        # Auth enabled.
        if "auth" in output_fields:
            if check_acl("view:auth") \
            or check_acl("enable:auth") \
            or check_acl("disable:auth"):
                if auth_enabled:
                    row.append(_("Enabled"))
                else:
                    row.append(_("Disabled"))
            else:
                row.append("-")
        # Sync enabled.
        if "sync" in output_fields:
            if check_acl("view:sync") \
            or check_acl("enable:sync") \
            or check_acl("disable:sync"):
                if sync_enabled:
                    row.append(_("Enabled"))
                else:
                    row.append(_("Disabled"))
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
            or check_acl("assign:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="realm",
                                                    object_uuid=realm_uuid,
                                                    max_policies=max_policies)
                row.append(policies_string)
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
                'uuid'              : realm_uuid,
                'name'              : realm_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
