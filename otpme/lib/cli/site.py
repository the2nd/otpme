# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.group import get_acls
from otpme.lib.classes.group import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "site",
                "status",
                "auth",
                "sync",
                "trusts",
                "address",
                "auth_fqdn",
                "mgmt_fqdn",
                "policies",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'auth_fqdn',
                        'mgmt_fqdn',
                        'address',
                        'enabled',
                        'description',
                        'trusted_site',
                        'auth_enabled',
                        'sync_enabled',
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
    register_cli(name="site",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, site_order, site_data, acls,
    output_fields=[], acl_checker=None, max_policies=5, **kwargs):
    """ Build table rows for sites. """
    _result = []
    for site_uuid in site_order:
        row = []
        site_name = site_data[site_uuid]['name']
        try:
            site_auth_fqdn = site_data[site_uuid]['auth_fqdn'][0]
        except KeyError:
            site_auth_fqdn = "Unknown"
        try:
            site_mgmt_fqdn = site_data[site_uuid]['mgmt_fqdn'][0]
        except KeyError:
            site_mgmt_fqdn = "Unknown"
        site_address = site_data[site_uuid]['address'][0]
        try:
            enabled = site_data[site_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            trusted_sites = site_data[site_uuid]['trusted_site']
        except:
            trusted_sites = []
        try:
            sync_enabled = site_data[site_uuid]['sync_enabled'][0]
        except:
            sync_enabled = False
        try:
            auth_enabled = site_data[site_uuid]['auth_enabled'][0]
        except:
            auth_enabled = False
        try:
            description = site_data[site_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = site_data[site_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            site_acls = acls[site_uuid]
        except:
            site_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(site_acls)

        # Realmname.
        if "site" in output_fields:
            row.append(site_name)
        # Status.
        if "status" in output_fields:
            if site_uuid == config.realm_master_uuid:
                site_type = "Master"
            else:
                site_type = "Slave"
            if not enabled:
                site_type = "%s (D)" % site_type
            row.append(site_type)
        # Auth enabled.
        if "auth" in output_fields:
            if check_acl("view:auth") \
            or check_acl("disable:auth") \
            or check_acl("disable:auth"):
                if auth_enabled:
                    row.append("Enabled")
                else:
                    row.append("Disabled")
            else:
                row.append("-")
        # Sync enabled.
        if "sync" in output_fields:
            if check_acl("view:sync") \
            or check_acl("disable:sync") \
            or check_acl("disable:sync"):
                if sync_enabled:
                    row.append("Enabled")
                else:
                    row.append("Disabled")
            else:
                row.append("-")
        # Trusts.
        if "trusts" in output_fields:
            _trusted_sites = []
            if check_acl("view:trust") \
            or check_acl("add:trust") \
            or check_acl("delete:trust"):
                for x in trusted_sites:
                    x_oid = backend.get_oid(x, instance=True)
                    _trusted_sites.append(x_oid.name)
            row.append(",".join(_trusted_sites))
        # Addresses.
        if "address" in output_fields:
            if check_acl("view:address") \
            or check_acl("edit:address"):
                row.append(site_address)
            else:
                row.append("-")
        if "auth_fqdn" in output_fields:
            if check_acl("view:auth_fqdn") \
            or check_acl("edit:auth_fqdn"):
                row.append(site_auth_fqdn)
            else:
                row.append("-")
        if "mgmt_fqdn" in output_fields:
            if check_acl("view:mgmt_fqdn") \
            or check_acl("edit:mgmt_fqdn"):
                row.append(site_mgmt_fqdn)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="site",
                                                    object_uuid=site_uuid,
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
                'uuid'              : site_uuid,
                'name'              : site_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
