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
from otpme.lib.classes import signing
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.group import get_acls
from otpme.lib.classes.group import get_value_acls

from otpme.lib.exceptions import *

default_callback = config.get_callback()

search_attribute="rel_path"
table_headers = [
                "script",
                #"unit",
                "status",
                "signatures",
                "policies",
                "inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'rel_path',
                        'enabled',
                        'unit',
                        'description',
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
    register_cli(name="script",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                search_attribute=search_attribute,
                max_len=30)

def row_getter(realm, site, script_order, script_data, acls,
    acl_checker=None, output_fields=[], max_policies=5,
    callback=default_callback, **kwargs):
    """ Build table rows for scripts. """
    _result = []
    for script_uuid in script_order:
        row = []
        script_name = script_data[script_uuid]['name']
        script_rel_path = script_data[script_uuid]['rel_path']
        unit_uuid = script_data[script_uuid]['unit'][0]
        try:
            enabled = script_data[script_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            description = script_data[script_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = script_data[script_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            script_acls = acls[script_uuid]
        except:
            script_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(script_acls)

        # Dict name.
        if "script" in output_fields:
            row.append(script_rel_path)
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
        # Signatures.
        if "signatures" in output_fields:
            if check_acl("view:signature") \
            or check_acl("add:signature") \
            or check_acl("delete:signature"):
                callback.disable()
                script_signatures = []
                script = backend.get_object(uuid=script_uuid)
                for user_uuid in script.signatures:
                    for sign_id in script.signatures[user_uuid]:
                        sign_tags = script.signatures[user_uuid][sign_id]['tags']
                        try:
                            sign_valid = script.verify_sign(user_uuid=user_uuid,
                                                            tags=sign_tags,
                                                            callback=callback)
                        except:
                            sign_valid = False
                        if sign_valid:
                            signature_status_string = "OK"
                        else:
                            signature_status_string = "FAIL"
                        user_oid = backend.get_oid(user_uuid,
                                                object_type="user",
                                                instance=True)
                        if user_oid:
                            user_name = user_oid.name
                        else:
                            user_name = "%s (orphan)" % user_uuid
                        # Make sure we add newline for tag lists longer than 30
                        # chars.
                        resolved_tags = signing.resolve_tags(sign_tags)
                        if len(",".join(resolved_tags)) > 30:
                            join_str = ",\n%s" % (" " * (len(user_name) + 2))
                        else:
                            join_str = ","
                        signature_string = "%s (%s) %s" % (user_name,
                                            join_str.join(resolved_tags),
                                            signature_status_string)
                        script_signatures.append(signature_string)
                row.append("\n".join(script_signatures))
                callback.enable()
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="script",
                                                    object_uuid=script_uuid,
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
                'uuid'              : script_uuid,
                'name'              : script_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
