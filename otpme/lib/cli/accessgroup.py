# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import backend
from otpme.lib.humanize import units
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.accessgroup import get_acls
from otpme.lib.classes.accessgroup import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "accessgr.",
                "status",
                "childs",
                "maxfail",
                "reset",
                "(sessions",
                "max",
                "relogin",
                "Childs",
                "master" ,
                "maxuse",
                "to_pass_on",
                "timeout",
                "utimeout)",
                "policies",
                #"inherit",
                "description",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'name',
                        'enabled',
                        'max_use',
                        'max_fail',
                        'description',
                        'max_sessions',
                        'max_fail_reset',
                        'session_master',
                        'relogin_timeout',
                        'timeout_pass_on',
                        'session_timeout',
                        'sessions_enabled',
                        'unused_session_timeout',
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
    register_cli(name="accessgroup",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, group_order, group_data, acls, table=None,
    max_roles=5, max_tokens=5, max_policies=5, output_fields=[],
    acl_checker=None, **kwargs):
    """ Build table rows for accessgroups. """
    # Align table headers.
    if table:
        table.align["maxfail"] = "c"
        table.align["reset"] = "c"
        table.align["max"] = "c"
        table.align["relogin"] = "c"
        table.align["maxuse"] = "c"
        table.align["timeout"] = "c"
        table.align["utimeout)"] = "c"
    # Workaround for "()" in header names.
    if "(sessions" in output_fields:
        output_fields.remove("(sessions")
        output_fields.append("sessions")
    if "utimeout)" in output_fields:
        output_fields.remove("utimeout)")
        output_fields.append("utimeout")
    row = []
    _result = []
    for ag_uuid in group_order:
        row = []
        ag_name = group_data[ag_uuid]['name']
        max_use = group_data[ag_uuid]['max_use'][0]
        max_fail = group_data[ag_uuid]['max_fail'][0]
        max_sessions = group_data[ag_uuid]['max_sessions'][0]
        max_fail_reset = group_data[ag_uuid]['max_fail_reset'][0]
        session_master = group_data[ag_uuid]['session_master'][0]
        session_timeout = group_data[ag_uuid]['session_timeout'][0]
        timeout_pass_on = group_data[ag_uuid]['timeout_pass_on'][0]
        sessions_enabled = group_data[ag_uuid]['sessions_enabled'][0]
        unused_session_timeout = group_data[ag_uuid]['unused_session_timeout'][0]
        try:
            relogin_timeout = group_data[ag_uuid]['relogin_timeout'][0]
        except:
            relogin_timeout = None
        try:
            enabled = group_data[ag_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            description = group_data[ag_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = group_data[ag_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            group_acls = acls[ag_uuid]
        except:
            group_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(group_acls)

        # Groupname.
        if "accessgr." in output_fields:
            row.append(ag_name)
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
        # Child accessgroups.
        if "childs" in output_fields:
            if check_acl("view:child_group") \
            or check_acl("add:child_group") \
            or check_acl("remove:child_group"):
                child_ags_result = backend.search(object_type="accessgroup",
                                        join_object_type="accessgroup",
                                        join_search_attr="uuid",
                                        join_search_val=ag_uuid,
                                        join_attribute="child_group",
                                        attribute="uuid",
                                        value="*",
                                        return_type="name")
                if child_ags_result:
                    row.append("\n".join(child_ags_result))
                else:
                    row.append("")
            else:
                row.append("-")
        # Max fail.
        if "maxfail" in output_fields:
            if check_acl("view:max_fail") \
            or check_acl("edit:max_fail"):
                row.append(max_fail)
            else:
                row.append("-")
        # Max fail reset time.
        if "reset" in output_fields:
            if check_acl("view:max_fail_reset") \
            or check_acl("edit:max_fail_reset"):
                if max_fail_reset == 0:
                    max_fail_reset = "never"
                else:
                    max_fail_reset = units.int2time(max_fail_reset,
                                                    time_unit="s")[0]
                row.append(max_fail_reset)
            else:
                row.append("-")
        # Sessions enabled.
        if "sessions" in output_fields:
            if check_acl("view:sessions_enabled") \
            or check_acl("enable:sessions") \
            or check_acl("disable:sessions"):
                if sessions_enabled:
                    row.append("Enabled")
                else:
                    row.append("Disabled")
            else:
                row.append("-")
        # Max sessions.
        if "max" in output_fields:
            if check_acl("view:max_sessions") \
            or check_acl("edit:max_sessions"):
                row.append(max_sessions)
            else:
                row.append("-")
        # Relogin timeout.
        if "relogin" in output_fields:
            if check_acl("view:relogin_timeout") \
            or check_acl("edit:relogin_timeout"):
                if relogin_timeout is None:
                    relogin_timeout = "N/A"
                else:
                    relogin_timeout = units.int2time(relogin_timeout,
                                                    time_unit="s")[0]
                row.append(relogin_timeout)
            else:
                row.append("-")
        # Child sessions.
        if "Childs" in output_fields:
            if check_acl("view:child_session") \
            or check_acl("add:child_session") \
            or check_acl("remove:child_session"):
                child_sessions_result = backend.search(object_type="accessgroup",
                                        join_object_type="accessgroup",
                                        join_search_attr="uuid",
                                        join_search_val=ag_uuid,
                                        join_attribute="child_session",
                                        attribute="uuid",
                                        value="*",
                                        return_type="name")
                if child_sessions_result:
                    row.append("\n".join(child_sessions_result))
                else:
                    row.append("")
            else:
                row.append("-")
        # Session master.
        if "master" in output_fields:
            if check_acl("view:session_master") \
            or check_acl("enable:session_master") \
            or check_acl("disable:session_master"):
                row.append(session_master)
            else:
                row.append("-")
        # Max use.
        if "maxuse" in output_fields:
            if check_acl("view:max_use") \
            or check_acl("edit:max_use"):
                row.append(max_use)
            else:
                row.append("-")
        # Timeout pass-on.
        if "to_pass_on" in output_fields:
            if check_acl("view:timeout_pass_on") \
            or check_acl("edit:timeout_pass_on"):
                if timeout_pass_on:
                    row.append("Enabled")
                else:
                    row.append("Disabled")
            else:
                row.append("-")
        # Session timeout.
        if "timeout" in output_fields:
            if check_acl("view:session_timeout") \
            or check_acl("edit:session_timeout"):
                if session_timeout is None:
                    session_timeout = "N/A"
                else:
                    session_timeout = units.int2time(session_timeout,
                                                    time_unit="s")[0]
                row.append(session_timeout)
            else:
                row.append("-")
        # Session unused timeout.
        if "utimeout" in output_fields:
            if check_acl("view:unused_session_timeout") \
            or check_acl("edit:unused_session_timeout"):
                if unused_session_timeout is None:
                    unused_session_timeout = "N/A"
                else:
                    unused_session_timeout = units.int2time(unused_session_timeout,
                                                            time_unit="s")[0]
                row.append(unused_session_timeout)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="accessgroup",
                                                    object_uuid=ag_uuid,
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
                'uuid'              : ag_uuid,
                'name'              : ag_name,
                'row'               : row,
                }
        _result.append(entry)
    # Workaround for "()" in header names.
    if "sessions" in output_fields:
        output_fields.remove("sessions")
        output_fields.append("(sessions")
    if "utimeout" in output_fields:
        output_fields.remove("utimeout")
        output_fields.append("utimeout)")
    return _result
