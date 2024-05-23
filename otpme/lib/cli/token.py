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
from otpme.lib import backend
from otpme.lib.cli import register_cli
from otpme.lib.cli import get_policies_string
from otpme.lib.cli import get_auth_script_string
from otpme.lib.classes.user import user_failcount
from otpme.lib.classes.user import user_is_blocked
from otpme.lib.classes.policy import get_acls
from otpme.lib.classes.policy import get_value_acls
from otpme.lib.classes.role import get_roles as _get_roles

from otpme.lib.exceptions import *

search_attribute="rel_path"

table_headers = [
            "token",
            "type",
            "status",
            "offline",
            "keep",
            "roles",
            "accessgroups",
            "groups",
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
                        'policy',
                        'enabled',
                        'token_type',
                        'owner_uuid',
                        'auth_script',
                        'description',
                        'keep_session',
                        'allow_offline',
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
    for sub_type in config.get_sub_object_types("token"):
        x_module_path = "otpme.lib.token.%s.%s" % (sub_type, sub_type)
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

    register_cli(name="token",
                id_attr="rel_path",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                search_attribute=search_attribute,
                search_regex_getter=search_regex_getter,
                max_len=10)

def search_regex_getter():
    """ Get default token search regex. """
    # If we got no search regex we only show tokens of the logged in user.
    try:
        login_user = backend.get_object(object_type="user",
                            uuid=config.auth_token.owner_uuid)
        search_regex = "%s/*" % login_user.name
    except:
        search_regex = None
    return search_regex

def row_getter(realm, site, token_order, token_data, acls, id_attr=None,
    output_fields=[], acl_checker=None, max_roles=5, max_policies=5, **kwargs):
    """ Build table rows for tokens. """
    _result = []
    for token_uuid in token_order:
        row = []
        _id_attr = token_data[token_uuid][id_attr]
        token_name = token_data[token_uuid]['name']
        enabled = token_data[token_uuid]['enabled'][0]
        token_type = token_data[token_uuid]['token_type'][0]
        owner_uuid = token_data[token_uuid]['owner_uuid'][0]
        try:
            policies = token_data[token_uuid]['policy']
        except:
            policies = None
        try:
            auth_script_uuid  = token_data[token_uuid]['auth_script'][0]
        except:
            auth_script_uuid = None
        try:
            auth_script_enabled = token_data[token_uuid]['auth_script_enabled'][0]
        except:
            auth_script_enabled = None
        try:
            description = token_data[token_uuid]['description'][0]
        except:
            description = None
        try:
            keep_session = token_data[token_uuid]['keep_session'][0]
        except:
            keep_session = None
        try:
            allow_offline = token_data[token_uuid]['allow_offline'][0]
        except:
            allow_offline = None
        try:
            acl_inheritance_enabled = token_data[token_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            token_acls = acls[token_uuid]
        except:
            token_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(token_acls)

        # Get token owner name.
        owner_name = None
        owner_result = backend.search(object_type="user",
                                    attribute="uuid",
                                    value=owner_uuid,
                                    return_type="name")
        if owner_result:
            owner_name = owner_result[0]

        # Tokenname.
        if "token" in output_fields:
            if not owner_name:
                _id_attr = "%s (orphan)" % _id_attr
            row.append(_id_attr)
        # Token type.
        if "type" in output_fields:
            row.append(token_type)

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
        # Offline status.
        if "offline" in output_fields:
            if check_acl("view:offline_status") \
            or check_acl("enable:offline") \
            or check_acl("disable:offline"):
                if allow_offline:
                    row.append("Enabled")
                else:
                    row.append("Disabled")
            else:
                row.append("-")
        # Session keep status.
        if "keep" in output_fields:
            if check_acl("view:session_keep") \
            or check_acl("enable:session_keep") \
            or check_acl("disable:session_keep"):
                if keep_session:
                    row.append("Enabled")
                else:
                    row.append("Disabled")
            else:
                row.append("-")

        get_roles = False
        show_roles = False
        if "roles" in output_fields:
            if check_acl("view:roles"):
                get_roles = True
                show_roles = True
        get_accessgroups = False
        show_accessgroups = False
        if "accessgroups" in output_fields:
            if check_acl("view:accessgroups"):
                get_roles = True
                get_accessgroups = True
                show_accessgroups = True

        roles_result = {}
        if get_roles:
            #return_attributes = ['name', 'site']
            #roles_result = backend.search(object_type="role",
            #                        attribute="token",
            #                        value=token_uuid,
            #                        return_attributes=return_attributes)
            token_roles = backend.search(object_type="role",
                                    attribute="token",
                                    value=token_uuid,
                                    return_type="uuid")
            return_attributes = ['name', 'site']
            all_token_roles = list(token_roles)
            for uuid in list(token_roles):
                role_roles = _get_roles(role_uuid=uuid,
                                        parent=True,
                                        recursive=True,
                                        return_type="uuid")
                for x in role_roles:
                    if x in token_roles:
                        continue
                    all_token_roles.append(x)
            if all_token_roles:
                roles_result = backend.search(object_type="role",
                                        attribute="uuid",
                                        values=all_token_roles,
                                        return_attributes=return_attributes)

        if get_accessgroups:
            return_attributes = ['name', 'site', 'enabled']
            accessgroups_result = backend.search(object_type="accessgroup",
                                                attribute="token",
                                                value=token_uuid,
                                                return_attributes=return_attributes)
            role_ags_result = {}
            if roles_result:
                role_ags_result = backend.search(object_type="accessgroup",
                                                attribute="role",
                                                values=list(roles_result),
                                                return_attributes=return_attributes)
        # Roles.
        if show_roles:
            roles_count = len(all_token_roles)
            processed_roles = 0
            token_roles_string = []
            for role_uuid in all_token_roles:
                role_name = roles_result[role_uuid]['name']
                role_site = roles_result[role_uuid]['site']
                if role_site != config.site:
                    role_path = "%s/%s" % (role_site, role_name)
                else:
                    role_path = role_name
                if role_uuid not in token_roles:
                    role_path = "(%s)" % role_path
                token_roles_string.append(role_path)
                processed_roles += 1
                if processed_roles == max_roles:
                    x = ("(%s of %s roles total)"
                        % (processed_roles, roles_count))
                    token_roles_string.append(x)
                    break
            row.append("\n".join(token_roles_string))
        else:
            row.append("-")

        # Accessgroups.
        if show_accessgroups:
            all_ags = list(accessgroups_result) + list(role_ags_result)
            group_strings = []
            for group_uuid in all_ags:
                if group_uuid in role_ags_result:
                    ag_data = role_ags_result
                else:
                    ag_data = accessgroups_result
                group_name = ag_data[group_uuid]['name']
                group_site = ag_data[group_uuid]['site']
                group_enabled = ag_data[group_uuid]['enabled']
                if not group_enabled:
                    group_status_string = "(D)"
                else:
                    if user_is_blocked(user_uuid=owner_uuid,
                                    access_group=group_name,
                                    realm=realm, site=site):
                        group_status_string = "(B)"
                    else:
                        group_failcount = user_failcount(owner_uuid, group_name)
                        if group_failcount > 0:
                            group_status_string = " (%s)" % group_failcount
                        else:
                            group_status_string = ""

                if group_site == config.site:
                    group_string = group_name
                else:
                    group_string = "%s/%s" % (group_site, group_name)

                if group_status_string:
                    group_string = "(%s %s)" % (group_string, group_status_string)

                if group_uuid in role_ags_result:
                    group_string = "(%s)" % group_string

                group_strings.append(group_string)

            row.append("\n".join(group_strings))
        else:
            row.append("-")

        # Groups.
        if "groups" in output_fields:
            if check_acl("view:groups"):
                return_attributes = ['name', 'site', 'enabled']
                groups_result = backend.search(object_type="group",
                                            attribute="token",
                                            value=token_uuid,
                                            return_attributes=return_attributes)
                role_groups_result = {}
                if roles_result:
                    role_groups_result = backend.search(object_type="group",
                                                attribute="role",
                                                values=list(roles_result),
                                                return_attributes=return_attributes)
                group_strings = []
                all_groups = list(groups_result) + list(role_groups_result)
                for group_uuid in all_groups:
                    if group_uuid in groups_result:
                        group_data = groups_result
                    else:
                        group_data = role_groups_result
                    group_name = group_data[group_uuid]['name']
                    group_site = group_data[group_uuid]['site']
                    group_enabled = group_data[group_uuid]['enabled']
                    if not group_enabled:
                        group_status_string = " (D)"
                    else:
                        group_status_string = ""

                    if group_uuid in role_groups_result:
                        if group_site != config.site:
                            group_string = "(%s/%s) %s" % (group_site,
                                                        group_name,
                                                        group_status_string)
                        else:
                            group_string = "(%s) %s" % (group_name,
                                                    group_status_string)
                    else:
                        group_string = "%s%s" % (group_name, group_status_string)
                    group_strings.append(group_string)
                row.append("\n".join(group_strings))
            else:
                row.append("-")
        # Authscript.
        if "authscript" in output_fields:
            if check_acl("view:auth_script") \
            or check_acl("enable:auth_script") \
            or check_acl("disable:auth_script"):
                if token_type == "otp_push" or "script_" in token_type:
                    row.append("N/A")
                else:
                    if auth_script_uuid:
                        auth_script_string = get_auth_script_string(auth_script_uuid)
                        if not auth_script_enabled:
                            auth_script_string = "%s (d)" % auth_script_string
                    else:
                        auth_script_string = ""
                    row.append(auth_script_string)
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = ""
                if policies:
                    policies_string = get_policies_string(object_type="token",
                                                        object_uuid=token_uuid,
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
        entry = {
                'uuid'  : token_uuid,
                'name'  : token_name,
                'row'   : row,
                }
        _result.append(entry)
    return _result
