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
from otpme.lib.cli import get_unit_string
from otpme.lib.cli import get_policies_string
from otpme.lib.classes.share import get_acls
from otpme.lib.classes.share import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "sharename",
                "unit",
                "status",
                "root_dir",
                "encrypted",
                "block_size",
                "read_only",
                "force_group",
                "fmode",
                "dmode",
                "roles",
                "tokens",
                "nodes",
                "pools",
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
                        'read_only',
                        'root_dir',
                        'encrypted',
                        'block_size',
                        'force_group_uuid',
                        'create_mode',
                        'directory_mode',
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
    register_cli(name="share",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, share_order, share_data, acls, max_roles=5,
    max_tokens=5, max_nodes=5, max_pools=5, max_policies=5, output_fields=[],
    acl_checker=None, **kwargs):
    """ Build table rows for shares. """
    _result = []
    for share_uuid in share_order:
        row = []
        share_name = share_data[share_uuid]['name']
        unit_uuid = share_data[share_uuid]['unit'][0]
        try:
            root_dir = share_data[share_uuid]['root_dir'][0]
        except:
            root_dir = None
        try:
            encrypted = share_data[share_uuid]['encrypted'][0]
        except:
            encrypted = False
        try:
            block_size = share_data[share_uuid]['block_size'][0]
        except:
            block_size = "N/A"
        try:
            read_only = share_data[share_uuid]['read_only'][0]
        except:
            read_only = False
        try:
            force_group_uuid = share_data[share_uuid]['force_group_uuid'][0]
        except:
            force_group_uuid = None
        try:
            create_mode = share_data[share_uuid]['create_mode'][0]
        except:
            create_mode = None
        try:
            directory_mode = share_data[share_uuid]['directory_mode'][0]
        except:
            directory_mode = None
        try:
            enabled = share_data[share_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            description = share_data[share_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = share_data[share_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            share_acls = acls[share_uuid]
        except:
            share_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(share_acls)

        # Groupname.
        if "sharename" in output_fields:
            row.append(share_name)
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
        # Root dir.
        if "root_dir" in output_fields:
            if check_acl("view:root_dir"):
                if root_dir:
                    root_dir_string = root_dir
                else:
                    root_dir_string = "Not set"
                row.append(root_dir_string)
            else:
                row.append("-")
        # Encrypted.
        if "encrypted" in output_fields:
            if check_acl("view:encrypted"):
                row.append(encrypted)
            else:
                row.append("-")
        # Blocksize.
        if "block_size" in output_fields:
            if check_acl("view:block_size"):
                row.append(block_size)
            else:
                row.append("-")
        # Force group.
        if "read_only" in output_fields:
            if check_acl("view:read_only"):
                row.append(read_only)
            else:
                row.append("-")
        # Force group.
        if "force_group" in output_fields:
            if check_acl("view:force_group"):
                force_group_string = "Not set"
                if force_group_uuid:
                    result = backend.search(object_type="group",
                                            attribute="uuid",
                                            value=force_group_uuid,
                                            return_type="name")
                    if result:
                        force_group_string = result[0]
                row.append(force_group_string)
            else:
                row.append("-")
        # Create mode.
        if "fmode" in output_fields:
            if check_acl("view:create_mode"):
                row.append(create_mode)
            else:
                row.append("-")
        # Directory mode.
        if "dmode" in output_fields:
            if check_acl("view:directory_mode"):
                row.append(directory_mode)
            else:
                row.append("-")
        # Roles/Tokens.
        get_roles = False
        role_access = False
        if "roles" in output_fields:
            processed_tokens = []
            if check_acl("view:role"):
                role_access = True
                get_roles = True
        token_roles = {}
        role_tokens_count = 0
        share_tokens_count = 0
        role_tokens_result = []
        if get_roles:
            member_roles = []
            return_attrs = ['site', 'name', 'enabled']
            roles_count, roles_result = backend.search(object_type="role",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="share",
                                                join_search_attr="uuid",
                                                join_search_val=share_uuid,
                                                join_attribute="role",
                                                order_by="name",
                                                max_results=max_roles,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for role_uuid in roles_result:
                role_site = roles_result[role_uuid]['site']
                role_name = roles_result[role_uuid]['name']
                role_enabled = roles_result[role_uuid]['enabled'][0]
                role_status_string = ""
                if not role_enabled:
                    role_status_string = " (D)"
                if role_site == config.site:
                    role_string = ("%s %s" % (role_name,
                                            role_status_string))
                else:
                    role_string = ("%s (%s) %s" % (role_name,
                                                role_site,
                                                role_status_string))
                member_roles.append(role_string)

                return_attrs = ['name', 'name', 'enabled']
                role_tokens_count, \
                role_tokens_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="role",
                                                join_search_attr="uuid",
                                                join_search_val=role_uuid,
                                                join_attribute="token",
                                                order_by="name",
                                                max_results=max_tokens,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
                for token_uuid in role_tokens_result:
                    token_roles[token_uuid] = role_uuid
                processed_roles = len(member_roles)
                if processed_roles == max_roles:
                    if roles_count > max_roles:
                        x = ("(%s of %s roles total)"
                            % (processed_roles, roles_count))
                        member_roles.append(x)
                    break
            row.append("\n".join(member_roles))
        else:
            if role_access:
                row.append("")
            else:
                row.append("-")
        # Tokens.
        get_tokens = False
        token_access = False
        if "tokens" in output_fields:
            if check_acl("view:token"):
                token_access = True
                get_tokens = True
        if get_tokens:
            member_tokens = []
            return_attrs = ['rel_path', 'enabled']
            share_tokens_count, \
            share_tokens_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="share",
                                                join_search_attr="uuid",
                                                join_search_val=share_uuid,
                                                join_attribute="token",
                                                order_by="rel_path",
                                                max_results=max_tokens,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for token_uuid in share_tokens_result:
                if len(processed_tokens) >= max_tokens:
                    break
                token_rel_path = share_tokens_result[token_uuid]['rel_path']
                token_enabled = share_tokens_result[token_uuid]['enabled'][0]
                token_string = token_rel_path
                if not token_enabled:
                    token_string += " (D)"
                member_tokens.append(token_string)
                processed_tokens.append(token_uuid)

            if share_tokens_count > max_tokens:
                x = ("(%s of %s tokens total)"
                    % (len(processed_tokens), share_tokens_count))
                member_tokens.append(x)

            row.append("\n".join(member_tokens))
        else:
            if token_access:
                row.append("")
            else:
                row.append("-")
        # Nodes.
        get_nodes = False
        node_access = False
        processed_nodes = []
        if "nodes" in output_fields:
            if check_acl("view:node"):
                node_access = True
                get_nodes = True
        if get_nodes:
            member_nodes = []
            return_attrs = ['name', 'enabled']
            share_nodes_count, \
            share_nodes_result = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="share",
                                                join_search_attr="uuid",
                                                join_search_val=share_uuid,
                                                join_attribute="node",
                                                order_by="name",
                                                max_results=max_nodes,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for node_uuid in share_nodes_result:
                if len(processed_nodes) >= max_nodes:
                    break
                node_name = share_nodes_result[node_uuid]['name']
                node_enabled = share_nodes_result[node_uuid]['enabled'][0]
                node_string = node_name
                if not node_enabled:
                    node_string += " (D)"
                member_nodes.append(node_string)
                processed_nodes.append(node_uuid)

            if share_nodes_count > max_nodes:
                x = ("(%s of %s nodes total)"
                    % (len(processed_nodes), share_nodes_count))
                member_nodes.append(x)

            row.append("\n".join(member_nodes))
        else:
            if node_access:
                row.append("")
            else:
                row.append("-")
        # Pools.
        get_pools = False
        pool_access = False
        processed_pools = []
        if "pools" in output_fields:
            if check_acl("view:pool"):
                pool_access = True
                get_pools = True
        if get_pools:
            member_pools = []
            return_attrs = ['name', 'enabled']
            share_pools_count, \
            share_pools_result = backend.search(object_type="pool",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="share",
                                                join_search_attr="uuid",
                                                join_search_val=share_uuid,
                                                join_attribute="pool",
                                                order_by="name",
                                                max_results=max_pools,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for pool_uuid in share_pools_result:
                if len(processed_pools) >= max_pools:
                    break
                pool_name = share_pools_result[pool_uuid]['name']
                pool_enabled = share_pools_result[pool_uuid]['enabled'][0]
                pool_string = pool_name
                if not pool_enabled:
                    pool_string += " (D)"
                member_pools.append(pool_string)
                processed_pools.append(pool_uuid)

            if share_pools_count > max_pools:
                x = ("(%s of %s pools total)"
                    % (len(processed_pools), share_pools_count))
                member_pools.append(x)

            row.append("\n".join(member_pools))
        else:
            if pool_access:
                row.append("")
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="share",
                                                    object_uuid=share_uuid,
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
                'uuid'              : share_uuid,
                'name'              : share_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
