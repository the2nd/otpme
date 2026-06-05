# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
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
                "hosts",
                "groups",
                "limit_hosts",
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
                        'limit_by_hosts',
                        'description',
                        'acl_inheritance_enabled',
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
    register_cli(name="share",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, share_order, share_data, acls,
    limit=None, max_roles=5, max_tokens=5, max_nodes=5, max_hosts=5,
    max_pools=5, max_policies=5, max_groups=5, output_fields=None,
    acl_checker=None, **kwargs):
    """ Build table rows for shares. """
    if output_fields is None:
        output_fields = []
    _result = []
    if limit is None:
        if len(share_order) == 1:
            limit = 30
    if limit is not None:
        max_roles = limit
        max_tokens = limit
        max_nodes = limit
        max_hosts = limit
        max_pools = limit
        max_policies = limit
        max_groups = limit
    for share_uuid in share_order:
        row = []
        share_name = share_data[share_uuid]['name']
        unit_uuid = share_data[share_uuid]['unit'][0]
        try:
            root_dir = share_data[share_uuid]['root_dir'][0]
        except Exception:
            root_dir = None
        try:
            encrypted = share_data[share_uuid]['encrypted'][0]
        except Exception:
            encrypted = False
        try:
            block_size = share_data[share_uuid]['block_size'][0]
        except Exception:
            block_size = "N/A"
        try:
            read_only = share_data[share_uuid]['read_only'][0]
        except Exception:
            read_only = False
        try:
            force_group_uuid = share_data[share_uuid]['force_group_uuid'][0]
        except Exception:
            force_group_uuid = None
        try:
            create_mode = share_data[share_uuid]['create_mode'][0]
        except Exception:
            create_mode = None
        try:
            directory_mode = share_data[share_uuid]['directory_mode'][0]
        except Exception:
            directory_mode = None
        try:
            limit_by_hosts = share_data[share_uuid]['limit_by_hosts'][0]
        except Exception:
            limit_by_hosts = False
        try:
            enabled = share_data[share_uuid]['enabled'][0]
        except Exception:
            enabled = False
        try:
            description = share_data[share_uuid]['description'][0]
        except Exception:
            description = None
        try:
            acl_inheritance_enabled = share_data[share_uuid]['acl_inheritance_enabled'][0]
        except Exception:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            share_acls = acls[share_uuid]
        except Exception:
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
                    enabled_string = _("Enabled")
                else:
                    enabled_string = _("Disabled")
                row.append(enabled_string)
            else:
                row.append("-")
        # Root dir.
        if "root_dir" in output_fields:
            if check_acl("view:root_dir"):
                if root_dir:
                    root_dir_string = root_dir
                else:
                    root_dir_string = _("Not set")
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
                force_group_string = _("Not set")
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
            if check_acl("view:roles"):
                role_access = True
                get_roles = True
        share_tokens_count = 0
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
                    role_string = f"{role_name} {role_status_string}"
                else:
                    role_string = f"{role_name} ({role_site}) {role_status_string}"
                member_roles.append(role_string)

                processed_roles = len(member_roles)
                if processed_roles == max_roles:
                    if roles_count > max_roles:
                        msg = _("({processed_roles} of {roles_count} roles total)")
                        msg = msg.format(processed_roles=processed_roles, roles_count=roles_count)
                        x = msg
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
            if check_acl("view:tokens"):
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
                msg = _("({tokens_len} of {share_tokens_count} tokens total)")
                msg = msg.format(tokens_len=len(processed_tokens), share_tokens_count=share_tokens_count)
                x = msg
                member_tokens.append(x)

            row.append("\n".join(member_tokens))
        else:
            if token_access:
                row.append("")
            else:
                row.append("-")
        # Hosts.
        get_hosts = False
        host_access = False
        processed_hosts = []
        if "hosts" in output_fields:
            if check_acl("view:hosts"):
                host_access = True
                get_hosts = True
        if get_hosts:
            member_hosts = []
            return_attrs = ['name', 'enabled']
            share_hosts_count, \
            share_hosts_result = backend.search(object_type="host",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="share",
                                                join_search_attr="uuid",
                                                join_search_val=share_uuid,
                                                join_attribute="host",
                                                order_by="name",
                                                max_results=max_hosts,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for host_uuid in share_hosts_result:
                if len(processed_hosts) >= max_hosts:
                    break
                host_name = share_hosts_result[host_uuid]['name']
                host_enabled = share_hosts_result[host_uuid]['enabled'][0]
                host_string = host_name
                if not host_enabled:
                    host_string += " (D)"
                member_hosts.append(host_string)
                processed_hosts.append(host_uuid)

            if share_hosts_count > max_hosts:
                msg = _("({hosts_len} of {share_hosts_count} hosts total)")
                msg = msg.format(hosts_len=len(processed_hosts), share_hosts_count=share_hosts_count)
                x = msg
                member_hosts.append(x)

            row.append("\n".join(member_hosts))
        else:
            if host_access:
                row.append("")
            else:
                row.append("-")
        # Groups (shares hosts groups).
        if "groups" in output_fields:
            if check_acl("view:groups") \
            or check_acl("add:group") \
            or check_acl("remove:group"):
                return_attrs = ['name', 'enabled']
                groups_count, \
                groups_result = backend.search(object_type="group",
                                            join_object_type="share",
                                            join_search_attr="uuid",
                                            join_search_val=share_uuid,
                                            join_attribute="group",
                                            attribute="uuid",
                                            value="*",
                                            max_results=max_groups,
                                            return_query_count=True,
                                            return_attributes=return_attrs)
                share_groups = []
                for x in groups_result:
                    group_status_string = ""
                    x_group_name = groups_result[x]['name']
                    x_group_enabled = groups_result[x]['enabled'][0]
                    if not x_group_enabled:
                        group_status_string = " (D)"
                    group_string = f"{x_group_name}{group_status_string}"
                    share_groups.append(group_string)
                    processed_groups = len(share_groups)
                    if processed_groups == max_groups:
                        if groups_count > max_groups:
                            msg = _("({processed_groups} of {groups_count} groups total)")
                            msg = msg.format(processed_groups=processed_groups, groups_count=groups_count)
                            x = msg
                            share_groups.append(x)
                        break
                row.append("\n".join(share_groups))
            else:
                row.append("-")
        # Limit by hosts.
        if "limit_hosts" in output_fields:
            if check_acl("view:limit_hosts"):
                row.append(limit_by_hosts)
            else:
                row.append("-")
        # Nodes.
        get_nodes = False
        node_access = False
        processed_nodes = []
        if "nodes" in output_fields:
            if check_acl("view:nodes"):
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
                msg = _("({nodes_len} of {share_nodes_count} nodes total)")
                msg = msg.format(nodes_len=len(processed_nodes), share_nodes_count=share_nodes_count)
                x = msg
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
            if check_acl("view:pools"):
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
                msg = _("({pools_len} of {share_pools_count} pools total)")
                msg = msg.format(pools_len=len(processed_pools), share_pools_count=share_pools_count)
                x = msg
                member_pools.append(x)

            row.append("\n".join(member_pools))
        else:
            if pool_access:
                row.append("")
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policies") \
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
                    acl_inheritance_string = _("Enabled")
                else:
                    acl_inheritance_string = _("Disabled")
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
