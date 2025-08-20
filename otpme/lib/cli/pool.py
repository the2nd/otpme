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
from otpme.lib.classes.pool import get_acls
from otpme.lib.classes.pool import get_value_acls

from otpme.lib.exceptions import *

table_headers = [
                "poolname",
                "unit",
                "status",
                "nodes",
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
    register_cli(name="pool",
                table_headers=table_headers,
                return_attributes=return_attributes,
                row_getter=row_getter,
                write_acls=write_acls,
                read_acls=read_acls,
                max_len=30)

def row_getter(realm, site, pool_order, pool_data, acls, max_roles=5,
    max_tokens=5, max_nodes=5, max_policies=5, output_fields=[],
    acl_checker=None, **kwargs):
    """ Build table rows for pools. """
    _result = []
    for pool_uuid in pool_order:
        row = []
        pool_name = pool_data[pool_uuid]['name']
        unit_uuid = pool_data[pool_uuid]['unit'][0]
        try:
            enabled = pool_data[pool_uuid]['enabled'][0]
        except:
            enabled = False
        try:
            description = pool_data[pool_uuid]['description'][0]
        except:
            description = None
        try:
            acl_inheritance_enabled = pool_data[pool_uuid]['acl_inheritance_enabled'][0]
        except:
            acl_inheritance_enabled = False

        # Get object ACLs.
        try:
            pool_acls = acls[pool_uuid]
        except:
            pool_acls = {}

        # Get ACL checker.
        check_acl = acl_checker(pool_acls)

        # Groupname.
        if "poolname" in output_fields:
            row.append(pool_name)
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
            pool_member_nodes = []
            return_attrs = ['name', 'enabled']
            pool_nodes_count, \
            pool_nodes_result = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                join_object_type="pool",
                                                join_search_attr="uuid",
                                                join_search_val=pool_uuid,
                                                join_attribute="node",
                                                order_by="name",
                                                max_results=max_nodes,
                                                return_query_count=True,
                                                return_attributes=return_attrs)
            for node_uuid in pool_nodes_result:
                pool_member_nodes.append(node_uuid)
                if len(processed_nodes) >= max_nodes:
                    break
                node_name = pool_nodes_result[node_uuid]['name']
                try:
                    node_enabled = pool_nodes_result[node_uuid]['enabled'][0]
                except KeyError:
                    node_enabled = None
                node_string = node_name
                if node_enabled is None:
                    node_string += " (Enabled status unknown)"
                if node_enabled is False:
                    node_string += " (D)"
                member_nodes.append(node_string)
                processed_nodes.append(node_uuid)

            if pool_nodes_count > max_nodes:
                x = ("(%s of %s nodes total)"
                    % (len(processed_nodes), pool_nodes_count))
                member_nodes.append(x)

            row.append("\n".join(member_nodes))
        else:
            if node_access:
                row.append("")
            else:
                row.append("-")
        # Policies.
        if "policies" in output_fields:
            if check_acl("view:policy") \
            or check_acl("add:policy") \
            or check_acl("remove:policy"):
                policies_string = get_policies_string(object_type="pool",
                                                    object_uuid=pool_uuid,
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
                'uuid'              : pool_uuid,
                'name'              : pool_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
