# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib.cli import register_cli

from otpme.lib.exceptions import *

table_headers = [
                "uuid",
                "name",
                "realm",
                "site",
                "status",
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.filetools"]

def register():
    return_attributes = [
                        'job_name',
                        'realm',
                        'site',
                        'job_status',
                        ]
    register_cli(name="job",
                table_headers=table_headers,
                search_attribute="job_name",
                return_attributes=return_attributes,
                row_getter=row_getter,
                max_len=30)

def row_getter(realm, site, job_order, job_data, acls, max_roles=5,
    max_tokens=5, max_nodes=5, max_policies=5, output_fields=[],
    acl_checker=None, **kwargs):
    """ Build table rows for jobs. """
    _result = []
    for job_uuid in job_order:
        row = []
        try:
            job_name = job_data[job_uuid]['job_name'][0]
        except:
            job_name = "Unknown"
        try:
            realm = job_data[job_uuid]['realm']
        except:
            realm = "Unknown"
        try:
            site = job_data[job_uuid]['site']
        except:
            site = "Unknown"
        try:
            job_status = job_data[job_uuid]['job_status'][0]
        except:
            job_status = "Unknown"

        # Job UUID.
        if "uuid" in output_fields:
            row.append(job_uuid)
        # Job name.
        if "name" in output_fields:
            row.append(job_name)
        # Job realm.
        if "realm" in output_fields:
            row.append(realm)
        # Job site.
        if "site" in output_fields:
            row.append(site)
        # Status.
        if "status" in output_fields:
            row.append(job_status)
        # Build row entry.
        entry = {
                'uuid'              : job_uuid,
                'name'              : job_name,
                'row'               : row,
                }
        _result.append(entry)
    return _result
