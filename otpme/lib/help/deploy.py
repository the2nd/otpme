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

from . import register_cmd_help

def register():
    register_cmd_help(command="deploy", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-deploy {command} [job]"),

    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-deploy add [--host <host1,host2>] [--unit <unit>] [--recursive] [--role <role1,role2>] [--group <group1,group2>] [--arg <name=value>] [--file <path>] [--key <path>] [--expiry <time>] [--on-demand] [--return-uuid] {job_type} {action}'),
                    'cmd'   :   '--host :hosts: --unit :units: --recursive :recursive=True: --role :roles: --group :groups: --arg :+job_args+: --file :file:job_file: --key :file:job_key: --expiry :job_ttl: --on-demand :on_demand=True: --return-uuid :return_uuid=True: <job_type> <action>',
                    '_help' :   {
                                    'cmd'                       : _('Add configuration management job.'),
                                    '--host <host1,host2>'      : _('Hosts (or nodes) the job is for.'),
                                    '--unit <unit>'             : _('Hosts of this unit.'),
                                    '--recursive'               : _('Hosts of the units below it as well.'),
                                    '--role <role1,role2>'      : _('Hosts of these roles. A role holds no nodes.'),
                                    '--group <group1,group2>'   : _('Hosts of these groups. A group holds no nodes.'),
                                    '--arg <name=value>'        : _('Argument of the job (e.g. packages=libreoffice). May be given more than once; a value with commas is a list.'),
                                    '--file <path>'             : _('File whose content the job carries (file_mgmt put_file).'),
                                    '--key <path>'              : _('File with the signing key of a repository (repo_mgmt add_repo).'),
                                    '--expiry <time>'           : _('How long the job may be run (e.g. 7d). Default 30d.'),
                                    '--on-demand'               : _('Tell the hosts to look now. Without it they ask on their next round.'),
                                    '--return-uuid'             : _('Print the UUID of the new job instead of a message. Useful in scripts.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-deploy list [--host <host>] [--failed] [--pending]'),
                    'cmd'   :   '--host :host: --failed :failed=True: --pending :pending=True:',
                    '_help' :   {
                                    'cmd'                       : _('List configuration management jobs.'),
                                    '--host <host>'             : _('Only jobs of this host.'),
                                    '--failed'                  : _('Only jobs that failed somewhere.'),
                                    '--pending'                 : _('Only jobs a host has not run yet.'),
                                },
                },

    'show'    : {
                    '_cmd_usage_help' : _('Usage: otpme-deploy show {conf_job}'),
                    'cmd'   :   '<conf_job>',
                    '_help' :   {
                                    'cmd'                       : _('Show job with its hosts: done, failed, waiting.'),
                                },
                },

    'results'    : {
                    '_cmd_usage_help' : _('Usage: otpme-deploy results [--host <host>] [conf_job]'),
                    'cmd'   :   '--host :host: [conf_job]',
                    '_help' :   {
                                    'cmd'                       : _('Show what the hosts made of a job.'),
                                    '--host <host>'             : _('Results of this host.'),
                                },
                },

    'ack'    : {
                    '_cmd_usage_help' : _('Usage: otpme-deploy ack {conf_job}'),
                    'cmd'   :   '<conf_job>',
                    '_help' :   {
                                    'cmd'                       : _('Acknowledge a job that failed, so it can be cleaned up.'),
                                },
                },

    'cancel'    : {
                    '_cmd_usage_help' : _('Usage: otpme-deploy cancel {conf_job}'),
                    'cmd'   :   '<conf_job>',
                    '_help' :   {
                                    'cmd'                       : _('Take back a job. Hosts that have not run it never will.'),
                                },
                },
    }
