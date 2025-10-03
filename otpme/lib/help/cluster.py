# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="cluster", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-cluster {command}"),

    'master_failover'    : {
                    '_cmd_usage_help' : _('Usage: otpme-cluster master_failover --random --to <new_master>'),
                    'cmd'   :   '--random :random_node=True: --to :new_master_node: --wait :wait=True:',
                    '_help' :   {
                                    'cmd'                   : _('Switch master node to this node.'),
                                    '--to <node>'           : _('Switch master to the given node.'),
                                    '--wait'                : _('Wait for master node to get ready (e.g. running jobs).'),
                                    '--random'              : _('Switch master to a random node.'),
                                },
                },

    'status'    : {
                    '_cmd_usage_help' : _('Usage: otpme-cluster status [--diff] [--full] [--full-index]'),
                    'cmd'   :   '--diff :diff_data=True: --full :full_data_diff=True: --full-index :full_index_diff=True:',
                    '_help' :   {
                                    'cmd'                   : _('Get cluster status.'),
                                    '--diff'                : _('Diff object checksums.'),
                                    '--full'                : _('Diff object checksums (read full data).'),
                                    '--full-index'          : _('Diff object checksums (read full index data).'),
                                },
                },

    'required_votes'    : {
                    '_cmd_usage_help' : _('Usage: otpme-cluster required_votes <quorum>'),
                    'cmd'   :   '[required_votes]',
                    '_help' :   {
                                    'cmd'                   : _('Set cluster required node votes to get quorum.'),
                                },
                },

    }
