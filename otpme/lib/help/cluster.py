# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="cluster", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : "Usage: otpme-cluster {command}",

    'master_failover'    : {
                    '_cmd_usage_help' : 'Usage: otpme-cluster master_failover --random --to <new_master>',
                    'cmd'   :   '--random :random_node=True: --to :new_master_node: --wait :wait=True:',
                    '_help' :   {
                                    'cmd'                   : 'Switch master node to this node.',
                                    '--to <node>'           : 'Switch master to the given node.',
                                    '--wait'                : 'Wait for master node to get ready (e.g. running jobs).',
                                    '--random'              : 'Switch master to a random node.',
                                },
                },

    'status'    : {
                    '_cmd_usage_help' : 'Usage: otpme-cluster status [--diff]',
                    'cmd'   :   '--diff :diff_data=True:',
                    '_help' :   {
                                    'cmd'                   : 'Get cluster status.',
                                },
                },
    }
