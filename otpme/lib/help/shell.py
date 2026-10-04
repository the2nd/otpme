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
    register_cmd_help(command="shell", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : False,
    '_include_global_opts'      : True,
    '_usage_help'   : _('Usage: otpme-shell [--user <user>] [--command <command>] [--expiry <time>] [--throwaway-key] {host}'),
    # The host by name and not as "|object|": a command with no
    # subcommand has no object type the completion could work out from
    # its name, and "host_name" says it.
    'cmd'   :   '--user :user: --command :command: --expiry :job_ttl: --throwaway-key :throwaway_key=True: <host_name>',
    '_help' :   {
                    'cmd'                   : _('Get a shell on a host.'),
                    '--user <user>'         : _('Run the shell as this user. Default root.'),
                    '--command <command>'   : _('Run this instead of a shell.'),
                    '--expiry <time>'       : _('How long the request stays good (e.g. 5m).'),
                    '--throwaway-key'       : _('Use a new key for this session instead of the SSH agent. The host allows this only for a signer added with --allow-throwaway-key.'),
                },
    }
