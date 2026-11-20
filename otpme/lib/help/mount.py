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
    register_cmd_help(command="mount", help_dict=cmd_help)

# 'cmd' is what CommandHandler.handle_mount() parses the command line
# with (cli.get_opts()), so the options and their help are one list.
cmd_help = {
    '_need_command'             : False,
    '_include_global_opts'      : True,
    '_usage_help'   : _('Usage: otpme-mount [options] [share [mountpoint]]'),
    'cmd'   :   '-a :mount_all=True: -u :umount=True: --list :list_shares=True: --nodes :[nodes]: --hard :hard=True: --encrypted :encrypted=True: --master-password-mount :master_password_mount=True: --add-share-key :add_share_key=True: --foreground :foreground=True: ["share"] ["mount_point"]',
    '_help' :   {
                    'cmd'                       : _('Mount a share. Without arguments, show the OTPme shares mounted here.'),
                    '-a'                        : _('Mount all shares you may mount, each at the usual place.'),
                    '-u'                        : _('Unmount the share. With -a, unmount all of them.'),
                    '--list'                    : _('List the shares you may mount.'),
                    '--nodes <node1,node2>'     : _('Use these nodes instead of the ones the share names.'),
                    '--hard'                    : _('Let a write wait while no node can be reached, instead of failing.'),
                    '--encrypted'               : _('Say that the share is encrypted (only needed with a mountpoint and --nodes).'),
                    '--master-password-mount'   : _('Make the key of an encrypted share from its master password.'),
                    '--add-share-key'           : _('Store the key made from the master password for your own token.'),
                    '--foreground'              : _('Keep the mount in this process instead of leaving it behind in one of its own.'),
                },
    }
