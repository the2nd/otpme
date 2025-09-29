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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="yubikey_gpg")

cmd_help = {
    '_need_command'             : True,
    'deploy' : {
                    '_cmd_usage_help' : _('Usage: otpme-token --type yubikey_gpg deploy -d -r -n --backup <backup_file> --restore <restore_file> [token]'),
                    'cmd'   :   '-n :no_token_write=True: -r :replace=True: --backup :gpg_backup_file: --restore :gpg_restore_file: -d :debug=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Initialize yubikey GPG applet.'),
                                    '-r'                    : _('Replace existing token.'),
                                    '-n'                    : _('Do NOT initialize yubikey GPG applet, just add token data to OTPme token.'),
                                    '--backup <file>'       : _('Write GPG backup to file (default /dev/shm/User_Name.gpg).'),
                                    '--restore <file>'      : _('Restore GPG configuration from backup file.'),
                                    '-d'                    : _('Enable token related debug output.'),
                                },
                    },
    }
