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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="yubikey_gpg")

cmd_help = {
    '_need_command'             : True,
    'deploy' : {
                    '_cmd_usage_help' : 'Usage: otpme-token --type yubikey_gpg deploy -d -r -n -b <backup_file> -r <restore_file> [token]',
                    'cmd'   :   '-n :no_token_write=True: -r :replace=True: -b :gpg_backup_file: -r :gpg_restore_file: -d :debug=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : 'Initialize yubikey GPG applet.',
                                    '-r'                    : 'Replace existing token.',
                                    '-n'                    : 'do NOT initialize yubikey GPG applet, just add token data to OTPme token',
                                    '-b <file>'             : 'write GPG backup to file (default /dev/shm/User_Name.gpg)',
                                    '-r <file>'             : 'restore GPG configuration from backup file',
                                    '-d'                    : 'enable token related debug output',
                                },
                    },
    }
