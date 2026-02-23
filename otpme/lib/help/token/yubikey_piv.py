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
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="yubikey_piv")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token add [-r] {token}'),
                    'cmd'   :   '-r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Add new token.'),
                                    '-r'                    : _('Replace existing token and keep its UUID.'),
                                },
                },

    'deploy' : {
                    '_cmd_usage_help' : _('Usage: otpme-token --type yubikey_piv deploy -d -r -n --key-len <key_len> --backup <backup_file> --restore <restore_file> --add-user-key [token]'),
                    'cmd'   :   '-n :no_token_write=True: --key-len :key_len: -r :replace=True: --backup :backup_file: --restore :restore_file: -d :debug=True: --add-user-key :add_user_key=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Initialize yubikey PIV applet.'),
                                    '-r'                    : _('Replace existing token.'),
                                    '-n'                    : _('Do NOT initialize yubikey PIV applet, just add token data to OTPme token.'),
                                    '--key-len <key_len>'   : _('Generate RSA key with <key_len>.'),
                                    '--backup <file>'       : _('Write backup to file (default /dev/shm/username_token.pem).'),
                                    '--restore <file>'      : _('Restore key from backup file.'),
                                    '--add-user-key'        : _('Add token RSA public key as user public key.'),
                                    '-d'                    : _('Enable token related debug output.'),
                                },
                    },

    'public_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token public_key {token} {public_key}'),
                    'cmd'   :   '<|object|> <public_key>',
                    '_help' :   {
                                    'cmd'                   : _('Set token public key.'),
                                },
                },

    'dump_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token dump_key {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Dump tokens public key.'),
                                },
                },
    }
