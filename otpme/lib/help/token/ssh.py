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

from .. import register_cmd_help

def register():
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="ssh")

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

    'password'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token password --generate {token} [password]'),
                    'cmd'   :   '--generate :auto_password=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : _('Change token password.'),
                                    '--generate'            : _('Generate password.'),
                                },
                },

    'ssh_public_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token ssh_public_key {token} [ssh_public_key]'),
                    'cmd'   :   '<|object|> [ssh_public_key]',
                    '_help' :   {
                                    'cmd'                   : _('Change token SSH public key.'),
                                },
                },

    'card_type'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token card_type {token} [card_type]'),
                    'cmd'   :   '<|object|> [card_type]',
                    '_help' :   {
                                    'cmd'                   : _('Set card type of SSH token (e.g. gpg).'),
                                },
                },

    'key_type'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token key_type {token} {key_type}'),
                    'cmd'   :   '<|object|> <key_type>',
                    '_help' :   {
                                    'cmd'                   : _('Set SSH key type (e.g. rsa).'),
                                },
                },

    '2f_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token 2f_token {token} {2f_token}'),
                    'cmd'   :   '<|object|> <second_factor_token>',
                    '_help' :   {
                                    'cmd'                   : _('Change second factor token.'),
                                },
                },

    'enable_2f'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token enable_2f {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Enable second factor token.'),
                                },
                },

    'disable_2f'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token disable_2f {token}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Disable second factor token.'),
                                },
                },

    'sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token sign --stdin-pass [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Sign token.'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin.'),
                                    '--tags'                : _('Tags to add to the signature.'),
                                },
                },

    'resign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token resign --stdin-pass {name}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Resign token signatures.'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin.'),
                                },
                },

    'get_sign_data'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token get_sign_data [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Get object data to be signed from token.'),
                                    '--tags'                : _('Add sign tags to the sign object.'),
                                },
                },

    'add_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token add_sign [--tags tag1,tag2...] {name} {signature}'),
                    'cmd'   :   '--tags :[tags]: <|object|> <signature>',
                    '_help' :   {
                                    'cmd'                   : _('Add new signature to token.'),
                                    '--tags'                : _('Tags included in the signature.'),
                                },
                },

    'del_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token del_sign [--user username] [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|> [username]',
                    '_help' :   {
                                    'cmd'                   : _('Delete signature from token.'),
                                    '--user'                : _('Select signature by username.'),
                                    '--tags'                : _('Select signature by tags.'),
                                },
                },

    'verify_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token verify_sign [--user username] [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|> [username]',
                    '_help' :   {
                                    'cmd'                   : _('Verify token signature(s).'),
                                    '--user'                : _('Select signature by username.'),
                                    '--tags'                : _('Select signature by tags.'),
                                },
                },

    'get_sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-token get_sign [--user username] [--tags tag1,tag2...] {name}'),
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Get token signature(s).'),
                                    '--user'                : _('Select signature by username.'),
                                    '--tags'                : _('Select signature by tags.'),
                                },
                },
    }
