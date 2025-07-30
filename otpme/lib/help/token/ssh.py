# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from .. import register_cmd_help

def register():
    register_cmd_help(command="token", help_dict=cmd_help, mod_name="ssh")

cmd_help = {
    '_need_command'             : True,
    'add'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add [-r] {token}',
                    'cmd'   :   '-r :replace=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'add new token',
                                    '-r'                    : 'replace existing token and keep its UUID',
                                },
                },

    'password'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token password --generate {token} [password]',
                    'cmd'   :   '--generate :auto_password=True: <|object|> [password]',
                    '_help' :   {
                                    'cmd'                   : 'change token password',
                                    '--generate'            : 'generate password',
                                },
                },

    'ssh_public_key'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token ssh_public_key {token} [ssh_public_key]',
                    'cmd'   :   '<|object|> [ssh_public_key]',
                    '_help' :   {
                                    'cmd'                   : 'change token SSH public key',
                                },
                },

    'card_type'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token card_type {token} [card_type]',
                    'cmd'   :   '<|object|> [card_type]',
                    '_help' :   {
                                    'cmd'                   : 'set card type of SSH token (e.g. gpg)',
                                },
                },

    'key_type'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token key_type {token} {key_type}',
                    'cmd'   :   '<|object|> <key_type>',
                    '_help' :   {
                                    'cmd'                   : 'set SSH key type (e.g. rsa)',
                                },
                },

    '2f_token'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token 2f_token {token} {2f_token}',
                    'cmd'   :   '<|object|> <second_factor_token>',
                    '_help' :   {
                                    'cmd'                   : 'change second factor token',
                                },
                },

    'enable_2f'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token enable_2f {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'enable second factor token',
                                },
                },

    'disable_2f'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token disable_2f {token}',
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'                   : 'disable second factor token',
                                },
                },

    'sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token sign --stdin-pass [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--stdin-pass :stdin_pass=True: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Sign token.',
                                    '--stdin-pass'          : 'Read passphrase for RSA private key from stdin.',
                                    '--tags'                : 'Tags to add to the signature.',
                                },
                },

    'resign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token resign --stdin-pass {name}',
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Resign token signatures',
                                    '--stdin-pass'          : 'Read passphrase for RSA private key from stdin',
                                },
                },

    'get_sign_data'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token get_sign_data [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'Get object data to be signed from token.',
                                    '--tags'                : 'Add sign tags to the sign object.',
                                },
                },

    'add_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token add_sign [--tags tag1,tag2...] {name} {signature}',
                    'cmd'   :   '--tags :[tags]: <|object|> <signature>',
                    '_help' :   {
                                    'cmd'                   : 'Add new signature to token.',
                                    '--tags'                : 'Tags included in the signature.',
                                },
                },

    'del_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token del_sign [--user username] [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|> [username]',
                    '_help' :   {
                                    'cmd'                   : 'Delete signature from token.',
                                    '--user'                : 'Select signature by username.',
                                    '--tags'                : 'Select signature by tags.',
                                },
                },

    'verify_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token verify_sign [--user username] [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|> [username]',
                    '_help' :   {
                                    'cmd'                   : 'Verify token signature(s).',
                                    '--user'                : 'Select signature by username.',
                                    '--tags'                : 'Select signature by tags.',
                                },
                },

    'get_sign'    : {
                    '_cmd_usage_help' : 'Usage: otpme-token get_sign [--user username] [--tags tag1,tag2...] {name}',
                    'cmd'   :   '--user :username: --tags :[tags]: <|object|>',
                    '_help' :   {
                                    'cmd'                   : 'get token signature(s)',
                                    '--user'                : 'Select signature by username.',
                                    '--tags'                : 'Select signature by tags.',
                                },
                },
    }
