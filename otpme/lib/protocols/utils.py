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

from otpme.lib import config
from otpme.lib.protocols.server import get_class as get_class_server
from otpme.lib.protocols.client import get_class as get_class_client
from otpme.lib.protocols.server import get_module as get_module_server

from otpme.lib.exceptions import *

def register_commands(command, subcommands,
    sub_type=None, sub_type_attribute=None):
    """ Register object commands. """
    for subcommand in subcommands:
        for proto in subcommands[subcommand]:
            for state in subcommands[subcommand][proto]:
                proto_module = get_module_server(proto)
                sub_types = getattr(proto_module, 'sub_types')
                command_map = getattr(proto_module, 'command_map')
                valid_commands = getattr(proto_module, 'valid_commands')
                # Register sub type attribute.
                if sub_type_attribute:
                    try:
                        x_sub_type_attribute = sub_types[command]
                    except:
                        x_sub_type_attribute = None
                    if x_sub_type_attribute \
                    and x_sub_type_attribute != sub_type_attribute:
                        msg = "Sub type already registered."
                        raise OTPmeException(msg)
                    sub_types[command] = sub_type_attribute
                # Register command.
                x_type = command
                if sub_type:
                    x_type = f"{command}:{sub_type}"
                else:
                    if command not in valid_commands:
                        valid_commands.append(command)
                if not x_type in command_map:
                    command_map[x_type] = {}
                if not state in command_map[x_type]:
                    command_map[x_type][state] = {}
                if subcommand in command_map[x_type][state]:
                    msg = _("Command already registered: {x_type}: {subcommand}")
                    msg = msg.format(x_type=x_type, subcommand=subcommand)
                    raise OTPmeException(msg)
                command_map[x_type][state][subcommand] = subcommands[subcommand][proto][state]

def load_protocol_modules():
    """ Load all protocol modules. """
    for daemon in config.get_otpme_daemons():
        proto_list = config.get_otpme_protocols(daemon)
        for proto in proto_list:
            get_class_server(proto)
            get_class_client(proto)

def send_job(job_id, realm, site):
    """ Send job ID to client. """
    request = {
            'query_id'  : job_id,
            'command'   : 'OTPME_JOB',
            'realm'     : realm,
            'site'      : site,
            }
    return request

def send_msg(job_id, message=None):
    """ Sends message to client. """
    request = {
            'query_id'  : job_id,
            'command'   : 'OTPME_MSG',
            'message'   : message,
            }
    return request

def send_keepalive(job_id, message=None):
    """ Sends keepalive message to client. """
    request = {
            'query_id'  : job_id,
            'command'   : 'OTPME_KEEPALIVE',
            }
    return request

def dump_data(job_id, message=None):
    """ Dumps data to client. """
    request = {
            'query_id'  : job_id,
            'command'   : 'OTPME_DUMP',
            'message'   : message,
            }
    return request

def ask(query_id, prompt="Input:", input_prefill=None):
    """ Sends request to client to ask user for input. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_ASK',
            'input_prefill' : input_prefill,
            'prompt'        : prompt,
            }
    return request

def askpass(query_id, prompt="Password:", null_ok=False):
    """ Sends request to client to ask user for password. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_ASKPASS',
            'prompt'        : prompt,
            'null_ok'       : null_ok,
            }
    return request

def passauth(query_id, prompt="Password:",
    pass_len=None):
    """ Sends request to client to do password authentication. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_PASSAUTH',
            'pass_len'      : pass_len,
            'prompt'        : prompt,
            }
    return request

def sshauth(query_id, challenge):
    """ Sends request to client to do SSH authentication. """
    request = {
            'query_id'  : query_id,
            'command'   : 'OTPME_SSHAUTH',
            'challenge' : challenge,
            }
    return request

def scauth(query_id, smartcard_type, smartcard_data):
    """ Sends request to client to do SSH authentication. """
    request = {
            'query_id'          : query_id,
            'command'           : 'OTPME_SCAUTH',
            'smartcard_type'   : smartcard_type,
            'smartcard_data'    : smartcard_data,
            }
    return request

def auth_jwt(query_id, username, reason, challenge):
    """ Sends request to client to get a JWT. """
    request = {
            'query_id'  : query_id,
            'command'   : 'OTPME_GET_JWT',
            'username'  : username,
            'reason'    : reason,
            'challenge' : challenge,
            }
    return request

def gen_user_keys(query_id, username, key_len, stdin_pass=False):
    """ Sends request to client to generate users private/public keys. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_GEN_USER_KEYS',
            'username'      : username,
            'key_len'       : key_len,
            'stdin_pass'    : stdin_pass,
            }
    return request

def sign(query_id, data, use_rsa_key=False):
    """ Sends request to client to sign given data. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_SIGN',
            'data'          : data,
            }
    return request

def encrypt(query_id, data, use_rsa_key=False):
    """ Sends request to client to encrypt given data. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_ENCRYPT',
            'use_rsa_key'   : use_rsa_key,
            'data'          : data,
            }
    return request

def decrypt(query_id, data, use_rsa_key=False):
    """ Sends request to client to decrypt given data. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_DECRYPT',
            'use_rsa_key'   : use_rsa_key,
            'data'          : data,
            }
    return request

def gen_share_key(query_id, key_len, key_mode):
    """ Sends request to client to generate and encrypt share key. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_GEN_SHARE_KEY',
            'key_len'       : key_len,
            'key_mode'     : key_mode,
            }
    return request

def reencrypt_share_key(query_id, share_user, share_key, key_mode):
    """ Sends request to client to re-encrypt given share key. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_REENCRYPT_SHARE_KEY',
            'share_user'    : share_user,
            'share_key'     : share_key,
            'key_mode'     : key_mode,
            }
    return request

def move_objects(query_id, object_data):
    """ Sends request to client to move objects to other site. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_OBJECT_MOVE',
            'object_data'   : object_data,
            }
    return request

def change_user_default_group(query_id, object_data):
    """ Sends request to client to change user default group on other site. """
    request = {
            'query_id'      : query_id,
            'command'       : 'OTPME_CHANGE_USER_DEFAULT_GROUP',
            'object_data'   : object_data,
            }
    return request
