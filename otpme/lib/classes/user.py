# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import jwt
from otpme.lib import cli
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.encryption import aes
from otpme.lib import sign_key_cache
from otpme.lib import multiprocessing
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.register import register_module
from otpme.lib.encryption import hash_password
from otpme.lib.policy import one_time_policy_run
from otpme.lib.otpme_acl import check_special_user
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.data_objects.used_sotp import UsedSOTP
from otpme.lib.classes.data_objects.failed_pass import FailedPass
from otpme.lib.classes.otpme_object import run_pre_post_add_policies

from otpme.lib.classes.otpme_object import \
    get_acls as _get_acls
from otpme.lib.classes.otpme_object import \
    get_value_acls as _get_value_acls
from otpme.lib.classes.otpme_object import \
    get_default_acls as _get_default_acls
from otpme.lib.classes.otpme_object import \
    get_recursive_default_acls as _get_recursive_default_acls

from otpme.lib.exceptions import *

default_callback = config.get_callback()

logger = config.logger

read_acls = [
            "sign",
            "verify",
            "encrypt",
            "decrypt",
        ]

write_acls = [
            "deploy",
            "gen_keys",
            "del_keys",
            "unblock",
        ]

read_value_acls = {
            "view_all"      : [
                        "private_key",
                        "key_script",
                        "auth_script",
                        "agent_script",
                        "login_script",
                        "used_pass_salt",
                        ],
            "view"      : [
                        "token",
                        "group",
                        "public_key",
                        "failcount",
                        "session",
                        "auto_disable",
                        ],
        }

write_value_acls = {
                    "add"       : [
                                "token",
                                ],
                    "delete"    : [
                                "token",
                                "session",
                                ],
                    "rename"    : [
                                "token",
                                ],
                    "deploy"    : [
                                "token",
                                ],
                    "edit"      : [
                                "group",
                                "private_key",
                                "private_key_pass",
                                "public_key",
                                "key_script",
                                "auth_script",
                                "agent_script",
                                "login_script",
                                "auto_disable",
                                ],
                    "enable"    : [
                                "disabled_login",
                                "autosign",
                                "auth_script",
                                "login_script",
                                "token"
                                ],
                    "disable"   : [
                                "disabled_login",
                                "autosign",
                                "auth_script",
                                "login_script",
                                "token",
                                ],
        }

default_acls = [
                    "+token",
                ]

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : [],
                    'oargs'             : ['add_default_token', 'default_token', 'default_token_type', 'default_roles', 'groups', 'unit', 'group', 'template_object', 'template_name', 'gen_qrcode', 'no_token_infos', 'ldif_attributes'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'job_type'          : 'process',
                    },
                },
            },
    'touch'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'touch',
                    'job_type'          : 'process',
                    },
                },
            },
    'list'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.list_getter("user"),
                    'oargs'              : [
                                        'reverse',
                                        'show_all',
                                        'attribute',
                                        'search_regex',
                                        'sort_by',
                                        ],
                    'job_type'          : None,
                    },
                'exists'    : {
                    'method'            : cli.list_getter("user"),
                    'oargs'              : [
                                        'reverse',
                                        'show_all',
                                        'attribute',
                                        'search_regex',
                                        'sort_by',
                                        ],
                    'job_type'          : None,
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("user"),
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'max_policies',
                                        'search_regex',
                                        'sort_by',
                                        'reverse',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        'realm',
                                        'site',
                                        'show_templates',
                                        ],
                    'job_type'          : 'thread',
                    },
                'exists'    : {
                    'method'            : 'show',
                    'args'              : ['realm'],
                    'oargs'             : ['token_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'del'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'delete',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable',
                    'job_type'          : 'process',
                    },
                },
            },
    'auto_disable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_auto_disable',
                    'args'              : ['auto_disable'],
                    'job_type'          : 'process',
                    },
                },
            },
    'rename'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'rename',
                    'args'              : ['new_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'move'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'move',
                    'args'              : ['new_unit'],
                    'oargs'             : ['default_group', 'keep_acls'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_acl_inheritance'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_acl_inheritance'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_group',
                    'args'              : ['new_group'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_disabled_login'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_disabled_login',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_disabled_login'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_disabled_login',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_autosign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_autosign',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_autosign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_autosign',
                    'job_type'          : 'process',
                    },
                },
            },
    'unblock'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'unblock',
                    'oargs'             : ['access_group'],
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_sessions'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sessions',
                    'job_type'          : 'process',
                    },
                },
            },
    'key_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_script',
                    'oargs'             : ['key_script', 'script_options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_key_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_key_script',
                    'oargs'             : ['return_type'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'get_ssh_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ssh_script',
                    'oargs'             : ['return_type'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'agent_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_agent_script',
                    'oargs'             : ['agent_script', 'script_options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'login_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_login_script',
                    'oargs'             : ['login_script', 'script_options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_login_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_login_script',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_login_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_login_script',
                    'job_type'          : 'process',
                    },
                },
            },
    'auth_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_auth_script',
                    'args'              : ['auth_script', 'script_options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_auth_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_auth_script',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_auth_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_auth_script',
                    'job_type'          : 'process',
                    },
                },
            },
    'deploy_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'deploy_token',
                    'oargs'             : ['token_name', 'token_type', 'smartcard_type', 'deploy_data', 'pre_deploy', 'replace'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_name'],
                    'oargs'             : ['token_type', 'destination_token', 'replace', 'gen_qrcode', 'enable_mschap'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_token',
                    'args'              : ['token_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign_mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sign_mode',
                    'job_type'          : 'thread',
                    },
                },
            },
    'gen_keys'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'gen_keys',
                    'oargs'         : [
                                        'sign_mode',
                                        'encrypt_key',
                                        'key_len',
                                        'aes_key',
                                        'aes_key_enc',
                                        'stdin_pass',
                                    ],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_keys'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_keys',
                    'job_type'          : 'thread',
                    },
                },
            },
    'key_pass'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_pass',
                    'job_type'          : 'process',
                    },
                },
            },
    'private_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_private_key',
                    'oargs'             : ['private_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_public_key',
                    'oargs'             : ['public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'dump_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_key',
                    'oargs'             : ['private', 'decrypt', 'aes_key'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'sign_data'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'sign_data',
                    'oargs'             : ['data', 'digest', 'aes_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'verify'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'verify',
                    'oargs'             : ['data', 'digest'],
                    'job_type'          : 'process',
                    },
                },
            },
    'encrypt'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'encrypt',
                    'oargs'             : ['data'],
                    'job_type'          : 'process',
                    },
                },
            },
    'decrypt'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'decrypt',
                    'oargs'             : ['data', 'aes_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_policies'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_policies',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'list_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_groups',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    },
                },
            },
    'list_tokens'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_tokens',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type', 'token_types'],
                    'dargs'             : {'return_type':'name'},
                    },
                },
            },
    'list_roles'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_roles',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    },
                },
            },
    'add_extension'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_extension',
                    'args'              : ['extension'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_extension'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_extension',
                    'args'              : ['extension'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_attribute'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_attribute',
                    'args'              : ['attribute'],
                    'oargs'             : ['value'],
                    'job_type'          : 'process',
                    },
                },
            },
    'modify_attribute'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'modify_attribute',
                    'args'              : ['attribute', 'old_value', 'new_value'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_attribute'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_attribute',
                    'args'              : ['attribute'],
                    'oargs'             : ['value'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_object_class'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_object_class',
                    'args'              : ['object_class'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_object_class'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_object_class',
                    'args'              : ['object_class'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls',],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls',],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_policy'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_policy'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'description'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_description',
                    'oargs'             : ['description'],
                    'job_type'          : 'process',
                    },
                },
            },
    'export'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'export_config',
                    'oargs'             : ['password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_orphans'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_orphans',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
                    },
                },
            },
    '_show_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_list_valid_object_classes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_valid_object_classes',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_list_valid_attributes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_valid_attributes',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_attributes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_attributes',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_object_classes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_object_classes',
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_ldif'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ldif',
                    'args'              : ['attributes'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_default_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_recursive_default_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'recursive_default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    'config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_config_param',
                    'args'              : ['parameter', 'value'],
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(**kwargs):
    return _get_value_acls(read_value_acls, write_value_acls, **kwargs)

def get_default_acls(**kwargs):
    return _get_default_acls(default_acls, **kwargs)

def get_recursive_default_acls(**kwargs):
    return _get_recursive_default_acls(recursive_default_acls, **kwargs)

VALID_USER_KEY_LENS = [
                        1024,
                        2048,
                        4096,
                        8192,
                    ]

DEFAULT_UNIT = "users"
USER_TEMPLATE = "user_template"
KEY_SCRIPT_NAME = "key_script.sh"
AUTH_SCRIPT_NAME = "auth_script.sh"
AGENT_SCRIPT_NAME = "agent_script.sh"
LOGIN_SCRIPT_NAME = "login_script.sh"

REGISTER_BEFORE = ['otpme.lib.policy']
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                "otpme.lib.classes.group",
                "otpme.lib.classes.script",
                "otpme.lib.classes.policy",
                ]

def local_admin_user_getter(self):
    from otpme.lib.multiprocessing import local_admin_user
    try:
        _local_admin_user = local_admin_user['value']
    except:
        _local_admin_user = None
    if _local_admin_user is True:
        return True
    return False

def local_admin_user_setter(self, new_status):
    from otpme.lib.multiprocessing import local_admin_user
    local_admin_user['value'] = new_status

def register():
    register_dn()
    register_oid()
    register_hooks()
    register_backend()
    register_template()
    register_object_unit()
    register_ldap_object()
    register_user_scripts()
    register_sync_settings()
    register_shared_objects()
    register_config_properties()
    register_config_parameters()
    register_commands("user", commands)
    register_module("otpme.lib.classes.session")
    register_module("otpme.lib.classes.data_objects.used_sotp")
    register_module("otpme.lib.classes.data_objects.failed_pass")
    register_module("otpme.lib.classes.data_objects.last_assigned_id")
    register_module("otpme.lib.classes.data_objects.revoked_signature")
    multiprocessing.register_shared_dict("otp_hashes")

def register_template():
    config.register_object_template("user", USER_TEMPLATE)

def register_config_properties():
    config.register_property(name="local_admin_user",
                            getx=local_admin_user_getter,
                            setx=local_admin_user_setter)

def register_shared_objects():
    from otpme.lib.multiprocessing import register_shared_dict
    register_shared_dict("local_admin_user")

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("user", "uid")

def register_hooks():
    config.register_auth_on_action_hook("user", "unlock")
    config.register_auth_on_action_hook("user", "gen_keys")
    config.register_auth_on_action_hook("user", "del_keys")
    config.register_auth_on_action_hook("user", "add_token")
    config.register_auth_on_action_hook("user", "del_token")
    config.register_auth_on_action_hook("user", "pre_add_token")
    config.register_auth_on_action_hook("user", "deploy_token")
    config.register_auth_on_action_hook("user", "change_group")
    config.register_auth_on_action_hook("user", "change_key_pass")
    config.register_auth_on_action_hook("user", "enable_autosign")
    config.register_auth_on_action_hook("user", "disable_autosign")
    config.register_auth_on_action_hook("user", "change_private_key")
    config.register_auth_on_action_hook("user", "change_public_key")
    config.register_auth_on_action_hook("user", "enable_auth_script")
    config.register_auth_on_action_hook("user", "disable_auth_script")
    config.register_auth_on_action_hook("user", "enable_login_script")
    config.register_auth_on_action_hook("user", "disable_login_script")
    config.register_auth_on_action_hook("user", "change_key_script")
    config.register_auth_on_action_hook("user", "change_agent_script")
    config.register_auth_on_action_hook("user", "change_login_script")
    config.register_auth_on_action_hook("user", "change_auth_script")
    config.register_auth_on_action_hook("user", "sign")
    config.register_auth_on_action_hook("user", "verify")
    config.register_auth_on_action_hook("user", "encrypt")
    config.register_auth_on_action_hook("user", "decrypt")

def register_user_scripts():
    """ Registger user scripts. """
    config.register_base_object("script", AGENT_SCRIPT_NAME)
    config.register_base_object("script", AUTH_SCRIPT_NAME)
    config.register_base_object("script", KEY_SCRIPT_NAME)
    config.register_base_object("script", LOGIN_SCRIPT_NAME)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT)
    config.register_default_unit("user", DEFAULT_UNIT)

def register_config_parameters():
    """ Registger config parameters. """
    # Object types our config parameters are valid for.
    object_types = [
                        'realm',
                        'site',
                        'unit',
                    ]
    # Default scripts unit.
    scripts_unit = config.get_default_unit("script")
    # Default key script to add to new users.
    KEY_SCRIPT_PATH = "%s/%s" % (scripts_unit, KEY_SCRIPT_NAME)
    config.register_config_parameter(name="default_key_script",
                                    ctype=str,
                                    default_value=KEY_SCRIPT_PATH,
                                    object_types=object_types)
    # Default auth script to add to new users.
    AUTH_SCRIPT_PATH = "%s/%s" % (scripts_unit, AUTH_SCRIPT_NAME)
    config.register_config_parameter(name="default_auth_script",
                                    ctype=str,
                                    default_value=AUTH_SCRIPT_PATH,
                                    object_types=object_types)
    # Default agent script to add to new users.
    AGENT_SCRIPT_PATH = "%s/%s" % (scripts_unit, AGENT_SCRIPT_NAME)
    config.register_config_parameter(name="default_agent_script",
                                    ctype=str,
                                    default_value=AGENT_SCRIPT_PATH,
                                    object_types=object_types)
    # Default login script to add to new users.
    LOGIN_SCRIPT_PATH = "%s/%s" % (scripts_unit, LOGIN_SCRIPT_NAME)
    config.register_config_parameter(name="default_login_script",
                                    ctype=str,
                                    default_value=LOGIN_SCRIPT_PATH,
                                    object_types=object_types)
    # Max failed pass history length
    object_types = [
                        'realm',
                        'site',
                        'unit',
                        'user',
                    ]
    config.register_config_parameter(name="failed_pass_history",
                                    ctype=int,
                                    default_value=16,
                                    object_types=object_types)
    # Add default realm login token on user creation?
    object_types = [
                        'realm',
                        'site',
                        'unit',
                    ]
    config.register_config_parameter(name="add_default_token",
                                    ctype=bool,
                                    default_value=True,
                                    object_types=object_types)
    ## Automatically start token deployment on user creation?
    #config.register_config_parameter(name="deploy_default_token",
    #                                ctype=bool,
    #                                default_value=True,
    #                                object_types=object_types)
    # Name of default token to add.
    config.register_config_parameter(name="default_token_name",
                                    ctype=str,
                                    default_value="login",
                                    object_types=object_types)
    # Default token type to add.
    config.register_config_parameter(name="default_token_type",
                                    ctype=str,
                                    default_value="hotp",
                                    object_types=object_types)
    # Length for user RSA keys.
    object_types = [
                        'realm',
                        'site',
                        'unit',
                        'user',
                    ]
    config.register_config_parameter(name="user_key_len",
                                    ctype=int,
                                    default_value=2048,
                                    valid_values=VALID_USER_KEY_LENS,
                                    object_types=object_types)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'name' ]
    # OID regex stuff.
    # allow "@" in usernames
    unit_path_re = oid.object_regex['unit']['path']
    user_name_re = '([0-9a-z]([0-9a-z_.@-]*[0-9a-z]){0,})'
    user_path_re = '%s[/]%s' % (unit_path_re, user_name_re)
    user_oid_re = 'user|%s' % user_path_re
    oid.register_oid_schema(object_type="user",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=user_name_re,
                            path_regex=user_path_re,
                            oid_regex=user_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="user",
                                getter=rel_path_getter)
    def name_checker(object_type, object_name):
        """ Make sure object name is in correct format. """
        base_users = config.get_base_objects("user")
        if object_name in base_users:
            return True
        regex_string = oid.object_regex[object_type]['name']
        regex = re.compile("^%s$" % regex_string)
        if regex.match(object_name):
            return True
    oid.register_name_checker(object_type="user",
                            getter=name_checker)
    return False

def register_backend():
    """ Register object for the file backend. """
    # Extension for user config dirs.
    user_dir_extension = "user"
    # Base data dir for used (OTP) objects.
    used_base_dir = backend.get_data_dir("used")
    # Path getter for users "used" dir.
    def upath_getter(user_oid):
        user_uuid = backend.get_uuid(user_oid)
        if not user_uuid:
            return
        user_used_dir = os.path.join(used_base_dir, user_uuid)
        return user_used_dir
    # Register users "used" dir.
    backend.register_object_dir(object_type="user",
                                name="used_dir",
                                getter=upath_getter,
                                drop=True)
    # Path getter for user paths.
    def opath_getter(user_oid):
        unit_fs_path = backend.get_unit_fs_path(user_oid)
        site_dir = backend.get_site_dir(user_oid.realm, user_oid.site)
        config_dir_name = "%s.%s" % (user_oid.name, user_dir_extension)
        config_dir = os.path.join(site_dir, unit_fs_path, config_dir_name)

        config_paths = {}
        config_paths['config_dir'] = config_dir
        config_paths['rmtree_on_delete'] = [config_dir]

        user_dirs = backend.get_object_dir(user_oid)
        for x in user_dirs:
            x_path = user_dirs[x]['path']
            if not x_path:
                continue
            config_paths[x] = x_path
            x_drop = user_dirs[x]['drop']
            if not x_drop:
                continue
            config_paths['rmtree_on_delete'].append(x_path)
        return config_paths
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                'group',
                'ca',
                'node',
                'host',
                ]
        return backend.rebuild_object_index("user", objects, after)
    # Register object to config.
    config.register_object_type(object_type="user",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["group"],
                            sync_before=["token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'name'])
    # Register object to backend.
    class_getter = lambda: User
    backend.register_object_type(object_type="user",
                                dir_name_extension=user_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=opath_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="host", object_type="user")
    config.register_object_sync(host_type="node", object_type="user")

def register_ldap_object():
    """ Register LDAP object settings. """
    config.register_ldap_object(object_type="user",
                                default_scope="one",
                                scopes=['one'])

def user_failcount(user_uuid, access_group):
    group_oid = oid.get(object_type="accessgroup",
                        realm=config.realm,
                        site=config.site,
                        name=access_group)
    group_uuid = backend.get_uuid(group_oid)
    if not group_uuid:
        return 0

    return_attrs = ['accessgroup_uuid']
    result = backend.search(object_type="failed_pass",
                            attribute="user_uuid",
                            value=user_uuid,
                            return_attributes=return_attrs)
    failed_list = []
    for ag_uuid in result:
        if ag_uuid != group_uuid:
            continue
        failed_list.append(ag_uuid)

    failed_count = len(failed_list)

    return failed_count

def user_is_blocked(user_uuid, access_group, realm, site):
    if not access_group or not realm or not site:
        raise Exception("Need realm and site and access_group.")

    # Re-read failcount.
    user_fail_count = user_failcount(user_uuid, access_group)

    # Get max fail from group.
    result = backend.search(object_type="accessgroup",
                            realm=realm,
                            site=site,
                            attribute="name",
                            value=access_group,
                            return_attributes=['max_fail', 'max_fail_reset'])
    if not result:
        msg = ("Unable to get 'max_fail' for accessgroup '%s'"
                % access_group)
        logger.critical(msg)
        return False

    for uuid in result:
        max_fail = result[uuid]['max_fail'][0]
        max_fail_reset = result[uuid]['max_fail_reset'][0]

    # If max_fail is set to 0 the user will never be blocked.
    is_blocked = False
    if max_fail > 0 and user_fail_count >= max_fail:
        is_blocked = True

    # Check if max fail reset is reached.
    if is_blocked and max_fail_reset > 0:
        # Get all failed pass object UUIDs to get last login try time.
        result = backend.search(object_type="failed_pass",
                                attribute="user_uuid",
                                value=user_uuid,
                                return_type="uuid")
        # Get last used timestamps.
        last_used_list = []
        for uuid in result:
            last_used = backend.get_last_used(realm=realm,
                                            site=site,
                                            object_type="failed_pass",
                                            uuid=uuid)
            last_used_list.append(last_used)
        # Check if reset time is reached.
        if last_used_list:
            now = time.time()
            last_login_try = sorted(last_used_list)[0]
            last_try_age = now - last_login_try
            if last_try_age > max_fail_reset:
                is_blocked = False
    return is_blocked

class User(OTPmeObject):
    """ Class that implements OTPmeUser. """
    commands = commands
    def __init__(self, object_id=None, path=None, name=None,
        unit=None, site=None, realm=None, **kwargs):
        # Set our type (used in parent class).
        self.type = "user"

        # Call parent class init.
        super(User, self).__init__(object_id=object_id,
                                    realm=realm,
                                    site=site,
                                    unit=unit,
                                    name=name,
                                    path=path,
                                    **kwargs)
        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Users primary group cache.
        self._group_uuid = None
        # Indicates that the user is allowed to login even if realm/site/accessgroup/unit is disabled.
        self.allow_disabled_login = False
        # Users keys can be handled by the key script on client side or by this
        # class.
        self.sign_mode = "client"
        # Will hold users RSA private key or stuff needed to get it
        # via self.key_script.
        #self.private_key = {}
        # Will hold users RSA public key.
        self.public_key = None
        # Indicates if user auto-sign feature is enabled.
        self.autosign_enabled = False
        # The OTPmeScript used to handle users private key.
        self.key_script = None
        # The OTPmeScript used to start/stop users gpg/ssh-agent.
        self.agent_script = None
        # The OTPmeScript used as users login script.
        self.login_script = None
        self.login_script_enabled = False
        self.used_pass_salt = None
        # SSO session data.
        self.sso_session_data = {}
        self.auth_script = None
        self.auth_script_enabled = False
        self.acl_inheritance_enabled = False
        self.track_last_used = True

        # Users default token.
        self.default_token = None

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "TOKENS",
                            "PUBLIC_KEY",
                            "DEFAULT_TOKEN",
                            "EXTENSIONS",
                            "EXTENSION_ATTRIBUTES",
                            "AUTOSIGN_ENABLED",
                            "ALLOW_DISABLED_LOGIN",
                            "OBJECT_CLASSES",
                            "homeDirectory",
                            "loginShell",
                            "uidNumber",
                            "givenName",
                            "sn",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "TOKENS",
                            "PUBLIC_KEY",
                            "DEFAULT_TOKEN",
                            "EXTENSIONS",
                            "EXTENSION_ATTRIBUTES",
                            "AUTOSIGN_ENABLED",
                            "ALLOW_DISABLED_LOGIN",
                            "OBJECT_CLASSES",
                            "USED_PASS_SALT",
                            "ACLS",
                            "ACL_INHERITANCE_ENABLED",
                            "homeDirectory",
                            "loginShell",
                            "uidNumber",
                            "givenName",
                            "sn",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'TOKENS'                    : {
                                                        'var_name'  : 'tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'DEFAULT_TOKEN'             : {
                                                        'var_name'  : 'default_token',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'ALLOW_DISABLED_LOGIN'      : {
                                                        'var_name'  : 'allow_disabled_login',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'SIGN_MODE'                 : {
                                                        'var_name'  : 'sign_mode',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

                        'AUTOSIGN_ENABLED'          : {
                                                        'var_name'  : 'autosign_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'PRIVATE_KEY'               : {
                                                        'var_name'  : 'private_key',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                        'encoding'  : 'BASE64',
                                                        'encryption': config.disk_encryption,
                                                    },

                        'PUBLIC_KEY'                : {
                                                        'var_name'  : 'public_key',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encoding'  : 'BASE64',
                                                    },

                        'KEY_SCRIPT'                : {
                                                        'var_name'  : 'key_script',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'KEY_SCRIPT_OPTIONS'        : {
                                                        'var_name'  : 'key_script_options',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'AGENT_SCRIPT'                : {
                                                        'var_name'  : 'agent_script',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'AGENT_SCRIPT_OPTIONS'        : {
                                                        'var_name'  : 'agent_script_options',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'LOGIN_SCRIPT'                : {
                                                        'var_name'  : 'login_script',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'LOGIN_SCRIPT_OPTIONS'        : {
                                                        'var_name'  : 'login_script_options',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'LOGIN_SCRIPT_ENABLED'       : {
                                                        'var_name'  : 'login_script_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'AUTH_SCRIPT'               : {
                                                        'var_name'  : 'auth_script',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'AUTH_SCRIPT_OPTIONS'       : {
                                                        'var_name'  : 'auth_script_options',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'AUTH_SCRIPT_ENABLED'       : {
                                                        'var_name'  : 'auth_script_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'USED_PASS_SALT'            : {
                                                        'var_name'  : 'used_pass_salt',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },
                        'SSO_SESSION_DATA'          : {
                                                        'var_name'  : 'sso_session_data',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },
                        }

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Try to get site name.
        if self.site_uuid:
            site_oid = backend.get_oid(object_type="site",
                                    uuid=self.site_uuid,
                                    instance=True)
            self.site = site_oid.name
        # Set OID.
        self.set_oid()

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string
        name = str(name)
        name_upper = name.upper()
        internal_users = config.get_internal_objects("user")
        if name_upper in internal_users:
            name = name_upper
        else:
            if name != name.lower():
                msg = (_("Username must be lowercase."))
                raise OTPmeException(msg)
        self.name = name

    def get_id(self):
        return self.uuid

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_authenticated(self):
        if config.auth_token:
            return True
        return False

    @property
    def group(self):
        if not self.group_uuid:
            return
        group_oid = backend.get_oid(self.group_uuid, instance=True)
        if not group_oid:
            return
        return group_oid.name

    @group.setter
    def group(self, new_group):
        result = backend.search(object_type="group",
                                #realm=config.realm,
                                #site=config.site,
                                attribute="name",
                                value=new_group,
                                return_type="uuid")
        if not result:
            msg = "Unknown group: %s" % new_group
            raise UnknownObject(msg)
        self.group_uuid = result[0]

    @property
    def group_uuid(self):
        if self._group_uuid:
            return self._group_uuid
        result = backend.search(object_type="group",
                                attribute="user",
                                value=self.uuid,
                                return_type="uuid")
        if not result:
            return
        self._group_uuid = result[0]
        return self._group_uuid

    @group_uuid.setter
    def group_uuid(self, group_uuid):
        return self._change_group(group_uuid)

    def _change_group(self, group_uuid,
        verify_acls=True, callback=default_callback):
        """ Change users group. """
        # Remove user from current group.
        current_group_uuid = None
        if self._group_uuid:
            current_group_uuid = self._group_uuid
        else:
            result = backend.search(object_type="group",
                                    attribute="user",
                                    value=self.uuid,
                                    return_type="uuid")
            if result:
                current_group_uuid = result[0]
        if current_group_uuid:
            result = backend.search(object_type="group",
                                    attribute="uuid",
                                    value=current_group_uuid,
                                    return_type="instance")
            if result:
                group = result[0]
                group.remove_default_group_user(self.uuid,
                                            verify_acls=verify_acls,
                                            ignore_missing=True)
        # Add user to new group.
        result = backend.search(object_type="group",
                                attribute="uuid",
                                value=group_uuid,
                                return_type="instance")
        if not result:
            msg = "Unknown group: %s" % group_uuid
            raise UnknownObject(msg)
        group = result[0]
        msg = "Setting group: %s" % group.name
        callback.send(msg)
        self._group_uuid = group.uuid
        self.update_index('group', self._group_uuid)
        result = group.add_default_group_user(self.uuid,
                                            verify_acls=verify_acls,
                                            callback=callback)
        self.update_extensions("change_group", callback=callback)
        return result

    def cross_site_move(self, path, default_group=None,
        callback=default_callback, **kwargs):
        """ Do cross site move of user. """
        if config.use_api:
            msg = "Cannot do cross-site move in API mode."
            return callback.error(msg)

        path_data = oid.resolve_path(object_path=path,
                                        object_type="unit")
        dst_realm = path_data['realm']
        dst_site = path_data['site']

        # Make sure we can change users default group.
        _default_group = None
        if self.group_uuid:
            result = backend.search(object_type="group",
                                    attribute="uuid",
                                    value=self.group_uuid,
                                    return_type="instance")
            if result:
                _default_group = result[0]
                if not _default_group.verify_acl("remove:default_group_user"):
                    msg = "Failed to change users default group: Permission denied"
                    return callback.error(msg)

        result = backend.search(object_type="group",
                                attribute="name",
                                value=default_group,
                                realm=config.realm,
                                return_type="instance")
        if not result:
            msg = "Unknown new default group: %s" % default_group
            return callback.error(msg)
        new_default_group = result[0]
        if new_default_group.site != dst_site:
            msg = "New default group must be from site: %s" % dst_site
            return callback.error(msg)

        object_config = self.object_config.copy()
        object_ids = [(self.oid.full_oid, self.uuid)]
        objects = {
                    self.oid.full_oid   : {
                                            'path'          : path,
                                            'object_config' : object_config,
                                            'default_group' : default_group,
                                        },
                }

        token_list = self.get_tokens(return_type="instance")
        for token in token_list:
            token_oc = token.object_config.copy()
            objects[token.oid.full_oid] = {}
            objects[token.oid.full_oid]['object_config'] = token_oc
            object_ids.append((token.oid.full_oid, token.uuid))

        # Get destination site cert to encrypt objects and
        # verify reply JWT.
        _dst_site = backend.get_object(object_type="site",
                                        realm=dst_realm,
                                        name=dst_site)
        # Generate encryption key.
        enc_mod = config.get_encryption_module("FERNET")
        enc_key = enc_mod.gen_key()
        # Encrypt objects.
        objects_encrypted = json.encode(objects,
                                    encoding="base64",
                                    encryption=enc_mod,
                                    enc_key=enc_key)

        # Encrypt encryption key with destination site public key.
        try:
            dst_site_public_key = RSAKey(key=_dst_site._cert.public_key())
        except Exception as e:
            msg = (_("Unable to get public key of site "
                    "certificate: %s: %s") % (dst_site, e))
            logger.warning(msg)
            return callback.error(msg)
        enc_key_encrypted = dst_site_public_key.encrypt(enc_key, encoding="hex")

        # Load JWT signing key.
        our_site = backend.get_object(uuid=config.site_uuid)
        sign_key = our_site._key
        # Build JWT.
        jwt_data = {
                'src_realm'     : config.realm,
                'src_site'      : config.site,
                'dst_path'      : path,
                'dst_realm'     : dst_realm,
                'dst_site'      : dst_site,
                'default_group' : default_group,
                'object_ids'    : object_ids,
                'enc_key'       : enc_key_encrypted,
                'reason'        : "OBJECT_MOVE",
                }
        # Sign object move data.
        _jwt = jwt.encode(payload=jwt_data, key=sign_key, algorithm='RS256')

        object_data = {
                    'path'          : path,
                    'src_realm'     : config.realm,
                    'src_site'      : config.site,
                    'dst_realm'     : dst_realm,
                    'dst_site'      : dst_site,
                    'objects'       : objects_encrypted,
                    'jwt'           : _jwt,
                    }

        # Actually move objects to other site.
        response = callback.move_objects(object_data)

        status = response['status']
        reply = response['reply']

        if not status:
            msg = "Object move failed: %s" % reply
            return callback.error(msg)

        # Decode reply JWT.
        try:
            jwt_data = jwt.decode(jwt=reply,
                                key=dst_site_public_key,
                                algorithm='RS256')
        except Exception as e:
            msg = "JWT verification failed: %s" % e
            logger.warning(msg)
            return callback.error(msg)

        # Make sure we only delete objects if all were written on
        # destination site.
        for x_oid in objects:
            x_oc = objects[x_oid]['object_config']
            x_uuid = x_oc['UUID']
            try:
                y_uuid = jwt_data[x_oid]['uuid']
            except KeyError:
                msg = "Failed to find object in reply: %s" % x_oid
                return callback.error(msg)
            if x_uuid != y_uuid:
                msg = ("UUID missmatch in reply: %s: %s <> %s"
                        % (x_oid, x_uuid, y_uuid))
                return callback.error(msg)


        if _default_group:
            _default_group.remove_default_group_user(self.uuid,
                                            ignore_missing=True)

        # Actually delete objects from backend.
        for object_type in reversed(config.object_add_order):
            for x_oid in objects:
                x_oid = oid.get(x_oid)
                if x_oid.object_type != object_type:
                    continue
                try:
                    backend.delete_object(x_oid, cluster=True)
                except UnknownObject:
                    pass
                except Exception as e:
                    msg = ("Failed to delete object on source site: %s"
                            % x_oid)
                    callback.error(msg)

        return callback.ok()

    def move(self, *args, callback=default_callback, **kwargs):
        """ Move user to other unit. """
        if self.name == config.admin_user_name:
            msg = "Moving admin user is not allowed."
            return callback.error(msg)
        internal_users = config.get_internal_objects("user")
        if self.name in internal_users:
            msg = "Moving internal user is not allowed."
            return callback.error(msg)
        new_unit = kwargs['new_unit']
        if new_unit.startswith("/"):
            path_data = oid.resolve_path(new_unit, object_type="user")
            new_site = path_data['site']
            if new_site != self.site:
                return self.cross_site_move(*args, path=new_unit,
                                            callback=callback,
                                            **kwargs)
        super(User, self).move(*args, callback=callback, **kwargs)
        token_list = self.get_tokens(return_type="instance")
        for token in token_list:
            token._write(callback=callback)
        return callback.ok()

    def get_members(self, return_type="full_oid", **kwargs):
        """ Get all user tokens. """
        token_list = self.get_tokens(return_type=return_type)
        members = {}
        members['token'] = token_list
        return members

    def _write(self, **kwargs):
        """ Wrapper to make sure users signing public key added to cache. """
        if self.public_key:
            try:
                sign_key_cache.add_cache(self.oid, self.public_key)
            except Exception as e:
                config.raise_exception()
                msg = "Unable to add signer cache: %s: %s" % (self.oid, e)
                logger.critical(msg)
        return super(User, self)._write(**kwargs)

    def get_sign_mode(self, callback=default_callback, **kwargs):
        """ Get users sign mode. """
        return callback.ok(self.sign_mode)

    def _set_key(self, aes_key=None, rsa_key=None, encrypted=False):
        """
        Encode (create one line string with AES+RSA key) private key string.
        """
        self.private_key = {'aes_key':aes_key, 'rsa_key':rsa_key, 'encrypted':encrypted}

    def _get_key(self):
        if self.sign_mode == "server":
            aes_key = self.private_key['aes_key']
            rsa_key = self.private_key['rsa_key']
            encrypted = self.private_key['encrypted']
        else:
            aes_key = None
            rsa_key = self.private_key['key_blob']
            encrypted = False
        return aes_key, rsa_key, encrypted

    @object_lock()
    @check_acls(['edit:group'])
    def change_group(self, new_group, verbose_level=0,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Change object group. """
        if new_group == "":
            msg = (_("Missing group."))
            return callback.error(msg)

        result = backend.search(object_type="group",
                                attribute="name",
                                value=new_group,
                                return_type="uuid")
        if not result:
            msg = (_("Unknown group: %s") % new_group)
            return callback.error(msg)
        group_uuid = result[0]

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        try:
            self._change_group(group_uuid,
                            verify_acls=True,
                            callback=callback)
        except UnknownObject as e:
            msg = str(e)
            return callback.error(msg, exception=UnknownObject)
        except PermissionDenied as e:
           msg = "Permission denied while setting group."
           return callback.error(msg, exception=PermissionDenied)

        # Reload extensions.
        self.load_extensions(verbose_level=verbose_level, callback=callback)
        return self._cache(callback=callback)

    @check_acls(['edit:private_key'])
    @object_lock(full_lock=True)
    def change_private_key(self, private_key, force=False, verbose_level=0,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Set users RSA private key or stuff to get it. """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("change_private_key",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                return callback.error()

        if self.private_key != None and not force:
            if self.confirmation_policy != "force":
                ask = callback.ask("Replace existing private key?: ")
                if str(ask).lower() != "y":
                    return callback.abort()

        if private_key == "":
            self.private_key = None
        else:
            # Set private key.
            self.private_key = private_key

        return self._cache(callback=callback)

    @check_acls(['edit:public_key'])
    @object_lock(full_lock=True)
    def change_public_key(self, public_key, force=False, verbose_level=0,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Set users RSA public key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("change_public_key",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                return callback.error()

        if self.public_key != None and not force:
            if self.confirmation_policy != "force":
                ask = callback.ask("Replace existing public key?: ")
                if str(ask).lower() != "y":
                    return callback.abort()

        if public_key == "":
            self.public_key = None
        else:
            # Set public key.
            self.public_key = public_key

        return self._cache(callback=callback)

    def get_key_script(self, return_type="path",
        _caller="API", callback=default_callback, **kwargs):
        """ Get user key script name or UUID + options. """
        opts = None
        script = None
        if _caller == "CLIENT":
            script = ""

        if self.key_script:
            if return_type == "uuid":
                script = self.key_script
            else:
                ks = backend.get_object(object_type="script",
                                        uuid=self.key_script)
                if not ks:
                    msg = (_("Script does not exist: %s") % self.key_script)
                    return callback.error(msg)
                if return_type == "path":
                    script = ks.rel_path
                elif return_type == "instance":
                    if _caller != "API":
                        return callback.error("Invalid return type: instance")
                    script = ks
                else:
                    msg = "Invalid <return_type>: %s" % return_type
                    raise OTPmeException(msg)
        if self.key_script_options:
            opts = self.key_script_options
        if _caller != "CLIENT":
            result = (script, opts)
        else:
            if opts:
                result = "%s %s" % (script, opts)
            else:
                result = script
        return callback.ok(result)

    def get_ssh_script(self, return_type="name",
        _caller="API", callback=default_callback, **kwargs):
        """ Get user SSH agent script name or UUID + options. """
        script = None
        opts = None
        if self.agent_script:
            if return_type == "uuid":
                script = self.agent_script
            else:
                ks = backend.get_object(object_type="script",
                                        uuid=self.agent_script)
                if not ks:
                    msg = (_("Script does not exist: %s") % self.agent_script)
                    return callback.error(msg)
                if return_type == "name":
                    script = ks.name
                if return_type == "instance":
                    if _caller != "API":
                        return callback.error("Invalid return type: instance")
                    script = ks
        if self.agent_script_options:
            opts = self.agent_script_options
        if _caller == "API":
            result = script, opts
        else:
            if opts:
                result = "%s %s" % (script, opts)
            else:
                result = script
        return callback.ok(result)

    def get_key(self, private=False, decrypt=False, aes_key=None,
        force=False, callback=default_callback, _caller="API", **kwargs):
        """ Return user key as string. """
        if private:
            if not self.verify_acl("view_all:private_key"):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)
        if private and self.private_key:
            # Get private key. We need to pass on callback to allow decryption
            # of private key if sign mode is server.
            try:
                private_key = self.get_private_key(decrypt=decrypt,
                                                    aes_key=aes_key,
                                                    callback=callback,
                                                    _caller=_caller)
                # Send private key to client.
                return callback.ok(private_key)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)
        elif not private and self.public_key:
            # If decrypt (-n) is set we return the public key in its original
            # form (e.g. not as a one line base64 string).
            if decrypt:
                public_key = decode(self.public_key, "base64")
            else:
                public_key = self.public_key
            return callback.ok(public_key)
        if private:
            msg = "No private key set."
        else:
            msg = "No public key set."
        return callback.error(msg)

    @check_acls(['gen_keys'])
    @check_special_user()
    @cli.check_rapi_opts()
    #@object_lock(full_lock=True)
    def gen_keys(self, sign_mode="client", encrypt_key=True, aes_key=None,
        aes_key_enc=None, key_len=None, pass_hash_type="PBKDF2", force=False,
        run_policies=True, stdin_pass=False, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Create users RSA private/public key pair. """
        if sign_mode not in [ 'client', 'server' ]:
            msg = ("Unknown sign mode: %s" % sign_mode)
            return callback.error(msg)

        if key_len is None:
            key_len = self.get_config_parameter("user_key_len")

        if key_len not in VALID_USER_KEY_LENS:
            key_lens = []
            for i in VALID_USER_KEY_LENS:
                key_lens.append(str(i))
            valid_key_lens = ", ".join(key_lens)
            msg = (_("Key bits must be one of: %s") % valid_key_lens)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("gen_keys",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if self.private_key or self.public_key:
            ask_user = True
            if force:
                ask_user = False
            if self.confirmation_policy == "force":
                ask_user = False
            if self.confirmation_policy != "paranoid":
                if force:
                    ask_user = False
            if ask_user:
                ask = callback.ask("Replace existing user keys?: ")
                if str(ask).lower() != "y":
                    return callback.abort()

        self.sign_mode = sign_mode

        if sign_mode == "client":
            # Ask client to create users keys.
            reply = callback.gen_user_keys(username=self.name,
                                            key_len=key_len,
                                            stdin_pass=stdin_pass)
            if reply is None:
                return callback.abort()

            try:
                status = reply['status']
            except:
                status = False
            try:
                message = reply['message']
            except:
                message = "Unknown error."

            if not status:
                msg = ("Key generation failed: %s" % message)
                return callback.error(msg)

            # Get keys from reply.
            try:
                self.private_key = {}
                self.private_key['key_blob'] = reply['private_key']
            except KeyError:
                pass
            try:
                self.public_key = reply['public_key']
            except KeyError:
                pass

            if not self.public_key:
                return callback.error("Got no public key.")

            if not self.private_key:
                return callback.error("Got no private key.")

            return self._cache(callback=callback)

        if aes_key and not aes_key_enc:
            msg = "Need 'aes_key_enc' when 'aes_key' is set."
            return callback.error(msg)

        if encrypt_key and not aes_key:
            aes_key = aes.gen_key()
            aes_key_enc = callback.encrypt(aes_key, use_rsa_key=False)
            if len(aes_key_enc) == 0:
                msg = ("Got no encrypted AES key from client.")
                return callback.error(msg)

        callback.send(_("Generating keys (%s bits)...") % key_len)
        # Generate new key pair.
        try:
            key = RSAKey(bits=key_len)
        except Exception as e:
            return callback.error(_("Error creating RSA key: %s")% e)

        # Encrypt private key if we got a AES key.
        if aes_key:
            try:
                key_encrypted = key.encrypt_key(aes_key=aes_key,
                                            hash_type=pass_hash_type)
                self._set_key(aes_key_enc, key_encrypted, encrypted=True)
            except Exception as e:
                msg = (_("Error encrypting private key: %s") % e)
                return callback.error(msg)
        else:
            self._set_key(rsa_key=private_key_base64)

        # Set public key.
        self.public_key = encode(key.public_key_base64, "base64")

        return self._cache(callback=callback)

    @check_acls(['del_keys'])
    @check_special_user()
    @cli.check_rapi_opts()
    #@object_lock(full_lock=True)
    def del_keys(self, force=False, run_policies=True, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Create users RSA private/public key pair. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_keys",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not self.private_key and not self.public_key:
            msg = "No user keys present."
            return callback.error(msg)

        ask_user = True
        if force:
            ask_user = False
        if self.confirmation_policy == "force":
            ask_user = False
        if self.confirmation_policy != "paranoid":
            if force:
                ask_user = False
        if ask_user:
            ask = callback.ask("Remove user keys?: ")
            if str(ask).lower() != "y":
                return callback.abort()

        self.private_key = None
        self.public_key = None

        return self._cache(callback=callback)

    def get_private_key(self, decrypt=True, aes_key=None,
        callback=default_callback, _caller="API"):
        """ Get private key (e.g. decrypt it). """
        if not self.private_key:
            msg = "No private key set."
            return callback.error(msg)
        # Decode private key stuff.
        aes_key, rsa_key, encrypted = self._get_key()
        if encrypted:
            if decrypt:
                if not aes_key:
                    if _caller == "API":
                        msg = ("Need 'aes_key' to decrypt private key.")
                        raise OTPmeException(msg)
                # Try to decrypt AES key.
                aes_key = callback.decrypt(aes_key)
                if not isinstance(aes_key, str):
                    msg = ("Unable to decrypt private key.")
                    return callback.error(msg)
                # Try to decrypt RSA key.
                key = RSAKey(key=rsa_key, aes_key=aes_key)
                try:
                    key = RSAKey(key=rsa_key, aes_key=aes_key)
                    private_key = key.private_key_base64
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Error decrypting private key: %s") % e)
                    return callback.error(msg)
            else:
                private_key = rsa_key
        else:
            private_key = decode(rsa_key, "base64")

        # We must not use callback here to prevent sending private key to the
        # client by accident!
        return private_key

    @check_acls(['edit:private_key_pass'])
    @object_lock(full_lock=True)
    def change_key_pass(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change private key passphrase. """
        if not self.private_key:
            return callback.error("No private key set.")
        if self.sign_mode != "server":
            msg = ("Private key is not handled by server.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_key_pass",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        remove_key_pass = False
        # Check if the current key is encrypted.
        if self.private_key.startswith("RSA{"):
            # Try to get keypack string.
            try:
                aes_key_enc, key_string = self._decode_key()
            except:
                msg = ("Error decoding private key value.")
                return callback.error(msg)
            # Try to get decrypted AES key from client.
            aes_key = callback.decrypt(aes_key_enc)
        else:
            # Try to get private key string.
            try:
                key_string = self.private_key.split("[")[1].split("]")[0]
                key_string = decode(key_string, "base64")
            except:
                msg = ("Error decoding private key value.")
                return callback.error(msg)
            aes_key = False

        try:
            user_key = RSAKey(key=key_string, aes_key=aes_key)
            private_key = user_key.private_key_base64
        except Exception as e:
            msg = (_("Error decrypting private key: %s") % e)
            return callback.error(msg)

        if aes_key:
            answer = callback.ask("Remove key password? ")
            if answer.lower() == "y":
                remove_key_pass = True

        if remove_key_pass:
            private_key = encode(user_key.private_key_base64, "base64")
            self.private_key = "RSA[%s]" % private_key
        else:
            # Gen new AES key.
            aes_key = aes.gen_key()
            # Try to get encrypted AES key from client.
            aes_key_enc = callback.encrypt(aes_key, use_rsa_key=False)
            # Try to encrypt RSA key.
            try:
                key_encrypted = user_key.encrypt_key(aes_key=aes_key)
            except Exception as e:
                msg = (_("Error encrypting private key: %s") % e)
                return callback.error(msg)
            # Encode keys.
            self._set_key(aes_key_enc, key_encrypted, encrypted=True)

        return self._cache(callback=callback)

    @check_acls(['sign'])
    @object_lock()
    def sign_data(self, data=None, digest=None, aes_key=None,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Sign given data with users private key. """
        if not data and not digest:
            msg = ("Need at least 'data' or 'digest'.")
            raise OTPmeException(msg)
        if self.sign_mode != "server":
            msg = ("Private key is not handled by server.")
            return callback.error(msg)
        if not self.private_key:
            msg = ("User does not have a private key.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("sign",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Try to get private key (e.g. decrypt)
        try:
            private_key = self.get_private_key(decrypt=True,
                                            aes_key=aes_key,
                                            _caller=_caller,
                                            callback=callback)
        except Exception as e:
            return callback.error(str(e))

        # Try to load private key.
        try:
            key = RSAKey(key=private_key)
        except Exception as e:
            msg = (_("Error loading private key: %s") % e)
            return callback.error(msg)
        # Try to sign data.
        try:
            signature = key.sign(message=data, digest=digest)
            signature = encode(signature, "base64")
        except Exception as e:
            msg = (_("Error siging data: %s") % e)
            return callback.error(msg)
        return callback.ok(signature)

    @check_acls(['verify'])
    def verify(self, signature, data=None, digest=None, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Verify given data+message with users public key. """
        if not data and not digest:
            msg = ("Need at least 'data' or 'digest'.")
            raise OTPmeException(msg)
        if self.sign_mode != "server":
            msg = ("Private key is not handled by server.")
            return callback.error(msg)
        if not self.public_key:
            msg = ("User does not have a public key.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("verify",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        try:
            key = RSAKey(key=decode(self.public_key, "base64"))
        except Exception as e:
            msg = (_("Error loading public key: %s") % e)
            return callback.error(msg)
        try:
            key.verify(signature=signature,
                        message=data,
                        digest=digest)
        except Exception as e:
            msg = (_("Error verifying signature: %s") % e)
            return callback.error(msg)
        return callback.ok()

    @check_acls(['encrypt'])
    def encrypt(self, data, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Encrypt given data with users public key. """
        if self.sign_mode != "server":
            return callback.error("Key is not handled by server.")
        if not self.public_key:
            return callback.error("User does not have a private key.")
        if run_policies:
            try:
                self.run_policies("encrypt",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Try to decode public key.
        try:
            public_key = decode(self.public_key, "base64")
        except Exception as e:
            return callback.error("Unable to decode public key.")
        # Try to load public key.
        try:
            key = RSAKey(key=public_key)
        except Exception as e:
            msg = (_("Error loading public key: %s") % e)
            return callback.error(msg)
        # Try to encrypt data.
        try:
            cipher = encode(key.encrypt(data=data), "base64")
        except Exception as e:
            msg = (_("Error encrypting data: %s") % e)
            return callback.error(msg)
        return callback.ok(cipher)

    @check_acls(['decrypt'])
    def decrypt(self, data, aes_key=None, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Decrypt given data with users private key. """
        if self.sign_mode != "server":
            return callback.error("Key is not handled by server.")
        if not self.private_key:
            return callback.error("User does not have a private key.")
        if run_policies:
            try:
                self.run_policies("decrypt",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Try to get private key (e.g. decrypt).
        try:
            private_key = self.get_private_key(decrypt=True,
                                            aes_key=aes_key,
                                            _caller=_caller,
                                            callback=callback)
        except Exception as e:
            return callback.error(str(e))

        # Try to load private key.
        try:
            key = RSAKey(key=private_key)
        except Exception as e:
            msg = (_("Error loading private key: %s") % e)
            return callback.error(msg)
        # Try to decrypt data.
        try:
            decrypted_data = key.decrypt(data=decode(data, "base64"))
        except Exception as e:
            msg = (_("Error decrypting data: %s") % e)
            return callback.error(msg)
        return callback.ok(decrypted_data)

    @object_lock()
    def _handle_acl(self, action, acl, recursive_acls=False,
        apply_default_acls=False, object_types=[], verify_acls=True,
        force=False, verbose_level=0, callback=default_callback, **kwargs):
        """ Method to call inherit_default_acl() for all site units. """
        exception = None

        if action == "add":
            inherit_method = "inherit_default_acl"
        else:
            inherit_method = "disinherit_default_acl"

        if not recursive_acls and not apply_default_acls:
            return callback.ok()

        if object_types and "token" not in object_types:
            return callback.ok()

        for t in self.tokens:
            # Get token.
            token = backend.get_object(object_type="token", uuid=t)
            # Skip orphan tokens.
            if not token:
                continue

            if not force:
                if not token.acl_inheritance_enabled:
                    continue

            if recursive_acls:
                # Get ACL apply IDs.
                apply_id, recursive_apply_id = token.get_acl_apply_ids(acl=acl)

                if apply_id:
                    add_status = token.handle_acl(action=action,
                                        acl=apply_id,
                                        owner_uuid=acl.owner_uuid,
                                        recursive_acls=recursive_acls,
                                        apply_default_acls=apply_default_acls,
                                        verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs)
                    if not add_status:
                        exception = True

            if apply_default_acls:
                token_inherit_method = getattr(token, inherit_method)
                add_status = token_inherit_method(acl=acl,
                                verify_acls=verify_acls,
                                verbose_level=verbose_level,
                                callback=callback)
                if not add_status:
                    exception = True

        if exception:
            return callback.error()
        else:
            return callback.ok()

    def is_admin(self, check_admin_user=True, check_admin_role=True):
        """ Check if the user has admin priviledges. """
        if check_admin_user:
            for token_uuid in self.tokens:
                if token_uuid == config.admin_token_uuid:
                    return True
        if check_admin_role:
            for uuid in self.tokens:
                token = backend.get_object(object_type="token", uuid=uuid)
                if not token:
                    continue
                if token.is_admin():
                    return True
        return False
        # This point should never be reached.
        msg = ("WARNING: You may have hit a BUG of User().is_admin().")
        raise OTPmeException(msg)

    def authenticate(self, **kwargs):
        """ Wrapper to call auth handler. """
        from otpme.lib.classes.auth_handler import AuthHandler
        auth_handler = AuthHandler()
        start_time = time.time()
        auth_status = auth_handler.authenticate(user=self, **kwargs)
        end_time = time.time()
        age = float(end_time - start_time)
        logger.debug("Authentication took %s seconds." % age)
        return auth_status

    def token(self, token_name):
        """ Return token instance. """
        token = backend.get_object(object_type="token",
                                    realm=self.realm,
                                    site=self.site,
                                    user=self.name,
                                    name=token_name)
        if token and token.destination_token:
            token.dst_token = token.get_destination_token()
        return token

    def get_tokens(self, client=None, host=None, access_group=None,
        check_parent_groups=False, resolv_token_links=True,
        check_sf_tokens=False, token_type=None, pass_type=None,
        token_types=None, pass_types=None, skip_disabled=True, quiet=True,
        return_type="uuid", callback=default_callback, _caller="API", **kwargs):
        """
        Return a list with tokens of this user, selected by access_group (and
        its parents if check_parent_groups=True) or all. If access_group (with
        or without check_parent_groups) is set only enabled groups are processed.
        """
        # List to hold tokens.
        tokens = []

        # If we got no token types list but a token type add it to list.
        if token_types is None:
            if token_type != None:
                token_types = [token_type]

        # If we got no pass types list but a pass type add it to list.
        if pass_types is None:
            if pass_type != None:
                pass_types = [pass_type]

        def check_token_types(token, token_types=None, pass_types=None):
            """ Check if token type matches. """
            token_type_matches = False
            token_pass_type_matches = False
            if token_types:
                _token_type = token.token_type
                # Make sure we check linked token if needed.
                if resolv_token_links:
                    if token.destination_token:
                        _token_type = token.dst_token.token_type
            if pass_types:
                _token_pass_type = token.pass_type
                # Make sure we check linked token if needed.
                if resolv_token_links:
                    if token.destination_token:
                        _token_pass_type = token.dst_token.pass_type
            if token_types:
                if _token_type in token_types:
                    token_type_matches = True
            if pass_types:
                if _token_pass_type in pass_types:
                    token_pass_type_matches = True
            if token_types and pass_types:
                if token_type_matches and token_pass_type_matches:
                    return True
            if token_types and not pass_types:
                if token_type_matches:
                    return True
            if not token_types and pass_types:
                if token_pass_type_matches:
                    return True
            return False

        # Walk through all tokens of the user.
        for uuid in self.tokens:
            add_token = False
            # Get token.
            t = backend.get_object(object_type="token",
                                    uuid=uuid)
            if not t:
                continue

            if skip_disabled:
                if not t.enabled:
                    continue

            # Make sure we resolve token links.
            if resolv_token_links:
                # Make sure we load destination tokens.
                if t.destination_token:
                    t.dst_token = t.get_destination_token()
                    if not t.dst_token:
                        continue
                    if skip_disabled:
                        if not t.dst_token.enabled:
                            continue

            # Make sure we resolv token links.
            if resolv_token_links and t.destination_token:
                token_uuid = t.dst_token.uuid
            else:
                token_uuid = t.uuid

            # Check if token is valid.
            token_valid = False
            if access_group:
                if access_group.is_assigned_token(token_uuid):
                    token_valid = True
            elif host:
                if host.is_assigned_token(token_uuid):
                    token_valid = True
            elif client:
                if client.is_assigned_token(token_uuid):
                    token_valid = True
            else:
                token_valid = True

            if not token_valid:
                continue

            # If token type or pass type is set add only
            # matching tokens.
            if token_types or pass_types:
                if check_token_types(token=t,
                                    token_types=token_types,
                                    pass_types=pass_types):
                    add_token = True
                # Check second factor token if requested.
                if check_sf_tokens and t.second_factor_token_enabled:
                    try:
                        sftoken = t.get_sftoken()
                    except Exception as e:
                        continue
                    if check_token_types(token=sftoken,
                                        token_types=token_types,
                                        pass_types=pass_types):
                        add_token = True
            else:
                add_token = True

            if not add_token:
                continue

            if t in tokens:
                continue

            # Append token to list if not already added.
            if not quiet:
                msg = ("Selecting token '%s' based on "
                    "accessgroup '%s'." % (t.name, access_group.name))
                logger.debug(msg)
            tokens.append(t)

        result = []
        for t in tokens:
            if return_type == "instance":
                result.append(t)
            elif return_type == "uuid":
                result.append(t.uuid)
            elif return_type == "read_oid":
                result.append(t.oid.read_oid)
            elif return_type == "full_oid":
                result.append(t.oid.full_oid)
            elif return_type == "name":
                result.append(t.name)
            elif return_type == "rel_path":
                result.append(t.rel_path)

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    def get_roles(self, return_type="name", _caller="API",
        callback=default_callback, **kwargs):
        """ Return list with all roles this user is in. """
        # Get all user tokens.
        token_list = self.get_tokens(return_type="instance")
        # Get roles from tokens.
        result = []
        for x in token_list:
            token_roles = x.get_roles(return_type=return_type)
            # FIXME: how to handle roles from other sites?
            for x in token_roles:
                if x in result:
                    continue
                result.append(x)

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    def get_groups(self, return_type="uuid", _caller="API",
        callback=default_callback, **kwargs):
        """ Return list with all groups this user is in. """
        # Get all user tokens.
        token_list = self.get_tokens(return_type="instance")
        # Get groups from tokens.
        result = []
        for x in token_list:
            token_groups = x.get_groups(return_type=return_type)
            # FIXME: how to handle groups from other sites?
            for g in token_groups:
                if g in result:
                    continue
                result.append(g)

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    def get_access_groups(self, return_type="name", _caller="API",
        callback=default_callback, **kwargs):
        """ Return list with all accessgroups this user is in. """
        # Get all user tokens.
        token_list = self.get_tokens(return_type="instance")
        # Get groups from tokens.
        result = []
        for x in token_list:
            token_groups = x.get_access_groups(return_type=return_type)
            # FIXME: how to handle groups from other sites?
            for g in token_groups:
                if g in result:
                    continue
                result.append(g)

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    def is_blocked(self, access_group, realm, site):
        """ Check if user is blocked. """
        return user_is_blocked(self.uuid, access_group, realm, site)

    def _gen_used_hash(self, string):
        """ Generate MD5 hash of used SLP/SOTP/OTP/pass hash to be saved to backend. """
        # Generate MD5 hash from used SLP/SOTP/OTP/pass hash and salt. We use
        # MD5 here for performance reasons. To increase security the salt
        # is saved encrypted in the user config but as this is only used on
        # server side there should be no security implication with using MD5.
        # The OTPme server already has the token secrets to generate e.g. a OTP.
        # The only thing one could think of as a security problem is that
        # count_fail() saves this hash to the backend to count failed login
        # tries. So if someone types in the wrong static password we do have
        # a less secure hash of it saved for a period of time.
        if not isinstance(string, str):
            raise OTPmeException("Need string")

        x_hash = stuff.gen_md5(string + self.used_pass_salt)

        return x_hash

    def _get_used_sotp(self):
        """ Get users used SOTP/SLP hashes. """
        used_objects = backend.search(object_type="used_sotp",
                                    attribute="user_uuid",
                                    value=self.uuid,
                                    return_attributes=['uuid', 'expiry'])
        return used_objects

    def is_used_sotp(self, hash, challenge=None, response=None):
        """
        Check if given SOTP hash is already used and remove outdated hashes
        from cache.
        """
        from otpme.lib import mschap_util
        # Indicates if SOTP/SLP was already used.
        was_used = False

        # Generate hash.
        _hash = self._gen_used_hash(hash)

        _used = self._get_used_sotp()
        for uuid in _used:
            used_expiry = _used[uuid]['expiry'][0]
            # Check if object has expired.
            if time.time() > used_expiry:
                msg = ("Removing expired used SOTP from backend: %s" % self.name)
                logger.debug(msg)
                used_object = backend.get_object(uuid=uuid)
                if not used_object:
                    continue
                try:
                    used_object.delete(force=True)
                except UnknownObject:
                    pass
                try:
                    multiprocessing.otp_hashes.pop(uuid)
                except KeyError:
                    pass
                continue

            # If we got a challenge/response pair verify it with the used_hash.
            try:
                otp_hash = multiprocessing.otp_hashes[uuid]
            except KeyError:
                used_object = backend.get_object(uuid=uuid)
                if not used_object:
                    return False
                otp_hash = used_object.object_hash
                multiprocessing.otp_hashes[uuid] = otp_hash
            if challenge and response:
                # Verify used_hash with given challenge/response.
                status, nt_key = mschap_util.verify(otp_hash,
                                                    challenge,
                                                    response)
                if status:
                    was_used = True
                    break
            else:
                # Stop processing if we found an already used hash.
                if _hash == otp_hash:
                    was_used = True
                    break
        return was_used

    def add_used_sotp(self, hash):
        """ Add SOTP hash to list of already used hashes for this user. """
        # Generate hash
        _hash = self._gen_used_hash(hash)

        # We want to cache used hashes 1h. We cache SLPs to prevent server
        # load when doing authentication and SOTPs to prevent re-usage of them.
        # For both 1h should be enough.
        # FIXME: make this a config file option???
        cache_time = 3600
        # Get epoch time.
        expiry_timestamp = time.time() + cache_time

        used_object = UsedSOTP(user_uuid=self.uuid,
                                object_hash=_hash,
                                expiry=expiry_timestamp,
                                realm=config.realm,
                                site=config.site,
                                no_transaction=True)
        try:
            used_object.add()
        except AlreadyExists:
            pass
        except LockWaitAbort:
            pass
        except OTPmeException as e:
            msg = "Failed to add used SOTP."
            logger.warning(msg)

    def remove_outdated_failed_pass_hashes(self, access_group):
        """ Remove outdated failed pass hashes of this user. """
        # Get max fail for accessgroup.
        result = backend.search(object_type="accessgroup",
                                    realm=config.realm,
                                    site=config.site,
                                    attribute="name",
                                    value=access_group,
                                    return_attributes=['max_fail'])
        if not result:
            msg = ("Unable to get max fail: Unknown accessgroup: %s"
                    % access_group)
            raise OTPmeException(msg)
        max_fail = result[0]

        # Get max failed pass config parameter.
        max_failed_pass = self.get_config_parameter("failed_pass_history")

        if max_fail > max_failed_pass:
            msg = ("Config parameter <failed_pass_history> overruled "
                    "by <max_fail> of accessgroup %s." % access_group)
            logger.warning(msg)
            max_failed_pass = max_fail
        # Get failed pass hashes.
        failed_pass_list = backend.search(object_type="failed_pass",
                                            attribute="user_uuid",
                                            value=self.uuid,
                                            return_type="instance")

        failed_pass_count = len(failed_pass_list)
        if failed_pass_count >= max_failed_pass:
            x_sort = lambda x: x.last_used
            result = sorted(failed_pass_list, key=x_sort)
            del_failed_pass = failed_pass_count - max_failed_pass
            for x in result[0:del_failed_pass]:
                x.delete()

    # FIXME: make this cluster aware! add shared list and proto to sync this!
    def count_fail(self, pass_hash, access_group):
        """ Increase login failures for user or user/group. """
        # FIXME: NOFIX: One could think count_fail() should be method of
        #               Token() to count failed login tries per token.
        #               But that is not possible because a request does not
        #               contain a token name or UUID. The token is identified
        #               by the given password/OTP and thats not possible if
        #               the password is wrong. :)
        # Get accessgroup UUID.
        result = backend.search(object_type="accessgroup",
                                    realm=config.realm,
                                    site=config.site,
                                    attribute="name",
                                    value=access_group,
                                    return_type="uuid")
        if not result:
            msg = ("Failed login count failed: Unknown accessgroup: %s"
                    % access_group)
            raise OTPmeException(msg)

        ag_uuid = result[0]

        # Generate hash
        _hash = hash_password(password=pass_hash,
                            salt=self.used_pass_salt,
                            hash_type="Argon2_d",
                            iterations=3,
                            encoding="hex",
                            key_len=16,
                            quiet=True)
        _hash = _hash['hash']

        failed_pass = FailedPass(user_uuid=self.uuid,
                                object_hash=_hash,
                                realm=config.realm,
                                site=config.site,
                                accessgroup_uuid=ag_uuid,
                                no_transaction=True)
        # If object already exists there is no need to re-add it.
        # We do not load the object
        if failed_pass.exists(load_object=False):
            # Load object.
            failed_pass._load()
            # Update last used timestamp.
            failed_pass.update_last_used_time()
            return True

        logger.debug("Counting failed login for this request.")

        # Write used pass hash config to backend.
        try:
            failed_pass.add()
            failed_pass.update_last_used_time()
            self.remove_outdated_failed_pass_hashes(access_group)
            return True
        except Exception as e:
            msg = ("Error counting failed login attempt: %s: %s"
                            % (self.oid, e))
            logger.critical(msg)
            return False

    def failcount(self, access_group):
        """ Return user or user/group failed login count. """
        return user_failcount(self.uuid, access_group)

    @check_acls(['unblock'])
    @backend.transaction
    def unblock(self, access_group=None, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Unblock user. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("unblock",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if access_group:
            group_oid = oid.get(object_type="accessgroup",
                                        realm=config.realm,
                                        site=config.site,
                                        name=access_group)
            group_uuid = backend.get_uuid(group_oid)
            if not group_uuid:
                msg = ("Unknown accessgroup: %s" % access_group)
                return callback.error(msg)
            group_list = [group_uuid]
        else:
            group_list = backend.search(object_type="accessgroup",
                                        attribute="uuid",
                                        value="*",
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)

        # Get all failed login objects for this user.
        failed_list = backend.search(object_type="failed_pass",
                                    attribute="user_uuid",
                                    value=self.uuid,
                                    return_type="instance")
        for x in failed_list:
            if x.accessgroup_uuid not in group_list:
                continue
            x.delete()

        return callback.ok()

    @check_acls(['deploy:token'])
    @object_lock(full_lock=True)
    @backend.transaction
    def deploy_token(self, token_name, token_type, smartcard_type,
        replace=False, deploy_data=None, pre_deploy=False, force=False,
        run_policies=True,verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Deploy existing or new token. """
        if not deploy_data and not pre_deploy:
            msg = ("Need at least 'pre_deploy' or 'deploy_data'!")
            raise OTPmeException(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("deploy_token",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        token = backend.get_object(object_type="token",
                                    realm=self.realm,
                                    site=self.site,
                                    user=self.name,
                                    name=token_name)
        if not token:
            from otpme.lib.token import get_class
            token_types = config.get_sub_object_types("token")
            for x in token_types:
                try:
                    token_module = x.replace("-", "_")
                    token_class = get_class(token_module)
                    try:
                        _token = token_class(name=token_name,
                                            user=self.name,
                                            realm=self.realm,
                                            site=self.site)
                    except Exception as e:
                        msg = "Failed to load token class: %s" % e
                        return callback.error(msg)
                    # Stop if we found a token class that supports the given
                    # hardware token type.
                    if smartcard_type in _token.supported_hardware_tokens:
                        token = _token
                        break
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Problem loading token type '%s': %s") % (x, e))
                    return callback.error(msg)

        if not token:
            msg = (_("Unable to find token class to deploy hardware token: %s")
                        % token_type)
            return callback.error(msg)

        if token.exists():
            if replace:
                if not self.add_token(token_name=token_name,
                                    token_type=token_type,
                                    replace=replace,
                                    force=True,
                                    _caller=_caller,
                                    callback=callback):
                    return callback.error("Error replacing token.")
            else:
                if not smartcard_type in token.supported_hardware_tokens:
                    msg = (_("Existing token '%s (%s)' does not support hardware token "
                            "type: %s") % (token.rel_path, token.token_type, smartcard_type))
                    return callback.error(msg)
                if not force:
                    ask = callback.ask("Re-deploy existing token? ")
                    if str(ask).lower() != "y":
                        return callback.abort()
        else:
            if pre_deploy:
                if not self.verify_acl("add:token"):
                    msg = ("Permission denied.")
                    return callback.error(msg, exception=PermissionDenied)
            if _caller == "CLIENT" and verbose_level > 0:
                msg = (_("Creating new token of type '%s' to deploy "
                        "token: %s") % (token.token_type, token_type))
                callback.send(msg)
            if not self.add_token(token_name=token_name,
                                token_type=token_type,
                                force=True,
                                _caller=_caller,
                                callback=callback):
                return callback.error("Error creating token object.")
            # Override token test instance with new created token.
            token = self.token(token_name)

        deploy_args = {}
        if deploy_data:
            try:
                deploy_args = json.decode(deploy_data, encoding="hex")
            except:
                config.raise_exception()
                return callback.error("Error decoding token data.")

        if pre_deploy:
            return token.pre_deploy(verbose_level=verbose_level,
                            callback=callback,
                            _caller=_caller,
                            **deploy_args)

        if not token.deploy(verbose_level=verbose_level,
                            callback=callback,
                            _caller=_caller,
                            **deploy_args):
            return callback.error("Error deploying token.")
        return callback.ok()

    @check_acls(['add:token'])
    @object_lock()
    @backend.transaction
    def add_token(self, token_name=None, token_type=None, token_uuid=None,
        new_token=None, destination_token=None, replace=False, gen_qrcode=True,
        no_token_infos=False, token_store_move=False, force=False, enable_mschap=False,
        run_policies=True, verify_acls=True, verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Adds token to user. """
        if self.template_object:
            msg = "Cannot add token to template user."
            return callback.error(msg)

        destination_token_uuid = None
        send_new_token_message = False
        if not token_store_move:
            if self.name == config.token_store_user:
                if token_name is None:
                    # Find free token name.
                    while True:
                        # Generate token name (lowercase letters and numbers).
                        token_name = stuff.gen_password(len=8, capital=False)
                        token_path = "%s/%s" % (self.name, token_name)
                        result = backend.search(object_type="token",
                                                attribute="rel_path",
                                                value=token_path,
                                                return_type="uuid")
                        if not result:
                            break
                    send_new_token_message = True

        if token_name is None:
            msg = "Need <token_name>."
            return callback.error(msg)

        if not new_token:
            if not token_type:
                token_type = self.get_config_parameter("default_token_type")

            if token_type == "link" and not destination_token:
                msg = (_("Please give link destination."))
                return callback.error(msg)

            if token_type == "link":
                result = backend.search(object_type="token",
                                        attribute="rel_path",
                                        value=destination_token,
                                        return_type="uuid")

                if not result:
                    msg = (_("Token does not exist: %s") % destination_token)
                    return callback.error(msg)

                destination_token_uuid = result[0]

                dst_token = backend.get_object(object_type="token",
                                        uuid=destination_token_uuid)

                if not dst_token:
                    msg = (_("Destination token does not exist."))
                    return callback.error(msg)

                if dst_token.token_type == "link":
                    msg = (_("Cannot link already linked token."))
                    return callback.error(msg)

                if not dst_token.cross_site_links:
                    site_trusted = stuff.get_site_trust_status(dst_token.realm,
                                                                dst_token.site)
                    if not site_trusted:
                        msg = (_("Token does not support cross site "
                                "links: %s") % dst_token.rel_path)
                        return callback.error(msg)

        # Check if given token exists.
        token_path = "%s/%s" % (self.name, token_name)
        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                return_type="instance")
        cur_token = None
        if result:
            cur_token = result[0]

        if replace:
            if not cur_token:
                return callback.error("Token does not exist.")
            if not force:
                if self.confirmation_policy != "force":
                    ask = callback.ask("Replace existing token?: ")
                    if str(ask).lower() != "y":
                        return callback.abort()
            # On replace we have to use the token UUID from the replaced token
            # to create the new one.
            token_uuid = cur_token.uuid
            # Delete used OTPs and counters of the old token.
            cur_token.delete_used_data_objects()
            # Remove token object from backend WITHOUT removing its UUID from
            # any role etc.
            try:
                backend.delete_object(cur_token.oid)
            except Exception as e:
                config.raise_exception()
                msg = (_("Error removing token '%s': %s") % (cur_token.name, e))
                return callback.error(msg)
        else:
            if cur_token and not new_token:
                msg = (_("Token already exists: %s") % cur_token.rel_path)
                return callback.error(msg)

        if not new_token:
            # Try to create new token instance.
            try:
                from otpme.lib.token import get_class
                token_class = get_class(token_type)
                new_token = token_class(name=token_name,
                                    user=self.name,
                                    realm=self.realm,
                                    site=self.site)
            except ImportError:
                msg = "Unknown token type: %s" % token_type
                return callback.error(msg)
            except Exception as e:
                msg = (_("Problem loading token type '%s': %s")
                                % (token_type, e))
                return callback.error(msg)

            # Add the new token.
            add_status = new_token.add(uuid=token_uuid,
                                    owner_uuid=self.uuid,
                                    gen_qrcode=gen_qrcode,
                                    enable_mschap=enable_mschap,
                                    run_policies=run_policies,
                                    verify_acls=verify_acls,
                                    no_token_infos=no_token_infos,
                                    destination_token_uuid=destination_token_uuid,
                                    verbose_level=verbose_level,
                                    force=True,
                                    callback=callback,
                                    _caller=_caller)
            if not add_status:
                return callback.error("Error creating token object.")

        # When replacing a token we just need to copy some token settings.
        if replace:
            new_token.acls = cur_token.acls
            new_token.acl_inheritance_enabled = cur_token.acl_inheritance_enabled
            if new_token.allow_offline is not None:
                new_token.allow_offline = cur_token.allow_offline
            if new_token.offline_expiry is not None:
                new_token.offline_expiry = cur_token.offline_expiry
            if new_token.offline_unused_expiry is not None:
                new_token.offline_unused_expiry = cur_token.offline_unused_expiry
            if new_token.keep_session is not None:
                new_token.keep_session = cur_token.keep_session
            if new_token.auth_script is not None:
                new_token.auth_script = cur_token.auth_script
            if new_token.auth_script_enabled is not None:
                new_token.auth_script_enabled = cur_token.auth_script_enabled
            # FIXME: does calling _cache() work?
            ## Write new token config.
            #lock_caller = "replace_token"
            #new_token.acquire_lock(lock_caller=lock_caller,
            #                        callback=callback)
            ##add_result = new_token._write(callback=callback)
            #new_token.release_lock(lock_caller=lock_caller, callback=callback)
            add_result = new_token._cache(callback=callback)
            return add_result

        # Append new token UUID to tokens variable of the user.
        self.tokens.append(new_token.uuid)
        # Update index.
        self.add_index('token', new_token.uuid)

        # Set default token.
        if self.name != config.token_store_user:
            default_token_name = self.get_config_parameter('default_token_name')
            if new_token.name == default_token_name:
                self.default_token = new_token.uuid
                ## Allow realm logins via default token.
                #result = backend.search(object_type="role",
                #                        attribute="name",
                #                        value=config.realm_user_role,
                #                        realm=self.realm,
                #                        site=self.site,
                #                        return_type="instance")
                #realm_user_role = result[0]
                #realm_user_role.add_token(token_path=new_token.rel_path,
                #                        verify_acls=False, callback=callback)

        if send_new_token_message:
            msg = "Added token: %s/%s" % (self.name, new_token.name)
            callback.send(msg)

        return self._cache(callback=callback)

    @object_lock()
    @backend.transaction
    def del_token(self, token_name, force=False, keep_token=False,
        run_policies=True, remove_default_token=False,
        callback=default_callback, _caller="API", **kwargs):
        """ Delete user token. """
        token = self.token(token_name)
        if not token:
            return callback.error("Token does not exist.")

        # FIXME: do we need this??? how to handle ACLs on token delete???
        # Check if the authenticated user tries to delete one of its own tokens.
        check_acls = True
        if config.auth_token:
            if config.auth_token.owner_uuid == self.uuid:
                check_acls = False

        if check_acls:
            if not self.verify_acl("delete:token"):
                if not token.verify_acl("delete:object"):
                    msg = ("Permission denied: %s" % token)
                    return callback.error(msg, exception=PermissionDenied)

        # Check for default token
        if self.default_token is not None:
            result = backend.search(object_type="token",
                                    attribute="uuid",
                                    value=self.default_token,
                                    return_attributes=['name'])
            if result:
                default_token_name = result[0]
                if token_name == default_token_name:
                    if not remove_default_token:
                        msg = ("Cannot remove default token. Please set a new default "
                                "token first.")
                        return callback.error(msg)
                    self.default_token = None

        check_login_token = False
        if config.auth_token:
            check_login_token = True
            if force and config.auth_token.is_admin():
                check_login_token = False

        if check_login_token:
            msg = (_("Cannot delete token used at login."))
            if token.uuid == config.auth_token.uuid:
                return callback.error(msg)
            if config.auth_token.destination_token:
                dst_token = config.auth_token.get_destination_token()
                if dst_token:
                    if dst_token.uuid == config.auth_token.uuid:
                        return callback.error(msg)

        if not keep_token:
            # Delete token.
            del_status = token.delete(callback=callback,
                                    run_policies=run_policies,
                                    force=force,
                                    **kwargs)
            # Check if user aborted token deletion.
            if del_status is None:
                return callback.abort()
            if not del_status:
                return callback.error()

        # Del ACL with view access to the token owner for the deleted token.
        acl = "token:%s:view" % token.uuid
        self.del_acl(acl=acl, verify_acls=False, callback=callback, **kwargs)

        # Remove token UUID from tokens variable of this user.
        try:
            self.tokens.remove(token.uuid)
        except ValueError:
            pass
        # Update index.
        self.del_index('token', token.uuid)

        return self._cache(callback=callback)

    @check_acls(['enable:disabled_login'])
    @object_lock()
    def enable_disabled_login(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable user disabled login. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_disabled_login",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.allow_disabled_login = True

        return self._cache(callback=callback)

    @check_acls(['disable:disabled_login'])
    @object_lock()
    def disable_disabled_login(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable user disabled login. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_disabled_login",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.allow_disabled_login = False

        return self._cache(callback=callback)

    @check_acls(['enable:autosign'])
    @object_lock()
    def enable_autosign(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable user auto-sign feature. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_autosign",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.autosign_enabled = True

        return self._cache(callback=callback)

    @check_acls(['disable:autosign'])
    @object_lock()
    def disable_autosign(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable user auto-sign feature. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_autosign",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.autosign_enabled = False

        return self._cache(callback=callback)

    @check_acls(['enable:auth_script'])
    @object_lock()
    def enable_auth_script(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable user auth script. """
        if not self.auth_script:
            msg = "Auth script not configured."
            return callback.error(msg)

        x = backend.get_object(object_type="script",
                            uuid=self.auth_script)
        if not x:
            msg = (_("Script does not exist: %s") % self.auth_script)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_auth_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Check if auth_script is already enabled.
        if self.auth_script_enabled:
            msg = (_("Authorization script already enabled for this user."))
            return callback.error(msg)

        self.auth_script_enabled = True
        self.update_index('auth_script_enabled', self.auth_script_enabled)

        return self._cache(callback=callback)

    @check_acls(['disable:auth_script'])
    @object_lock()
    def disable_auth_script(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable user auth script. """
        # Check if auth_script is already disabled.
        if not self.auth_script_enabled:
            msg = (_("Authorization script already disabled for this user."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_auth_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.auth_script_enabled = False
        self.update_index('auth_script_enabled', self.auth_script_enabled)

        return self._cache(callback=callback)

    @check_acls(['enable:login_script'])
    @object_lock()
    def enable_login_script(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable user login script. """
        if not self.login_script:
            msg = "Login script not configured."
            return callback.error(msg)

        x = backend.get_object(object_type="script", uuid=self.login_script)
        if not x:
            msg = (_("Script does not exist: %s") % self.login_script)
            return callback.error(msg)

        # Check if login_script is already enabled.
        if self.login_script_enabled:
            msg = (_("Login script already enabled for this user."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_login_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.login_script_enabled = True

        return self._cache(callback=callback)

    @check_acls(['disable:login_script'])
    @object_lock()
    def disable_login_script(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable user login script. """
        # Check if login_script is already disabled.
        if not self.login_script_enabled:
            msg = (_("Login script already disabled for this user."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_login_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.login_script_enabled = False

        return self._cache(callback=callback)

    @check_acls(['edit:key_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    def change_key_script(self, key_script=None, script_options=None,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Change user key script. """
        if script_options:
            script_options = script_options.split(" ")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_key_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        return self.change_script(script_var='key_script',
                        script_options_var='key_script_options',
                        script_options=script_options,
                        script=key_script, callback=callback)

    @check_acls(['edit:agent_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    def change_agent_script(self, agent_script=None, script_options=None,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Change user agent script. """
        if script_options:
            script_options = script_options.split(" ")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_agent_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        return self.change_script(script_var='agent_script',
                        script_options_var='agent_script_options',
                        script_options=script_options,
                        script=agent_script, callback=callback)

    @check_acls(['edit:login_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    def change_login_script(self, login_script=None, script_options=None,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Change user login script. """
        if script_options:
            script_options = script_options.split(" ")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_login_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        return self.change_script(script_var='login_script',
                        script_options_var='login_script_options',
                        script_options=script_options,
                        script=login_script, callback=callback)

    @check_acls(['edit:auth_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    def change_auth_script(self, auth_script=None, script_options=None,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Change user auth script. """
        if script_options:
            script_options = script_options.split(" ")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_auth_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        return self.change_script(script_var='auth_script',
                        script_options_var='auth_script_options',
                        script_options=script_options,
                        script=auth_script, callback=callback)

    @check_special_user()
    @object_lock(full_lock=True)
    @backend.transaction
    def rename(self, new_name, callback=default_callback, _caller="API", **kwargs):
        """ Rename user. """
        if config.auth_token:
            if config.auth_token.owner_uuid == self.uuid:
                return callback.error("You cannot rename yourself. :)")

        if self.name == config.admin_user_name:
            return callback.error("Cannot rename admin user.")

        result = backend.search(object_type="user",
                                attribute="name",
                                value=new_name)
        if result:
            user_uuid = result[0]
            user_oid = backend.get_oid(user_uuid)
            msg = "User already exists: %s" % user_oid
            return callback.error(msg)

        # Get user sessions.
        sessions = backend.get_sessions(user=self.uuid)
        if len(sessions) > 0:
            return callback.error("Cannot rename user with active sessions.")

        # Build new OID.
        new_oid = oid.get(object_type="user",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)

        rename_result = self._rename(new_oid=new_oid,
                                    callback=callback,
                                    _caller=_caller,
                                    **kwargs)
        # Update user tokens.
        for token_uuid in self.tokens:
            token = backend.get_object(object_type="token", uuid=token_uuid)
            token.user = self.name
            token.path = "%s/%s" % (self.name, token.name)
            token.set_path()
            token.set_oid()
            token._write(callback=callback)

        return rename_result

    @object_lock(full_lock=True)
    @backend.transaction
    @one_time_policy_run
    @run_pre_post_add_policies()
    def add(self, group=None, add_default_token=None, default_token=None,
        default_token_type=None, template_name=None, template_object=None,
        gen_qrcode=True, no_token_infos=False, run_policies=True, force=False,
        verify_acls=True, groups=None, default_roles=None, ldif_attributes=None,
        _caller="API", verbose_level=0, callback=default_callback, **kwargs):
        """ Add user. """
        # Check if user exist on any site.
        result = backend.search(object_type="user",
                                attribute="name",
                                value=self.name,
                                return_type="oid")
        if result:
            user_oid = result[0]
            msg = "User already exists: %s" % user_oid
            return callback.error(msg)

        # Get default token settings.
        if add_default_token is None:
            # No need to add default token for base users.
            base_users = config.get_base_objects("user")
            if self.name in base_users:
                add_default_token = False
            else:
                add_default_token = self.get_config_parameter('add_default_token')

        default_token_name = self.get_config_parameter('default_token_name')
        if default_token_type is None:
            default_token_type = self.get_config_parameter('default_token_type')
        if default_token is not None:
            add_default_token = True

        # Set template status.
        if template_object is not None:
            self.template_object = template_object

        if self.template_object:
            add_default_token = False

        if add_default_token:
            try:
                from otpme.lib.token import get_class
                get_class(default_token_type)
            except ImportError:
                msg = "Unknown token type: %s" % default_token_type
                return callback.error(msg)

        _groups = []
        if groups is not None:
            for group_name in groups:
                result = backend.search(object_type="group",
                                        attribute="name",
                                        value=group_name,
                                        realm=self.realm,
                                        site=self.site,
                                        return_type="instance")
                if not result:
                    msg = "Unknown group: %s" % group_name
                    return callback.error(msg)
                _group = result[0]
                if verify_acls:
                    if not _group.verify_acl("add:token"):
                        msg = "Group: %s: Permission denied" % group_name
                        return callback.error(msg)
                # Acquire lock.
                #_group._cache(callback=callback)
                _groups.append(_group)

        _default_roles = []
        if default_roles is not None:
            for role_name in default_roles:
                result = backend.search(object_type="role",
                                        attribute="name",
                                        value=role_name,
                                        realm=self.realm,
                                        site=self.site,
                                        return_type="instance")
                if not result:
                    msg = "Unknown role: %s" % role_name
                    return callback.error(msg)
                _role = result[0]
                if verify_acls:
                    if not _role.verify_acl("add:token"):
                        msg = "Role: %s: Permission denied" % role_name
                        return callback.error(msg)
                # Acquire lock.
                #_role._cache(callback=callback)
                _default_roles.append(_role)

        # Handle default token from TOKENSTORE.
        _default_token = None
        if add_default_token:
            if default_token:
                default_token_path = ("%s/%s"
                                    % (config.token_store_user,
                                    default_token))
                result = backend.search(object_type="token",
                                        attribute="rel_path",
                                        value=default_token_path,
                                        return_type="instance",
                                        realm=self.realm,
                                        site=self.site)
                if not result:
                    msg = "Unknown token: %s" % default_token_path
                    return callback.error(msg)
                _default_token = result[0]

        if self.template_object and template_name:
            msg = "Cannot create template from template."
            return callback.error(msg)

        # Get template name set by policy.
        if template_name is None:
            template_name = self.template_name

        # Get template.
        template = None
        if template_name:
            template = backend.get_object(object_type="user",
                                        realm=self.realm,
                                        site=self.site,
                                        name=template_name)
            if not template:
                msg = "Unknown template: %s" % template_name
                return callback.error(msg)

        # If no group is given but a template, prever templates group
        # over any defaultgroups policy.
        if group is None:
            if template:
                group = template.group

        run_group_policies = False
        if group is None:
            run_group_policies = True
            if self.name == config.admin_user_name:
                group = config.admin_group
            else:
                group = config.users_group

        # Check for given group.
        default_group = None
        if group is not None:
            result = backend.search(object_type="group",
                                    attribute="name",
                                    value=group,
                                    return_type="instance")
            if not result:
                msg = "Unknown group: %s" % group
                return callback.error(msg)
            default_group = result[0]
            if verify_acls:
                if not default_group.verify_acl('add:default_group_user'):
                    msg = "Group: %s: Permission denied" % group
                    return callback.error(msg)

        check_exists = True
        if force:
            check_exists = False
        if template is not None:
            check_exists = False

        if not config.realm_init:
            if self.name == config.admin_user_name:
                check_exists = False
            if self.name == config.token_store_user:
                check_exists = False

        if not check_exists and not force:
            if backend.object_exists(self.oid, realm=config.realm, site=config.site):
                msg = (_("%s%s already exists.")
                    % (self.type[0].upper(), self.type[1:]))
                return callback.error(msg)

        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(template=template,
                                callback=callback,
                                verify_acls=verify_acls,
                                verbose_level=verbose_level,
                                run_policies=run_policies,
                                check_exists=check_exists,
                                **kwargs)
        if result is False:
            return callback.error()

        # Generate salt for used OTP/pass hashes.
        self.used_pass_salt = stuff.gen_secret(32)

        try:
            inherit_status = self.inherit_acls(force=True,
                                            verify_acls=False,
                                            verbose_level=verbose_level,
                                            callback=callback)
            inherit_error = ""
        except Exception as e:
            config.raise_exception()
            inherit_status = False
            inherit_error = (_("WARNING: Unable to inherit ACLs from parent "
                                "object: %s") % e)
        if not inherit_status:
            return callback.error(inherit_error)

        # If no group and not template group is given run policies (e.g. defaultgroups).
        if run_group_policies:
            policy_hook = "set_default_group"
            parent_object = self.get_parent_object()
            try:
                self._run_parent_object_policies(policy_hook,
                                                parent_object=parent_object,
                                                child_object=self,
                                                callback=callback,
                                                _caller=_caller)
            except PolicyException as e:
                msg = str(e)
                return callback.error(msg)
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        # If not group was set by policies set default users group.
        if self.group is None:
            try:
                self._change_group(default_group.uuid,
                                verify_acls=verify_acls,
                                callback=callback)
            except UnknownObject as e:
                msg = str(e)
                return callback.error(msg, exception=UnknownObject)
            except PermissionDenied as e:
               msg = "Permission denied while setting group."
               return callback.error(msg, exception=PermissionDenied)

        # Handle given LDIF attributes.
        default_attributes = {}
        if ldif_attributes:
            try:
                default_extensions = config.default_extensions[self.type]
            except:
                default_extensions = []
            for ext in default_extensions:
                ext_attrs = config.get_ldif_attributes(ext, self.type)
                for x in ldif_attributes.split(","):
                    try:
                        attr = x.split("=")[0]
                        value = x.split("=")[1]
                    except:
                        msg = "Invalid attribute: %s" % x
                        return callback.error(msg)
                    if attr not in ext_attrs:
                        continue
                    if ext not in default_attributes:
                        default_attributes[ext] = {}
                    default_attributes[ext][attr] = value

        # Add object using parent class BEFORE adding any token etc.
        add_result = super(User, self).add(template=template,
                                        run_policies=False,
                                        inherit_acls=False,
                                        default_attributes=default_attributes,
                                        verbose_level=verbose_level,
                                        callback=callback, **kwargs)
        if not add_result:
            return add_result

        # Make sure user has displayName attribute.
        self.add_attribute(attribute="displayName")

        # Internal users (e.g. TOKENSTORE) do not need any scripts etc.
        internal_users = config.get_internal_objects("user")
        if self.name in internal_users:
            return callback.ok()

        # Set default key script.
        if template:
            result = backend.search(object_type="script",
                                    attribute="uuid",
                                    value=template.key_script,
                                    return_type="rel_path",
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                msg = ("Unable to find template key script: %s"
                        % template.key_script)
                return callback.error(msg)
            default_key_script = result[0]
        else:
            default_key_script = self.get_config_parameter("default_key_script")
        if verbose_level > 0:
            msg = (_("Setting default key script: %s")
                    % default_key_script)
            callback.send(msg)
        self.change_key_script(default_key_script,
                                verify_acls=False,
                                callback=callback)
        # Set default agent script.
        if template:
            result = backend.search(object_type="script",
                                    attribute="uuid",
                                    value=template.agent_script,
                                    return_type="rel_path",
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                msg = ("Unable to find template agent script: %s"
                        % template.agent_script)
                return callback.error(msg)
            default_agent_script = result[0]
        else:
            default_agent_script = self.get_config_parameter("default_agent_script")
        if verbose_level > 0:
            msg = (_("Setting default agent script: %s")
                    % default_agent_script)
            callback.send(msg)
        self.change_agent_script(default_agent_script,
                                verify_acls=False,
                                callback=callback)

        # Set default login script.
        if template:
            result = backend.search(object_type="script",
                                    attribute="uuid",
                                    value=template.login_script,
                                    return_type="rel_path",
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                msg = ("Unable to find template login script: %s"
                        % template.login_script)
                return callback.error(msg)
            default_login_script = result[0]
        else:
            default_login_script = self.get_config_parameter("default_login_script")
        if verbose_level > 0:
            msg = (_("Setting default login script: %s")
                    % default_login_script)
            callback.send(msg)
        self.change_login_script(default_login_script,
                                verify_acls=False,
                                callback=callback)
        # Set login script enabled status.
        if template:
            if template.login_script_enabled != self.login_script_enabled:
                if template.login_script_enabled:
                    self.enable_login_script()
                else:
                    self.disable_login_script()
        # Set default auth script.
        if template:
            result = backend.search(object_type="script",
                                    attribute="uuid",
                                    value=template.auth_script,
                                    return_type="rel_path",
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                msg = ("Unable to find template auth script: %s"
                        % template.auth_script)
                return callback.error(msg)
            default_auth_script = result[0]
        else:
            default_auth_script = self.get_config_parameter("default_auth_script")
        if verbose_level > 0:
            msg = (_("Setting default auth script: %s")
                    % default_auth_script)
            callback.send(msg)
        self.change_auth_script(default_auth_script,
                                verify_acls=False,
                                callback=callback)
        # Set auth script enabled status.
        if template:
            if template.auth_script_enabled != self.auth_script_enabled:
                if template.auth_script_enabled:
                    self.enable_auth_script()
                else:
                    self.disable_auth_script()

            # Handle auto sign setting
            if template.autosign_enabled != self.autosign_enabled:
                if template.autosign_enabled:
                    self.disable_autosign(force=True, callback=callback)
                else:
                    self.enable_autosign(force=True, callback=callback)

        self._cache(callback=callback)

        # Add default token.
        if add_default_token:
            if default_token:
                new_token_path = "%s/%s" % (self.name, default_token_name)
                _default_token.move(new_token_path,
                                    verify_acls=verify_acls,
                                    callback=callback)
            else:
                self.add_token(token_name=default_token_name,
                                token_type=default_token_type,
                                no_token_infos=no_token_infos,
                                gen_qrcode=gen_qrcode,
                                verify_acls=False,
                                force=force,
                                callback=callback)
            # Add default token to default roles.
            _default_token = self.token(default_token_name)
            for role in _default_roles:
                role.add_token(token_path=_default_token.rel_path,
                                verify_acls=verify_acls,
                                callback=callback)
            if _groups:
                # Add token to given groups.
                for _group in _groups:
                    _group.add_token(token_path=_default_token.rel_path,
                                    verify_acls=verify_acls,
                                    callback=callback)
            else:
                # If no groups are given run policies (e.g. defaultgroups).
                policy_hook = "set_groups"
                parent_object = self.get_parent_object()
                try:
                    self._run_parent_object_policies(policy_hook,
                                                    parent_object=parent_object,
                                                    child_object=self,
                                                    callback=callback,
                                                    _caller=_caller)
                except PolicyException as e:
                    msg = str(e)
                    return callback.error(msg)
                except Exception as e:
                    config.raise_exception()
                    msg = str(e)
                    return callback.error(msg)

        # Run post policies ALSO BEFORE adding token (e.g. tokenacls).
        if run_policies:
            super(User, self)._run_post_add_policies(verbose_level=verbose_level,
                                                    callback=callback, **kwargs)

        # Non-admin users are done here.
        if self.name != config.admin_user_name:
            return self._write(callback=callback)

        # Get admin token.
        admin_token = self.token(token_name=default_token_name)

        # Add token to SITE_ADMIN role.
        result = backend.search(object_type="role",
                                attribute="name",
                                value=config.site_admin_role,
                                return_type="instance",
                                realm=config.realm,
                                site=config.site)
        if not result:
            msg = (_("Unable to find %s role.") % config.site_admin_role)
            return callback.error(msg)

        site_admin_role = result[0]

        site_admin_role.add_token(token_path=admin_token.rel_path,
                                    verify_acls=verify_acls,
                                    callback=callback)

        # Add allow all ACL for admin token to own site.
        mysite = backend.get_object(object_type="site", uuid=config.site_uuid)
        acl = "token:%s:all" % admin_token.uuid
        mysite.add_acl(acl=acl,
                        recursive_acls=False,
                        apply_default_acls=False,
                        verify_acls=False,
                        verbose_level=1,
                        callback=callback)

        return self._write(callback=callback)

    @check_special_user()
    @object_lock(recursive=True, full_lock=True)
    @backend.transaction
    def delete(self, force=False, verify_acls=True, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete user. """
        internal_users = config.get_internal_objects("user")
        if self.name in internal_users:
            msg = "Cannot delete internal user: %s" % self.name
            return callback.error(msg)

        if self.name == config.admin_user_name:
            return callback.error("Cannot delete admin user.")
        else:
            if config.auth_token:
                if config.auth_token.owner_uuid == self.uuid:
                    return callback.error("You cannot delete yourself. :)")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)
                # FIXME: do we need this check? allow deletion of user without permission to tokens???
                if not self.verify_acl("delete:token"):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if not self.exists():
            return callback.error("User does not exist.")

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        token_list = self.get_tokens(return_type="instance")
        token_list_names = [i.name for i in token_list]

        if not force:
            if token_list:
                if self.confirmation_policy != "force":
                    if self.confirmation_policy == "paranoid":
                        msg = (_("User has tokens: %(token_list)s\n"
                                "Please type '%(user_name)s' to delete object: ")
                                % {"user_name":self.name,
                                "token_list":", ".join(token_list_names)})
                        response = callback.ask(msg)
                        if response != self.name:
                            return callback.abort()
                    else:
                        msg = (_("User has tokens: %(token_list)s\n"
                                "Delete user '%(user_name)s'?: ")
                                % {"user_name":self.name,
                                "token_list":", ".join(token_list_names)})
                        response = callback.ask(msg)
                        if str(response).lower() != "y":
                            return callback.abort()
            else:
                if self.confirmation_policy == "paranoid":
                    msg = (_( "Please type '%(user_name)s' to delete object: ")
                            % {"user_name":self.name})
                    response = callback.ask(msg)
                    if response != self.name:
                        return callback.abort()

        # Remove user from group.
        if self.group_uuid:
            default_group = backend.get_object(uuid=self.group_uuid)
            default_group.remove_default_group_user(self.uuid,
                                            verify_acls=False,
                                            ignore_missing=True)

        # Delete user sessions.
        session_list = backend.get_sessions(user=self.uuid,
                                        return_type="instance")
        for session in session_list:
            session.delete(force=True, recursive=True, verify_acls=False)

        # Delete user tokens.
        for token in token_list:
            token_del_status = token.delete(force=True,
                                        verify_acls=False,
                                        remove_default_token=True,
                                        callback=callback,
                                        **kwargs)
            if not token_del_status:
                msg = (_("Unable to remove token: %s") % token.name)
                return callback.error(msg)
            self.tokens.remove(token.uuid)

        # Remove used SOTPs.
        _used = self._get_used_sotp()
        for uuid in _used:
            used_oid = backend.get_oid(uuid)
            used_oid = oid.get(used_oid)
            try:
                backend.delete_object(used_oid)
            except Exception as e:
                msg = ("Error removing used SOTP '%s' from backend: %s"
                        % (used_object, e))
                logger.critical(msg)

        # Make sure to remove user from signers cache.
        sign_key_cache.del_cache(self.oid)

        # Delete object using parent class.
        del_status = super(User, self).delete(verbose_level=verbose_level,
                                            force=force, callback=callback)
        return del_status

    @check_acls(['remove:orphans'])
    @object_lock()
    @backend.transaction
    def remove_orphans(self, force=False, run_policies=True, verbose_level=0,
        recursive=False, callback=default_callback, _caller="API", **kwargs):
        """ Remove orphan UUIDs. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_orphans",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        remove_orphans = True
        acl_list = self.get_orphan_acls()
        policy_list = self.get_orphan_policies()

        token_list = []
        token_uuids = self.tokens
        for i in token_uuids:
            token_oid = backend.get_oid(object_type="token", uuid=i)
            if not token_oid:
                token_list.append(i)

        if not force:
            msg = ""
            if acl_list:
                msg = (_("%s|%s: Found the following orphan ACLs: %s\n")
                    % (self.type, self.name, ",".join(acl_list)))

            if policy_list:
                msg = (_("%s|%s: Found the following orphan policies: %s\n")
                    % (self.type, self.name, ",".join(policy_list)))

            if token_list:
                msg = (_("%s|%s: Found the following orphan token UUIDs: %s\n")
                    % (self.type, self.name, ",".join(token_list)))

            if msg:
                answer = callback.ask(_("%sRemove?: ") % msg)
                if answer.lower() != "y":
                    remove_orphans = False

        object_changed = False
        if remove_orphans:
            if acl_list:
                if self.remove_orphan_acls(force=True,
                                        verbose_level=verbose_level,
                                        callback=callback, **kwargs):
                    object_changed = True

            if policy_list:
                if self.remove_orphan_policies(force=True,
                                        verbose_level=verbose_level,
                                        callback=callback, **kwargs):
                    object_changed = True

            for i in token_list:
                if verbose_level > 0:
                    msg = (_("Removing orphan token UUID: %s") % i)
                    callback.send(msg)
                object_changed = True
                if i in self.tokens:
                    self.tokens.remove(i)

        if recursive:
            for i in self.tokens:
                token = backend.get_object(object_type="token", uuid=i)
                if token.remove_orphans(force=force,
                                        callback=callback,
                                        verbose_level=verbose_level,
                                        **kwargs):
                    object_changed = True

        if not object_changed:
            msg = None
            if verbose_level > 0:
                msg = (_("No orphan objects found for %s: %s")
                        % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show(self, callback=default_callback, token_name=None, **kwargs):
        """ Show user info. """
        view_public_acl = False
        if self.verify_acl("view_public"):
            view_public_acl = True
        view_acl = False
        if self.verify_acl("view"):
            view_acl = True
        edit_acl = False
        if self.verify_acl("edit"):
            edit_acl = True
        if not view_public_acl:
           if not view_acl:
                if not edit_acl:
                    msg = ("Permission denied.")
                    return callback.error(msg, exception=PermissionDenied)

        if token_name:
            token = self.token(token_name)
            if not token:
                return callback.error(_("Unknown token: %s") % token_name)
            token_lines = token.show()
            return callback.ok(token_lines)

        from otpme.lib import cli

        lines = []
        lines.append("User info:\n")
        oid_string = "\tOID:\t\t\t%s\n" % self.oid.full_oid
        lines.append(oid_string)
        if not self.enabled:
            lines.append("\tstatus:\t\t\tDisabled\n")
        else:
            lines.append("\tstatus:\t\t\tActive\n")

        if self.verify_acl("view:auto_disable") \
        or self.verify_acl("edit:auto_disable"):
            if self.auto_disable_time == 0:
                auto_disable = "\tauto-disable:\t\tdisabled\n"
            else:
                auto_disable = "\tauto-disable:\t\t%s\n" % self.auto_disable_time
            lines.append(auto_disable)
            unused_disable = "\tunused-disable:\t\t%s\n" % self.unused_disable
            lines.append(unused_disable)
        else:
            auto_disable = "\tauto-disable:\t\t\tPermission denied\n"
            lines.append(auto_disable)
            unused_disable = "\tunused-disable:\t\t\tPermission denied\n"
            lines.append(unused_disable)

        lines.append("\trealm:\t\t\t%s\n" % self.realm)
        lines.append("\tsite:\t\t\t%s\n" % self.site)
        if self.unit:
            lines.append("\tunit:\t\t\t%s\n" % self.unit)
        else:
            lines.append("\tunit:\t\t\t\n")

        if self.group:
            lines.append("\tgroup:\t\t\t%s\n" % self.group)
        else:
            lines.append("\tgroup:\t\t\t\n")

        if view_acl or edit_acl:
            autosign = "Disabled"
            if self.autosign_enabled:
                autosign = "Enabled"
            lines.append("\tauto-sign:\t\t%s\n" % autosign)

        if view_acl or edit_acl:
            allow_disabled_login = "Disabled"
            if self.allow_disabled_login:
                allow_disabled_login = "Enabled"
            lines.append("\tallow-disabled-login:\t%s\n" % allow_disabled_login)

        if self.verify_acl("view:auth_script") \
        or self.verify_acl("enable:auth_script") \
        or self.verify_acl("disable:auth_script"):
            auth_script = "N/A"
            auth_script_status = "N/A"
            if self.auth_script:
                if self.auth_script_enabled:
                    auth_script_status = "Enabled"
                else:
                    auth_script_status = "Disabled"
                x = backend.get_object(object_type="script", uuid=self.auth_script)
                if x:
                    auth_script = x.rel_path
                    if self.auth_script_options:
                        auth_script_options = " ".join(self.auth_script_options)
                        auth_script = "%s %s" % (auth_script,
                                                auth_script_options)
            lines.append("\tauth_script:\t\t%s (%s)\n"
                        % (auth_script, auth_script_status))

        if self.verify_acl("view:key_script"):
            key_script = "N/A"
            if self.key_script:
                x = backend.get_object(object_type="script", uuid=self.key_script)
                if x:
                    key_script = x.rel_path
                    if self.key_script_options:
                        key_script_options = " ".join(self.key_script_options)
                        key_script = "%s %s" % (key_script, key_script_options)
            lines.append("\tkey_script:\t\t%s\n" % key_script)

        if self.verify_acl("view:agent_script"):
            agent_script = "N/A"
            if self.agent_script:
                x = backend.get_object(object_type="script", uuid=self.agent_script)
                if x:
                    agent_script = x.rel_path
                    if self.agent_script_options:
                        agent_script_options = " ".join(self.agent_script_options)
                        agent_script = "%s %s" % (agent_script, agent_script_options)
            lines.append("\tagent_script:\t\t%s\n" % agent_script)

        if self.verify_acl("view:login_script") \
        or self.verify_acl("enable:login_script") \
        or self.verify_acl("disable:login_script"):
            login_script = "N/A"
            login_script_status = "N/A"
            if self.login_script:
                if self.login_script_enabled:
                    login_script_status = "Enabled"
                else:
                    login_script_status = "Disabled"
                x = backend.get_object(object_type="script", uuid=self.login_script)
                if x:
                    login_script = x.rel_path
                    if self.login_script_options:
                        login_script_options = " ".join(self.login_script_options)
                        login_script = "%s %s" % (login_script, login_script_options)
            lines.append("\tlogin_script:\t\t%s (%s)\n"
                        % (login_script, login_script_status))

        if self.acl_inheritance_enabled:
            lines.append("\tinherit_acls:\t\tEnabled\n")
        else:
            lines.append("\tinherit_acls:\t\tDisabled\n")

        description = ""
        if self.description:
            description = self.description
        lines.append("\tdescription:\t\t%s\n" % description)

        create_time = self.create_time
        create_time = datetime.datetime.fromtimestamp(create_time)
        create_time = create_time.strftime('%d.%m.%Y %H:%M:%S')
        lines.append("\tcreated:\t\t%s\n" % create_time)

        last_modified = self.last_modified
        last_modified = datetime.datetime.fromtimestamp(last_modified)
        last_modified = last_modified.strftime('%d.%m.%Y %H:%M:%S')
        lines.append("\tmodified:\t\t%s\n" % last_modified)

        last_used = self.get_last_used_time(return_type="date")
        last_used = last_used.strftime('%d.%m.%Y %H:%M:%S')
        lines.append("\tlast_used:\t\t%s\n" % last_used)

        lines.append("\tchecksum:\t\t%s\n" % self.checksum)
        lines.append("\tsync_checksum:\t\t%s\n" % self.sync_checksum)
        origin = backend.get_object(uuid=self.origin)
        if not origin:
            origin = self.origin_cache
        lines.append("\torigin:\t\t\t%s\n" % origin)

        lines.append("\n")
        lines.append("User tokens:\n")

        token_lines = []
        search_regex = "%s/*" % self.name
        show_tokens = cli.show_getter("token")
        token_list = show_tokens(realm=self.realm,
                                site=self.site,
                                show_all=True,
                                verify_acls=False,
                                search_regex=search_regex,
                                id_attr="name")
        for l in token_list.split("\n"):
            token_lines.append(" " * 8 + l)

        output = ""
        for line in lines:
            output += str(line)

        output += "\n".join(token_lines)

        return callback.ok(output)
