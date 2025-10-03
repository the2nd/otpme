# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import magic
import base64
import datetime
from typing import List
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import jwt
from otpme.lib import cli
from otpme.lib import json
from otpme.lib import trash
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.encryption import aes
from otpme.lib import sign_key_cache
from otpme.lib.audit import audit_log
from otpme.lib import multiprocessing
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.job.callback import JobCallback
from otpme.lib.register import register_module
from otpme.lib.encryption import hash_password
from otpme.lib.typing import match_class_typing
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
                        "auto_mount",
                        "auto_disable",
                        ],
            "dump"      : [
                        "photo",
                        ],
        }

write_value_acls = {
                    "add"       : [
                                "token",
                                "photo",
                                ],
                    "delete"    : [
                                "token",
                                "photo",
                                "session",
                                ],
                    "rename"    : [
                                "token",
                                ],
                    "deploy"    : [
                                "token",
                                ],
                    "edit"      : [
                                "config",
                                "group",
                                "key_mode",
                                "private_key",
                                "private_key_pass",
                                "public_key",
                                "key_script",
                                "auth_script",
                                "agent_script",
                                "login_script",
                                "auto_disable",
                                "language",
                                ],
                    "enable"    : [
                                "disabled_login",
                                "autosign",
                                "auth_script",
                                "login_script",
                                "token"
                                "auto_mount",
                                ],
                    "disable"   : [
                                "disabled_login",
                                "autosign",
                                "auth_script",
                                "login_script",
                                "token",
                                "auto_mount",
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
                    'oargs'             : ['add_default_token', 'default_token', 'default_token_type', 'default_role', 'default_roles', 'groups', 'unit', 'group', 'template_object', 'template_name', 'gen_qrcode', 'no_token_infos', 'password', 'ldif_attributes'],
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
    'show_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : [],
                    'job_type'          : 'thread',
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
    'enable_auto_mount'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_auto_mount',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_auto_mount'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_auto_mount',
                    'job_type'          : 'thread',
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
                    'oargs'             : ['auth_script', 'script_options'],
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
                    'oargs'             : ['token_type', 'destination_token', 'replace', 'gen_qrcode', 'enable_mschap', 'password'],
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
    'key_mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_mode',
                    'args'              : ['key_mode'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'get_key_mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_key_mode',
                    'job_type'          : 'thread',
                    },
                },
            },
    'gen_keys'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'gen_keys',
                    'oargs'         : [
                                        'key_mode',
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
    'import_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'import_key',
                    'args'              : ['private_key'],
                    'oargs'             : ['encrypt_key', 'aes_key'],
                    'job_type'          : 'thread',
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
                    'oargs'             : ['position', 'value'],
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
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls',],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
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
    'language'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_language',
                    'oargs'             : ['language'],
                    'job_type'          : 'thread',
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
    'photo'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_photo',
                    'args'              : ['image_data'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'dump_photo'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump_photo',
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_photo'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_photo',
                    'job_type'          : 'thread',
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
                    'oargs'             : ['attributes'],
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
    config.register_auth_on_action_hook("user", "move")
    config.register_auth_on_action_hook("user", "sign")
    config.register_auth_on_action_hook("user", "verify")
    config.register_auth_on_action_hook("user", "encrypt")
    config.register_auth_on_action_hook("user", "decrypt")
    config.register_auth_on_action_hook("user", "add_photo")
    config.register_auth_on_action_hook("user", "del_photo")
    config.register_auth_on_action_hook("user", "dump_photo")

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
                        'site',
                        'unit',
                    ]
    def script_setter(script_path):
        result = backend.search(object_type="script",
                                attribute="rel_path",
                                value=script_path,
                                return_type="uuid")
        if not result:
            msg = _("Unknown script: {script_path}")
            msg = msg.format(script_path=script_path)
            raise UnknownObject(msg)
        script_uuid = result[0]
        return script_uuid
    def script_getter(script_uuid):
        result = backend.search(object_type="script",
                                attribute="uuid",
                                value=script_uuid,
                                return_type="rel_path")
        if not result:
            msg = _("Unknown script: {script_uuid}")
            msg = msg.format(script_uuid=script_uuid)
            raise UnknownObject(msg)
        script_path = result[0]
        return script_path
    # Default scripts unit.
    scripts_unit = config.get_default_unit("script")
    # Default key script to add to new users.
    KEY_SCRIPT_PATH = f"{scripts_unit}/{KEY_SCRIPT_NAME}"
    config.register_config_parameter(name="default_key_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=KEY_SCRIPT_PATH,
                                    object_types=object_types)
    # Default auth script to add to new users.
    AUTH_SCRIPT_PATH = f"{scripts_unit}/{AUTH_SCRIPT_NAME}"
    config.register_config_parameter(name="default_auth_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=AUTH_SCRIPT_PATH,
                                    object_types=object_types)
    # Default agent script to add to new users.
    AGENT_SCRIPT_PATH = f"{scripts_unit}/{AGENT_SCRIPT_NAME}"
    config.register_config_parameter(name="default_agent_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=AGENT_SCRIPT_PATH,
                                    object_types=object_types)
    # Default login script to add to new users.
    LOGIN_SCRIPT_PATH = f"{scripts_unit}/{LOGIN_SCRIPT_NAME}"
    config.register_config_parameter(name="default_login_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=LOGIN_SCRIPT_PATH,
                                    object_types=object_types)
    # Max failed pass history length
    object_types = [
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
    def default_token_setter(token_type):
        token_types = config.get_sub_object_types("token")
        if token_type not in token_types:
            msg = "Invalid token type: {token_type}"
            msg = msg.format(token_type=token_type)
            raise ValueError(msg)
        return token_type
    config.register_config_parameter(name="default_token_type",
                                    ctype=str,
                                    default_value="hotp",
                                    setter=default_token_setter,
                                    object_types=object_types)
    # Length for user RSA keys.
    object_types = [
                        'realm',
                        'site',
                        'unit',
                        'user',
                    ]
    def user_key_len_setter(key_len):
        valid_key_lens = [2048, 4096]
        if key_len not in valid_key_lens:
            msg = "Invalid key len: {key_len}"
            msg = msg.format(key_len=key_len)
            raise ValueError(msg)
        return key_len
    config.register_config_parameter(name="user_key_len",
                                    ctype=int,
                                    default_value=2048,
                                    setter=user_key_len_setter,
                                    valid_values=VALID_USER_KEY_LENS,
                                    object_types=object_types)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'name' ]
    # OID regex stuff.
    # allow "@" in usernames
    unit_path_re = oid.object_regex['unit']['path']
    user_name_re = '([0-9a-z]([0-9a-z_.@-]*[0-9a-z]){0,})'
    user_path_re = f'{unit_path_re}[/]{user_name_re}'
    user_oid_re = f'user|{user_path_re}'
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
        regex = re.compile(f"^{regex_string}$")
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
    def upath_getter(user_oid, user_uuid):
        user_used_dir = os.path.join(used_base_dir, user_uuid)
        return user_used_dir
    # Register users "used" dir.
    backend.register_object_dir(object_type="user",
                                name="used_dir",
                                getter=upath_getter,
                                drop=True)
    # Path getter for user paths.
    def opath_getter(user_oid, user_uuid):
        unit_fs_path = backend.get_unit_fs_path(user_oid)
        site_dir = backend.get_site_dir(user_oid.realm, user_oid.site)
        config_dir_name = f"{user_oid.name}.{user_dir_extension}"
        config_dir = os.path.join(site_dir, unit_fs_path, config_dir_name)

        config_paths = {}
        config_paths['config_dir'] = config_dir
        config_paths['rmtree_on_delete'] = [config_dir]

        if not user_uuid:
            return config_paths

        user_dirs = backend.get_object_dir(user_oid, user_uuid)
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
                            object_cache=10240,
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
        log_msg = _("Unable to get 'max_fail' for accessgroup '{access_group}'", log=True)[1]
        log_msg = log_msg.format(access_group=access_group)
        logger.critical(log_msg)
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
            last_used = backend.get_last_used(uuid=uuid)
            if last_used == 0:
                continue
            last_used_list.append(last_used)
        # Check if reset time is reached.
        if last_used_list:
            now = time.time()
            last_login_try = sorted(last_used_list)[0]
            last_try_age = now - last_login_try
            if last_try_age > max_fail_reset:
                is_blocked = False
    return is_blocked

@match_class_typing
class User(OTPmeObject):
    """ Class that implements OTPmeUser. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        path: Union[str,None]=None,
        name: Union[str,None]=None,
        unit: Union[str,None]=None,
        site: Union[str,None]=None,
        realm: Union[str,None]=None,
        **kwargs,
        ):
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

        # Localization for mgmtd stuff.
        self.language = None
        # Users primary group cache.
        self._group_uuid = None
        # Indicates that the user is allowed to login even if realm/site/accessgroup/unit is disabled.
        self.allow_disabled_login = False
        # Indicates that the users shares should be mounted on login.
        self.auto_mount = True
        # Users keys can be handled by the key script on client side or by this
        # class.
        self.key_mode = "client"
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
        # User photo.
        self.photo = None
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
                            "AUTO_MOUNT",
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
                            "AUTO_MOUNT",
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
                        'LANGUAGE'                  : {
                                                        'var_name'  : 'language',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

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

                        'AUTO_MOUNT'                : {
                                                        'var_name'  : 'auto_mount',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },


                        'ALLOW_DISABLED_LOGIN'      : {
                                                        'var_name'  : 'allow_disabled_login',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'KEY_MODE'                  : {
                                                        'var_name'  : 'key_mode',
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
                        'PHOTO'                     : {
                                                        'var_name'  : 'photo',
                                                        'type'      : str,
                                                        'required'  : False,
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

    def _set_name(self, name: str):
        """ Set object name. """
        name_upper = name.upper()
        internal_users = config.get_internal_objects("user")
        if name_upper in internal_users:
            name = name_upper
        else:
            if name != name.lower():
                msg = _("Username must be lowercase.")
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
    def group(self, new_group: str):
        result = backend.search(object_type="group",
                                attribute="name",
                                value=new_group,
                                return_type="uuid")
        if not result:
            msg = _("Unknown group: {new_group}")
            msg = msg.format(new_group=new_group)
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

    def _change_group(
        self,
        group_uuid: str,
        verify_acls: bool=True,
        new_user: bool=False,
        callback: JobCallback=default_callback,
        ):
        """ Change users group. """
        current_group_uuid = None
        # Get new group.
        result = backend.search(object_type="group",
                                attribute="uuid",
                                value=group_uuid,
                                return_type="instance")
        if not result:
            msg = _("Unknown group: {group_uuid}")
            msg = msg.format(group_uuid=group_uuid)
            raise UnknownObject(msg)
        new_group = result[0]
        # Check current group.
        if self._group_uuid:
            current_group_uuid = self._group_uuid
        else:
            result = backend.search(object_type="group",
                                    attribute="user",
                                    value=self.uuid,
                                    return_type="uuid")
            if result:
                current_group_uuid = result[0]

        if not new_user and not current_group_uuid:
            msg = "Default group not set (e.g. sync required?)."
            return callback.error(msg)

        old_group = None
        if current_group_uuid:
            if current_group_uuid == group_uuid:
                msg = _("User already in group: {new_group_name}")
                msg = msg.format(new_group_name=new_group.name)
                return callback.error(msg)
            result = backend.search(object_type="group",
                                    attribute="uuid",
                                    value=current_group_uuid,
                                    return_type="instance")
            if result:
                old_group = result[0]

        # Add user to new group.
        local_add = None
        local_remove = None
        cross_site_add = None
        cross_site_remove = None
        cross_site_change = None
        if new_group.site == config.site:
            local_add = True
            if old_group:
                if old_group.site == config.site:
                    local_remove = True
                else:
                    cross_site_remove = True
        else:
            if old_group:
                if old_group.site == config.site:
                    local_remove = True
                    cross_site_add = True
                else:
                    cross_site_change = True
            else:
                cross_site_add = True

        if cross_site_add or cross_site_remove or cross_site_change:
            if callback == default_callback:
                msg = "Cannot change user default group without valid callback."
                return callback.error(msg)

        transaction_started = False
        if local_add or local_remove:
            try:
                backend.begin_transaction(name="change_user_default_group",
                                        callback=callback)
            except AlreadyExists:
                transaction_started = False
            else:
                transaction_started = True
        if local_add:
            msg = _("Setting group: {new_group_name}")
            msg = msg.format(new_group_name=new_group.name)
            callback.send(msg)
            result = new_group.add_default_group_user(self.uuid,
                                                verify_acls=verify_acls,
                                                callback=callback)
        if cross_site_add:
            msg = _("Setting group: {new_group_name}")
            msg = msg.format(new_group_name=new_group.name)
            callback.send(msg)
            result = self.cross_site_user_default_group_change(action="add",
                                                            user=self,
                                                            new_group=new_group,
                                                            callback=callback)
            if not result:
                msg = _("Failed to change user default group.")
                return callback.error(msg)

        if local_remove:
            old_group.remove_default_group_user(self.uuid,
                                        verify_acls=verify_acls,
                                        ignore_missing=True,
                                        callback=callback)

        if cross_site_remove:
            result = self.cross_site_user_default_group_change(action="remove",
                                                                user=self,
                                                                old_group=old_group,
                                                                callback=callback)
            if not result:
                # Clear callback modified objects.
                callback.forget_modified_objects()
                # Abort global transaction.
                backend.abort_transaction()
                msg = "Failed to change user default group."
                return callback.error()

        if transaction_started:
            backend.end_transaction()

        if cross_site_change:
            result = self.cross_site_user_default_group_change(action="change",
                                                                user=self,
                                                                old_group=old_group,
                                                                new_group=new_group,
                                                                callback=callback)
            if not result:
                msg = "Failed to change user default group."
                return callback.error()

        # Set new group UUID and update index and extensions.
        self._group_uuid = new_group.uuid
        self.update_index('group', self._group_uuid)
        self.update_extensions("change_group", callback=callback)

        return self._cache(callback=callback)

    def cross_site_user_default_group_change(self,
        action: str,
        user: OTPmeObject,
        old_group: OTPmeObject=None,
        new_group: OTPmeObject=None,
        callback: JobCallback=default_callback,
        ):
        # Load JWT signing key.
        our_site = backend.get_object(uuid=config.site_uuid)
        sign_key = our_site._key

        # Set source site.
        src_realm = config.realm
        src_site = config.site
        # Set destination site.
        old_group_name = None
        old_group_uuid = None
        new_group_name = None
        new_group_uuid = None
        if action == "add":
            dst_realm = new_group.realm
            dst_site = new_group.site
            new_group_name = new_group.name
            new_group_uuid = new_group.uuid
        elif action == "remove":
            dst_realm = old_group.realm
            dst_site = old_group.site
            old_group_name = old_group.name
            old_group_uuid = old_group.uuid
        elif action == "change":
            dst_realm = new_group.realm
            dst_site = new_group.site
            new_group_name = new_group.name
            new_group_uuid = new_group.uuid
            old_group_name = old_group.name
            old_group_uuid = old_group.uuid

        # Build JWT.
        jwt_data = {
                'src_realm'         : src_realm,
                'src_site'          : src_site,
                'dst_realm'         : dst_realm,
                'dst_site'          : dst_site,
                'action'            : action,
                'old_group_name'    : old_group_name,
                'old_group_uuid'    : old_group_uuid,
                'new_group_name'    : new_group_name,
                'new_group_uuid'    : new_group_uuid,
                'user_name'         : user.name,
                'user_uuid'         : user.uuid,
                'reason'            : "USER_DEFAULT_GROUP_CHANGE",
                }
        # Sign object move data.
        _jwt = jwt.encode(payload=jwt_data, key=sign_key, algorithm='RS256')

        object_data = {
                    'src_realm'     : src_realm,
                    'src_site'      : src_site,
                    'dst_realm'     : dst_realm,
                    'dst_site'      : dst_site,
                    'action'        : action,
                    'jwt'           : _jwt,
                    }

        # Actually move objects to other site.
        response = callback.change_user_default_group(object_data)

        try:
            status = response['status']
        except KeyError:
            msg = "Response missing status."
            return callback.error(msg)

        try:
            reply = response['reply']
        except KeyError:
            msg = "Response missing reply."
            return callback.error(msg)

        if not status:
            if action == "add":
                msg = _("Set user default group failed: {reply}")
                msg = msg.format(reply=reply)
            elif action == "remove":
                msg = _("Unset user default group failed: {reply}")
                msg = msg.format(reply=reply)
            elif action == "change":
                msg = _("Change user default group failed: {reply}")
                msg = msg.format(reply=reply)
            return callback.error(msg)

        # Get destination site cert to encrypt objects and
        # verify reply JWT.
        _dst_site = backend.get_object(object_type="site",
                                        realm=dst_realm,
                                        name=dst_site)
        # Encrypt encryption key with destination site public key.
        try:
            dst_site_public_key = RSAKey(key=_dst_site._cert.public_key())
        except Exception as e:
            msg, log_msg = _("Unable to get public key of site certificate: {dst_site}: {e}", log=True)
            msg = msg.format(dst_site=dst_site, e=e)
            log_msg = log_msg.format(dst_site=dst_site, e=e)
            logger.warning(log_msg)
            return callback.error(msg)

        # Decode reply JWT.
        try:
            reply_jwt_data = jwt.decode(jwt=reply,
                                    key=dst_site_public_key,
                                    algorithm='RS256')
        except Exception as e:
            msg, log_msg = _("JWT verification failed: {e}", log=True)
            msg = msg.format(e=e)
            log_msg = log_msg.format(e=e)
            logger.warning(log_msg)
            return callback.error(msg)

        if reply_jwt_data != jwt_data:
            msg = _("Got wrong JWT data from peer:\n\t{jwt_data}\n\t{reply_jwt_data}")
            msg = msg.format(jwt_data=jwt_data, reply_jwt_data=reply_jwt_data)
            return callback.error(msg)

        return callback.ok()

    def cross_site_move(
        self,
        path: str,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Do cross site move of user. """
        if config.use_api:
            msg = "Cannot do cross-site move in API mode."
            return callback.error(msg)

        path_data = oid.resolve_path(object_path=path,
                                    object_type="unit")
        dst_realm = path_data['realm']
        dst_site = path_data['site']

        object_ids = [(self.oid.full_oid, self.uuid)]
        user_policies = self.get_policies(ignore_hooks=True,
                                        return_type="name")
        for policy_name in user_policies:
            self.remove_policy(policy_name=policy_name,
                                verify_acls=False)
        self.update_object_config()
        object_config = self.object_config.copy()
        objects = {
                    self.oid.full_oid   : {
                                            'path'          : path,
                                            'object_config' : object_config,
                                            'policies'      : user_policies,
                                        },
                }

        token_list = self.get_tokens(return_type="instance")
        for token in token_list:
            objects[token.oid.full_oid] = {}
            token_policies = token.get_policies(ignore_hooks=True,
                                                return_type="name")
            for policy_name in token_policies:
                token.remove_policy(policy_name=policy_name,
                                    verify_acls=False)
                token.update_object_config()
            objects[token.oid.full_oid]['policies'] = token_policies
            token_oc = token.object_config.copy()
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
            msg, log_msg = _("Unable to get public key of site certificate: {dst_site}: {e}", log=True)
            msg = msg.format(dst_site=dst_site, e=e)
            log_msg = log_msg.format(dst_site=dst_site, e=e)
            logger.warning(log_msg)
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
            msg = _("Object move failed: {reply}")
            msg = msg.format(reply=reply)
            return callback.error(msg)

        # Decode reply JWT.
        try:
            jwt_data = jwt.decode(jwt=reply,
                                key=dst_site_public_key,
                                algorithm='RS256')
        except Exception as e:
            msg, log_msg = _("JWT verification failed: {e}", log=True)
            msg = msg.format(e=e)
            log_msg = log_msg.format(e=e)
            logger.warning(log_msg)
            return callback.error(msg)

        # Make sure we only delete objects if all were written on
        # destination site.
        for x_oid in objects:
            x_oc = objects[x_oid]['object_config']
            x_uuid = x_oc['UUID']
            try:
                y_uuid = jwt_data[x_oid]['uuid']
            except KeyError:
                msg = _("Failed to find object in reply: {x_oid}")
                msg = msg.format(x_oid=x_oid)
                return callback.error(msg)
            if x_uuid != y_uuid:
                msg = _("UUID missmatch in reply: {x_oid}: {x_uuid} <> {y_uuid}")
                msg = msg.format(x_oid=x_oid, x_uuid=x_uuid, y_uuid=y_uuid)
                return callback.error(msg)

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
                    msg = _("Failed to delete object on source site: {x_oid}")
                    msg = msg.format(x_oid=x_oid)
                    callback.error(msg)

        return callback.ok()

    @audit_log()
    def move(self,
        *args,
        _caller: str="API",
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Move user to other unit. """
        if self.name == config.admin_user_name:
            msg = "Moving admin user is not allowed."
            return callback.error(msg)
        internal_users = config.get_internal_objects("user")
        if self.name in internal_users:
            msg = "Moving internal user is not allowed."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("move",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        new_unit = kwargs['new_unit']
        if new_unit.startswith("/"):
            path_data = oid.resolve_path(new_unit, object_type="user")
            new_site = path_data['site']
            if new_site != self.site:
                if config.auth_user.uuid == self.uuid:
                    msg = "Cannot move own user while logged in."
                    return callback.error(msg)
                return self.cross_site_move(*args, path=new_unit,
                                            callback=callback,
                                            **kwargs)
        move_result = super(User, self).move(*args, callback=callback, **kwargs)
        token_list = self.get_tokens(return_type="instance")
        for token in token_list:
            token._write(callback=callback)
        return move_result

    @check_acls(['add:photo'])
    @object_lock()
    @audit_log()
    def add_photo(
        self,
        image_data: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_photo",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        # Check if data is base64 and decode.
        if stuff.is_base64(image_data):
            image_data = base64.b64decode(image_data)

        magic_handler = magic.Magic(mime=True, uncompress=True)
        image_type = magic_handler.from_buffer(image_data)

        if image_type != "image/jpeg":
            msg = "Photo must be in jpeg format."
            return callback.error(msg)

        if isinstance(image_data, str):
            image_data = image_data.encode()

        image_base64 = base64.b64encode(image_data)
        image_base64 = image_base64.decode()

        self.photo = image_base64

        self.add_attribute(attribute="jpegPhoto", value=self.photo)

        return self._write(callback=callback)

    @check_acls(['del:photo'])
    @object_lock()
    @audit_log()
    def del_photo(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_photo",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.photo = None
        self.del_attribute(attribute="jpegPhoto")

        return self._write(callback=callback)

    @check_acls(['dump:photo'])
    @object_lock()
    @audit_log()
    def dump_photo(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if not self.photo:
            msg = _("No photo set.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("dump_photo",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return callback.ok(self.photo)

    def get_members(self, return_type: str="full_oid", **kwargs):
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
                log_msg = _("Unable to add signer cache: {self_oid}: {e}", log=True)[1]
                log_msg = log_msg.format(self_oid=self.oid, e=e)
                logger.critical(log_msg)
        return super(User, self)._write(**kwargs)

    @check_acls(['edit:language'])
    def change_language(self, language, callback: JobCallback=default_callback, **kwargs):
        """ Change users localization. """
        if language == self.language:
            msg = _("Users language already set to {language}")
            msg = msg.format(language=self.language)
            return callback.error(msg)
        self.language = language
        return self._cache(callback=callback)

    @check_acls(['edit:key_mode'])
    def change_key_mode(self, key_mode, callback: JobCallback=default_callback, **kwargs):
        """ Change users key mode. """
        if key_mode == self.key_mode:
            msg = _("Users key mode already set to {key_mode}")
            msg = msg.format(key_mode=self.key_mode)
            return callback.error(msg)
        self.key_mode = key_mode
        return self._cache(callback=callback)

    def get_key_mode(self, callback: JobCallback=default_callback, **kwargs):
        """ Get users key mode. """
        key_mode = self.key_mode
        if key_mode is None:
            key_mode = "client"
        return callback.ok(key_mode)

    def _set_key(
        self,
        aes_key: Union[str,None]=None,
        rsa_key: Union[str,None]=None,
        encrypted: bool=False,
        ):
        """
        Encode (create one line string with AES+RSA key) private key string.
        """
        self.private_key = {'aes_key':aes_key, 'rsa_key':rsa_key, 'encrypted':encrypted}

    def _get_key(self):
        if self.key_mode == "server":
            try:
                aes_key = self.private_key['aes_key']
                rsa_key = self.private_key['rsa_key']
                encrypted = self.private_key['encrypted']
            except KeyError:
                msg = "Failed to load private key: Wrong key mode set?"
                raise OTPmeException(msg)
        else:
            aes_key = None
            rsa_key = self.private_key['key_blob']
            encrypted = False
        return aes_key, rsa_key, encrypted

    @object_lock()
    @check_acls(['edit:group'])
    @audit_log()
    def change_group(
        self,
        new_group: str,
        verbose_level: int=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change object group. """
        if new_group == "":
            msg = _("Missing group.")
            return callback.error(msg)

        result = backend.search(object_type="group",
                                attribute="name",
                                value=new_group,
                                return_type="uuid")
        if not result:
            msg = _("Unknown group: {new_group}")
            msg = msg.format(new_group=new_group)
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
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

        return self._cache(callback=callback)

    @check_acls(['edit:private_key'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_private_key(
        self,
        private_key: str,
        force: bool=False,
        verbose_level=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        if self.private_key is not None and not force:
            if self.confirmation_policy != "force":
                ask = callback.ask("Replace existing private key?: ")
                if str(ask).lower() != "y":
                    return callback.abort()

        if private_key == "":
            self.private_key = {}
        else:
            # Set private key.
            self.private_key = {}
            self.private_key['key_blob'] = private_key

        return self._cache(callback=callback)

    @check_acls(['edit:public_key'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_public_key(
        self,
        public_key: str,
        force: bool=False,
        verbose_level: int=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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

    def get_key_script(
        self,
        return_type: str="path",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
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
                    msg = _("Script does not exist: {key_script}")
                    msg = msg.format(key_script=self.key_script)
                    return callback.error(msg)
                if return_type == "path":
                    script = ks.rel_path
                elif return_type == "data":
                    script = ks.dump(run_policies=False)
                elif return_type == "instance":
                    if _caller != "API":
                        return callback.error("Invalid return type: instance")
                    script = ks
                else:
                    msg = _("Invalid <return_type>: {return_type}")
                    msg = msg.format(return_type=return_type)
                    raise OTPmeException(msg)
        if self.key_script_options:
            opts = self.key_script_options
        if _caller != "CLIENT":
            result = (script, opts)
        else:
            if opts:
                result = f"{script} {opts}"
            else:
                result = script
        return callback.ok(result)

    def get_ssh_script(
        self,
        return_type: str="name",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
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
                    msg = _("Script does not exist: {agent_script}")
                    msg = msg.format(agent_script=self.agent_script)
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
                result = f"{script} {opts}"
            else:
                result = script
        return callback.ok(result)

    def get_key(
        self,
        private: bool=False,
        decrypt: bool=False,
        aes_key: Union[str,None]=None,
        force: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Return user key as string. """
        if private:
            if not self.verify_acl("view_all:private_key"):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)
        if private and self.private_key:
            # Get private key. We need to pass on callback to allow decryption
            # of private key if key mode is server.
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
    @audit_log()
    def gen_keys(
        self,
        key_mode: str="client",
        encrypt_key: bool=True,
        aes_key: Union[str,None]=None,
        aes_key_enc: Union[str,None]=None,
        key_len: Union[int,None]=None,
        pass_hash_type: str="PBKDF2",
        force: bool=False,
        run_policies: bool=True,
        stdin_pass: bool=False,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Create users RSA private/public key pair. """
        if key_mode not in [ 'client', 'server' ]:
            msg = _("Unknown key mode: {key_mode}")
            msg = msg.format(key_mode=key_mode)
            return callback.error(msg)

        if key_len is None:
            key_len = self.get_config_parameter("user_key_len")

        if key_len not in VALID_USER_KEY_LENS:
            key_lens = []
            for i in VALID_USER_KEY_LENS:
                key_lens.append(str(i))
            valid_key_lens = ", ".join(key_lens)
            msg = _("Key bits must be one of: {valid_key_lens}")
            msg = msg.format(valid_key_lens=valid_key_lens)
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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

        self.key_mode = key_mode

        if key_mode == "client":
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
                msg = _("Key generation failed: {message}")
                msg = msg.format(message=message)
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

        msg = _("Generating keys ({key_len} bits)...")
        msg = msg.format(key_len=key_len)
        callback.send(msg)
        # Generate new key pair.
        try:
            key = RSAKey(bits=key_len)
        except Exception as e:
            msg = _("Error creating RSA key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)

        # Encrypt private key if we got a AES key.
        if aes_key:
            try:
                key_encrypted = key.encrypt_key(aes_key=aes_key,
                                            hash_type=pass_hash_type)
                self._set_key(aes_key_enc, key_encrypted, encrypted=True)
            except Exception as e:
                msg = _("Error encrypting private key: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
        else:
            self._set_key(rsa_key=private_key_base64)

        # Set public key.
        self.public_key = encode(key.public_key_base64, "base64")

        # Add ACLs to allow default token to do encrypt stuff.
        if self.default_token:
            acls = []
            acl = f"token:{self.default_token}:encrypt"
            acls.append(acl)
            acl = f"token:{self.default_token}:decrypt"
            acls.append(acl)
            acl = f"token:{self.default_token}:sign"
            acls.append(acl)
            acl = f"token:{self.default_token}:verify"
            acls.append(acl)
            if acl in acls:
                self.add_acl(acl=acl,
                            recursive_acls=False,
                            apply_default_acls=False,
                            verify_acls=False,
                            verbose_level=1,
                            callback=callback)

        return self._cache(callback=callback)

    @check_acls(['del_keys'])
    @check_special_user()
    @cli.check_rapi_opts()
    #@object_lock(full_lock=True)
    @audit_log()
    def del_keys(
        self,
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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

        self.private_key = {}
        self.public_key = None

        return self._cache(callback=callback)

    @check_acls(['import_key'])
    @check_special_user()
    @cli.check_rapi_opts()
    #@object_lock(full_lock=True)
    @audit_log()
    def import_key(
        self,
        private_key: str,
        encrypt_key: bool=True,
        aes_key: Union[str,None]=None,
        aes_key_enc: Union[str,None]=None,
        pass_hash_type: str="PBKDF2",
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Import RSA private/public key. """
        if self.key_mode == "client":
            msg = "Cannot import key in client mode."
            return callback.error(msg)

        # Try to load RSA key.
        try:
            key = RSAKey(key=private_key)
        except Exception as e:
            config.raise_exception()
            msg = _("Error loading private key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("import_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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

        if aes_key and not aes_key_enc:
            msg = "Need 'aes_key_enc' when 'aes_key' is set."
            return callback.error(msg)

        if encrypt_key and not aes_key:
            aes_key = aes.gen_key()
            aes_key_enc = callback.encrypt(aes_key, use_rsa_key=False)
            if len(aes_key_enc) == 0:
                msg = ("Got no encrypted AES key from client.")
                return callback.error(msg)

        # Encrypt private key if we got a AES key.
        if aes_key:
            try:
                key_encrypted = key.encrypt_key(aes_key=aes_key,
                                            hash_type=pass_hash_type)
                self._set_key(aes_key_enc, key_encrypted, encrypted=True)
            except Exception as e:
                msg = _("Error encrypting private key: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
        else:
            self._set_key(rsa_key=key.private_key_base64)

        # Set public key.
        self.public_key = encode(key.public_key_base64, "base64")

        return self._cache(callback=callback)

    def get_private_key(
        self,
        decrypt: bool=True,
        aes_key: Union[str,None]=None,
        callback: JobCallback=default_callback,
        _caller="API",
        ):
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
                try:
                    key = RSAKey(key=rsa_key, aes_key=aes_key)
                    private_key = key.private_key_base64
                except Exception as e:
                    config.raise_exception()
                    msg = _("Error decrypting private key: {e}")
                    msg = msg.format(e=e)
                    return callback.error(msg)
            else:
                private_key = rsa_key
        else:
            #private_key = decode(rsa_key, "base64")
            private_key = rsa_key

        # We must not use callback here to prevent sending private key to the
        # client by accident!
        return private_key

    @check_acls(['edit:private_key_pass'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_key_pass(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change private key passphrase. """
        if not self.private_key:
            return callback.error("No private key set.")
        if self.key_mode != "server":
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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
            msg = _("Error decrypting private key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)

        if aes_key:
            answer = callback.ask("Remove key password? ")
            if answer.lower() == "y":
                remove_key_pass = True

        if remove_key_pass:
            private_key = encode(user_key.private_key_base64, "base64")
            self.private_key = f"RSA[{private_key}]"
        else:
            # Gen new AES key.
            aes_key = aes.gen_key()
            # Try to get encrypted AES key from client.
            aes_key_enc = callback.encrypt(aes_key, use_rsa_key=False)
            # Try to encrypt RSA key.
            try:
                key_encrypted = user_key.encrypt_key(aes_key=aes_key)
            except Exception as e:
                msg = _("Error encrypting private key: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
            # Encode keys.
            self._set_key(aes_key_enc, key_encrypted, encrypted=True)

        return self._cache(callback=callback)

    @check_acls(['sign'])
    @object_lock()
    @audit_log()
    def sign_data(
        self,
        data: Union[str,None]=None,
        digest: Union[str,None]=None,
        aes_key: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Sign given data with users private key. """
        if not data and not digest:
            msg = ("Need at least 'data' or 'digest'.")
            raise OTPmeException(msg)
        if self.key_mode != "server":
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
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
            msg = _("Error loading private key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        # Try to sign data.
        try:
            signature = key.sign(message=data, digest=digest)
            signature = encode(signature, "base64")
        except Exception as e:
            msg = _("Error siging data: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        return callback.ok(signature)

    @check_acls(['verify'])
    @audit_log()
    def verify(
        self,
        signature: str,
        data: Union[str,None]=None,
        digest: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Verify given data+message with users public key. """
        if not data and not digest:
            msg = ("Need at least 'data' or 'digest'.")
            raise OTPmeException(msg)
        if self.key_mode != "server":
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
        try:
            key = RSAKey(key=decode(self.public_key, "base64"))
        except Exception as e:
            msg = _("Error loading public key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        try:
            key.verify(signature=signature,
                        message=data,
                        digest=digest)
        except Exception as e:
            msg = _("Error verifying signature: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        return callback.ok()

    @check_acls(['encrypt'])
    @audit_log()
    def encrypt(
        self,
        data: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Encrypt given data with users public key. """
        if self.key_mode != "server":
            return callback.error("Key is not handled by server.")
        if not self.public_key:
            return callback.error("User does not have a private key.")
        if run_policies:
            try:
                self.run_policies("encrypt",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
        # Try to decode public key.
        try:
            public_key = decode(self.public_key, "base64")
        except Exception as e:
            return callback.error("Unable to decode public key.")
        # Try to load public key.
        try:
            key = RSAKey(key=public_key)
        except Exception as e:
            msg = _("Error loading public key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        # Try to encrypt data.
        try:
            cipher = encode(key.encrypt(cleartext=data), "base64")
        except Exception as e:
            msg = _("Error encrypting data: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        return callback.ok(cipher)

    @check_acls(['decrypt'])
    @audit_log()
    def decrypt(
        self,
        data: str,
        aes_key: Union[str,None]=None,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Decrypt given data with users private key. """
        if self.key_mode != "server":
            return callback.error("Key is not handled by server.")
        if not self.private_key:
            return callback.error("User does not have a private key.")
        if run_policies:
            try:
                self.run_policies("decrypt",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
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
            msg = _("Error loading private key: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        # Try to decrypt data.
        data = decode(data, "base64")
        try:
            decrypted_data = key.decrypt(ciphertext=data)
        except Exception as e:
            config.raise_exception()
            msg = _("Error decrypting data: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        decrypted_data = encode(decrypted_data, "base64")
        return callback.ok(decrypted_data)

    @object_lock()
    def _handle_acl(
        self,
        action: str,
        acl: object,
        recursive_acls: bool=False,
        apply_default_acls: bool=False,
        object_types: List=[],
        verify_acls: bool=True,
        force: bool=False,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
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

    def is_admin(
        self,
        check_admin_user: bool=True,
        check_admin_role: bool=True,
        ):
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
        duration = float(end_time - start_time)
        log_msg = _("Authentication took {duration} seconds.", log=True)[1]
        log_msg = log_msg.format(duration=duration)
        logger.debug(log_msg)
        return auth_status

    def token(self, token_name: str):
        """ Return token instance. """
        token = backend.get_object(object_type="token",
                                    realm=self.realm,
                                    site=self.site,
                                    user=self.name,
                                    name=token_name)
        if token and token.destination_token:
            token.dst_token = token.get_destination_token()
        return token

    def get_tokens(
        self,
        client: Union[OTPmeObject,None]=None,
        host: Union[OTPmeObject,None]=None,
        access_group: Union[OTPmeObject,None]=None,
        resolv_token_links: bool=True,
        check_sf_tokens: bool=False,
        token_type: Union[str,None]=None,
        pass_type: Union[str,None]=None,
        token_types: Union[List,None]=None,
        pass_types: Union[List,None]=None,
        skip_disabled: bool=True,
        quiet: bool=True,
        return_type: str="uuid",
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """
        Return a list with tokens of this user, selected by access_group or all.
        """
        # List to hold tokens.
        tokens = []
        # If we got no token types list but a token type add it to list.
        if token_types is None:
            if token_type != None:
                token_types = [token_type]

        # If we got no pass types list but a pass type add it to list.
        if pass_types is None:
            if pass_type is not None:
                pass_types = [pass_type]

        def check_token_types(token_uuid, token_data, token_types=None, pass_types=None):
            """ Check if token type matches. """
            token_type_matches = False
            token_pass_type_matches = False
            if token_types:
                _token_type = token_data[token_uuid]['token_type'][0]
                # Make sure we check linked token if needed.
                if resolv_token_links:
                    try:
                        destination_token = token_data[token_uuid]['destination_token'][0]
                    except KeyError:
                        destination_token = None
                    if destination_token:
                        _token_type = token_data[destination_token]['token_type'][0]
            if pass_types:
                _token_pass_type = token_data[token_uuid]['pass_type'][0]
                # Make sure we check linked token if needed.
                if resolv_token_links:
                    try:
                        destination_token = token_data[token_uuid]['destination_token'][0]
                    except KeyError:
                        destination_token = None
                    if destination_token:
                        _token_pass_type = token_data[destination_token]['pass_type'][0]
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

        return_attrs = [
                        'name',
                        'read_oid',
                        'full_oid',
                        'rel_path',
                        'enabled',
                        'token_type',
                        'pass_type',
                        'destination_token',
                        'second_factor_token',
                        'second_factor_token_enabled',
                        ]

        token_data = {}
        if self.tokens:
            token_data = backend.search(object_type="token",
                                        attribute="uuid",
                                        values=self.tokens,
                                        return_attributes=return_attrs)

        # Walk through all tokens of the user.
        for uuid in token_data:
            add_token = False

            token_name = token_data[uuid]['name']
            token_enabled = token_data[uuid]['enabled'][0]

            if skip_disabled:
                if not token_enabled:
                    continue

            # Make sure we resolve token links.
            if resolv_token_links:
                try:
                    destination_token = token_data[uuid]['destination_token'][0]
                except KeyError:
                    destination_token = None
                # Make sure we load destination tokens.
                if destination_token:
                    if skip_disabled:
                        dst_token_result = backend.search(object_type="token",
                                                attribute="uuid",
                                                value=destination_token,
                                                return_attributes=return_attrs)
                        if not dst_token_result:
                            continue
                        token_data[destination_token] = dst_token_result[destination_token]
                        try:
                            destination_token_enabled = dst_token_result[destination_token]['enabled']
                        except KeyError:
                            continue
                        if not destination_token_enabled:
                            continue

            # Make sure we resolv token links.
            if resolv_token_links and destination_token:
                token_uuid = dst_token_result[destination_token]
            else:
                token_uuid = uuid

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
                if check_token_types(token_uuid=token_uuid,
                                    token_data=token_data,
                                    token_types=token_types,
                                    pass_types=pass_types):
                    add_token = True
                # Check second factor token if requested.
                try:
                    second_factor_token_enabled = token_data[token_uuid]['second_factor_token_enabled'][0]
                except KeyError:
                    second_factor_token_enabled = False
                if check_sf_tokens and second_factor_token_enabled:
                    try:
                        second_factor_token = token_data[token_uuid]['second_factor_token'][0]
                    except KeyError:
                        continue
                    if check_token_types(token_uuid=second_factor_token,
                                        token_data=token_data,
                                        token_types=token_types,
                                        pass_types=pass_types):
                        add_token = True
            else:
                add_token = True

            if not add_token:
                continue

            if token_uuid in tokens:
                continue

            # Append token to list if not already added.
            if not quiet:
                log_msg = _("Selecting token '{token_uuid}' based on accessgroup '{access_group_name}'.", log=True)[1]
                log_msg = log_msg.format(token_uuid=token_uuid, access_group_name=access_group.name)
                logger.debug(log_msg)
            tokens.append(token_uuid)

        result = []
        for token_uuid in tokens:
            if return_type == "instance":
                token = backend.get_object(uuid=token_uuid)
                if not token:
                    continue
                result.append(token)
            elif return_type == "uuid":
                result.append(token_uuid)
            elif return_type == "read_oid":
                read_oid = token_data[token_uuid]['read_oid']
                result.append(read_oid)
            elif return_type == "full_oid":
                full_oid = token_data[token_uuid]['full_oid']
                result.append(full_oid)
            elif return_type == "name":
                token_name = token_data[token_uuid]['name']
                result.append(token_name)
            elif return_type == "rel_path":
                rel_path = token_data[token_uuid]['rel_path']
                result.append(rel_path)

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

    def get_groups(
        self,
        return_type: str="uuid",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
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

    def get_access_groups(
        self,
        return_type: str="name",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
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

    def is_blocked(self, access_group: str, realm: str, site: str):
        """ Check if user is blocked. """
        return user_is_blocked(self.uuid, access_group, realm, site)

    def _gen_used_hash(self, string: str):
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

    def is_used_sotp(
        self,
        hash: str,
        challenge: Union[str,None]=None,
        response: Union[str,None]=None,
        ):
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
                log_msg = _("Removing expired used SOTP from backend: {self_name}", log=True)[1]
                log_msg = log_msg.format(self_name=self.name)
                logger.debug(log_msg)
                used_oid = backend.get_oid(uuid=uuid, instance=True)
                try:
                    backend.delete_object(used_oid, cluster=True)
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

    def add_used_sotp(self, hash: str):
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
            log_msg = _("Failed to add used SOTP.", log=True)[1]
            logger.warning(log_msg)

    def remove_outdated_failed_pass_hashes(self, access_group: str):
        """ Remove outdated failed pass hashes of this user. """
        # Get max fail for accessgroup.
        result = backend.search(object_type="accessgroup",
                                    realm=config.realm,
                                    site=config.site,
                                    attribute="name",
                                    value=access_group,
                                    return_attributes=['max_fail'])
        if not result:
            msg = _("Unable to get max fail: Unknown accessgroup: {access_group}")
            msg = msg.format(access_group=access_group)
            raise OTPmeException(msg)
        max_fail = result[0]

        # Get max failed pass config parameter.
        max_failed_pass = self.get_config_parameter("failed_pass_history")

        if max_fail > max_failed_pass:
            log_msg = _("Config parameter <failed_pass_history> overruled by <max_fail> of accessgroup {access_group}.", log=True)[1]
            log_msg = log_msg.format(access_group=access_group)
            logger.warning(log_msg)
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

    def count_fail(self, pass_hash: str, access_group: str):
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
            msg = _("Failed login count failed: Unknown accessgroup: {access_group}")
            msg = msg.format(access_group=access_group)
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

        log_msg = _("Counting failed login for this request.", log=True)[1]
        logger.debug(log_msg)

        # Write used pass hash config to backend.
        try:
            failed_pass.add()
            failed_pass.update_last_used_time()
            self.remove_outdated_failed_pass_hashes(access_group)
            return True
        except Exception as e:
            log_msg = _("Error counting failed login attempt: {self_oid}: {e}", log=True)[1]
            log_msg = log_msg.format(self_oid=self.oid, e=e)
            logger.critical(log_msg)
            return False

    def failcount(self, access_group: str):
        """ Return user or user/group failed login count. """
        return user_failcount(self.uuid, access_group)

    @check_acls(['unblock'])
    @backend.transaction
    @audit_log()
    def unblock(
        self,
        access_group: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        if access_group:
            group_oid = oid.get(object_type="accessgroup",
                                        realm=config.realm,
                                        site=config.site,
                                        name=access_group)
            group_uuid = backend.get_uuid(group_oid)
            if not group_uuid:
                msg = _("Unknown accessgroup: {access_group}")
                msg = msg.format(access_group=access_group)
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
    @audit_log(ignore_args=['deploy_data'])
    def deploy_token(
        self,
        token_name: str,
        token_type: str,
        smartcard_type: str,
        replace: bool=False,
        deploy_data: Union[str,None]=None,
        pre_deploy: bool=False,
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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
                        msg = _("Failed to load token class: {e}")
                        msg = msg.format(e=e)
                        return callback.error(msg)
                    # Stop if we found a token class that supports the given
                    # hardware token type.
                    if smartcard_type in _token.supported_hardware_tokens:
                        token = _token
                        break
                except Exception as e:
                    config.raise_exception()
                    msg = _("Problem loading token type '{x}': {e}")
                    msg = msg.format(x=x, e=e)
                    return callback.error(msg)

        if not token:
            msg = _("Unable to find token class to deploy hardware token: {token_type}")
            msg = msg.format(token_type=token_type)
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
                    msg = _("Existing token '{token_rel_path} ({token_token_type})' does not support hardware token type: {smartcard_type}")
                    msg = msg.format(token_rel_path=token.rel_path, token_token_type=token.token_type, smartcard_type=smartcard_type)
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
                msg = _("Creating new token of type '{token_type}' to deploy token: {token_type_second}")
                msg = msg.format(token_type=token_type, token_type_second=token_type)
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
    @audit_log(ignore_args=['password'])
    def add_token(
        self,
        token_name: Union[str,None]=None,
        token_type: Union[str,None]=None,
        token_uuid: Union[str,None]=None,
        new_token: Union[OTPmeObject,None]=None,
        destination_token: Union[str,None]=None,
        password: Union[str,None]=None,
        replace: bool=False,
        gen_qrcode: bool=True,
        no_token_infos: bool=False,
        force: bool=False,
        enable_mschap: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Adds token to user. """
        if self.template_object:
            msg = "Cannot add token to template user."
            return callback.error(msg)

        destination_token_uuid = None
        send_new_token_message = False
        if self.name == config.token_store_user:
            if token_name is None:
                # Find free token name.
                while True:
                    # Generate token name (lowercase letters and numbers).
                    token_name = stuff.gen_password(len=8, capital=False)
                    token_path = f"{self.name}/{token_name}"
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
                msg = _("Please give link destination.")
                return callback.error(msg)

            if token_type == "link":
                result = backend.search(object_type="token",
                                        attribute="rel_path",
                                        value=destination_token,
                                        return_type="uuid")

                if not result:
                    msg = _("Token does not exist: {destination_token}")
                    msg = msg.format(destination_token=destination_token)
                    return callback.error(msg)

                destination_token_uuid = result[0]

                dst_token = backend.get_object(object_type="token",
                                        uuid=destination_token_uuid)

                if not dst_token:
                    msg = _("Destination token does not exist.")
                    return callback.error(msg)

                if dst_token.token_type == "link":
                    msg = _("Cannot link already linked token.")
                    return callback.error(msg)

                if not dst_token.cross_site_links:
                    site_trusted = stuff.get_site_trust_status(dst_token.realm,
                                                                dst_token.site)
                    if not site_trusted:
                        msg = _("Token does not support cross site links: {dst_token_rel_path}")
                        msg = msg.format(dst_token_rel_path=dst_token.rel_path)
                        return callback.error(msg)

        # Check if given token exists.
        token_path = f"{self.name}/{token_name}"
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
            # Add replaced token to trash.
            if config.auth_token:
                deleted_by = f"token:{config.auth_token.rel_path}"
            else:
                deleted_by = "API"
            trash.add(cur_token.oid, deleted_by)
            # On replace we have to use the token UUID from the replaced token
            # to create the new one.
            token_uuid = cur_token.uuid
            # Delete used OTPs and counters of the old token.
            cur_token.delete_used_data_objects()
            # Remove token object from backend WITHOUT removing its UUID from
            # any role etc.
            try:
                backend.delete_object(cur_token.oid, cluster=True)
            except Exception as e:
                config.raise_exception()
                msg = _("Error removing token '{cur_token_name}': {e}")
                msg = msg.format(cur_token_name=cur_token.name, e=e)
                return callback.error(msg)
        else:
            if cur_token and not new_token:
                msg = _("Token already exists: {cur_token_rel_path}")
                msg = msg.format(cur_token_rel_path=cur_token.rel_path)
                return callback.error(msg)

        if new_token:
            if password is not None:
                new_token.change_password(password=password,
                                        verify_acls=False,
                                        callback=callback)
        else:
            # Try to create new token instance.
            try:
                from otpme.lib.token import get_class
                token_class = get_class(token_type)
                new_token = token_class(name=token_name,
                                    user=self.name,
                                    realm=self.realm,
                                    site=self.site)
            except ImportError:
                msg = _("Unknown token type: {token_type}")
                msg = msg.format(token_type=token_type)
                return callback.error(msg)
            except Exception as e:
                msg = _("Problem loading token type '{token_type}': {e}")
                msg = msg.format(token_type=token_type, e=e)
                return callback.error(msg)

            # Add the new token.
            add_status = new_token.add(uuid=token_uuid,
                                    owner_uuid=self.uuid,
                                    gen_qrcode=gen_qrcode,
                                    password=password,
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
            msg = "Trying to preserve token ACLs..."
            callback.send(msg)
            for x in cur_token.acls:
                new_token.add_acl(raw_acl=x,
                                verify_acls=False,
                                callback=callback)
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
                self.update_index('default_token', self.default_token)
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
            msg = _("Added token: {self_name}/{new_token_name}")
            msg = msg.format(self_name=self.name, new_token_name=new_token.name)
            callback.send(msg)

        return self._cache(callback=callback)

    @object_lock()
    @backend.transaction
    def del_token(
        self,
        token_name: str,
        force: bool=False,
        keep_token: bool=False,
        run_policies: bool=True,
        remove_default_token: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                    msg = _("Permission denied: {token}")
                    msg = msg.format(token=token)
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
                    self.del_index('default_token', self.default_token)
                    self.default_token = None

        check_login_token = False
        if config.auth_token:
            check_login_token = True
            if force and config.auth_token.is_admin():
                check_login_token = False

        if check_login_token:
            msg = _("Cannot delete token used at login.")
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
        acl = f"token:{token.uuid}:view"
        self.del_acl(acl=acl, verify_acls=False, callback=callback, **kwargs)

        # Remove token UUID from tokens variable of this user.
        try:
            self.tokens.remove(token.uuid)
        except ValueError:
            pass
        # Update index.
        self.del_index('token', token.uuid)

        return self._cache(callback=callback)

    @check_acls(['enable:auto_mount'])
    @object_lock()
    @audit_log()
    def enable_auto_mount(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable user disabled login. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_auto_mount",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.auto_mount = True

        return self._cache(callback=callback)

    @check_acls(['disable:auto_mount'])
    @object_lock()
    @audit_log()
    def disable_auto_mount(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable user disabled login. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_auto_mount",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.auto_mount = False

        return self._cache(callback=callback)

    @check_acls(['enable:disabled_login'])
    @object_lock()
    @audit_log()
    def enable_disabled_login(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.allow_disabled_login = True

        return self._cache(callback=callback)

    @check_acls(['disable:disabled_login'])
    @object_lock()
    @audit_log()
    def disable_disabled_login(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.allow_disabled_login = False

        return self._cache(callback=callback)

    @check_acls(['enable:autosign'])
    @object_lock()
    @audit_log()
    def enable_autosign(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.autosign_enabled = True

        return self._cache(callback=callback)

    @check_acls(['disable:autosign'])
    @object_lock()
    @audit_log()
    def disable_autosign(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.autosign_enabled = False

        return self._cache(callback=callback)

    @check_acls(['enable:auth_script'])
    @object_lock()
    @audit_log()
    def enable_auth_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable user auth script. """
        if not self.auth_script:
            msg = "Auth script not configured."
            return callback.error(msg)

        x = backend.get_object(object_type="script",
                            uuid=self.auth_script)
        if not x:
            msg = _("Script does not exist: {auth_script}")
            msg = msg.format(auth_script=self.auth_script)
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        # Check if auth_script is already enabled.
        if self.auth_script_enabled:
            msg = _("Authorization script already enabled for this user.")
            return callback.error(msg)

        self.auth_script_enabled = True
        self.update_index('auth_script_enabled', self.auth_script_enabled)

        return self._cache(callback=callback)

    @check_acls(['disable:auth_script'])
    @object_lock()
    @audit_log()
    def disable_auth_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable user auth script. """
        # Check if auth_script is already disabled.
        if not self.auth_script_enabled:
            msg = _("Authorization script already disabled for this user.")
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.auth_script_enabled = False
        self.update_index('auth_script_enabled', self.auth_script_enabled)

        return self._cache(callback=callback)

    @check_acls(['enable:login_script'])
    @object_lock()
    @audit_log()
    def enable_login_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable user login script. """
        if not self.login_script:
            msg = "Login script not configured."
            return callback.error(msg)

        x = backend.get_object(object_type="script", uuid=self.login_script)
        if not x:
            msg = _("Script does not exist: {login_script}")
            msg = msg.format(login_script=self.login_script)
            return callback.error(msg)

        # Check if login_script is already enabled.
        if self.login_script_enabled:
            msg = _("Login script already enabled for this user.")
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.login_script_enabled = True

        return self._cache(callback=callback)

    @check_acls(['disable:login_script'])
    @object_lock()
    @audit_log()
    def disable_login_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable user login script. """
        # Check if login_script is already disabled.
        if not self.login_script_enabled:
            msg = _("Login script already disabled for this user.")
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.login_script_enabled = False

        return self._cache(callback=callback)

    @check_acls(['edit:key_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    @audit_log()
    def change_key_script(
        self,
        key_script: Union[str,None]=None,
        script_options: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return self.change_script(script_var='key_script',
                        script_options_var='key_script_options',
                        script_options=script_options,
                        script=key_script, callback=callback)

    @check_acls(['edit:agent_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    @audit_log()
    def change_agent_script(
        self,
        agent_script: Union[str,None]=None,
        script_options: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return self.change_script(script_var='agent_script',
                        script_options_var='agent_script_options',
                        script_options=script_options,
                        script=agent_script, callback=callback)

    @check_acls(['edit:login_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    @audit_log()
    def change_login_script(
        self,
        login_script: Union[str,None]=None,
        script_options: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return self.change_script(script_var='login_script',
                        script_options_var='login_script_options',
                        script_options=script_options,
                        script=login_script, callback=callback)

    @check_acls(['edit:auth_script'])
    @check_special_user()
    @object_lock(full_lock=True)
    @audit_log()
    def change_auth_script(
        self,
        auth_script: Union[str,None]=None,
        script_options: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return self.change_script(script_var='auth_script',
                        script_options_var='auth_script_options',
                        script_options=script_options,
                        script=auth_script, callback=callback)

    @check_special_user()
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
            msg = _("User already exists: {user_oid}")
            msg = msg.format(user_oid=user_oid)
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
            token.path = f"{self.name}/{token.name}"
            token.set_path()
            token.set_oid()
            token._write(callback=callback)

        return rename_result

    @object_lock(full_lock=True)
    @backend.transaction
    @one_time_policy_run
    @run_pre_post_add_policies()
    @audit_log(ignore_args=['password'])
    def add(
        self,
        group: Union[str,None]=None,
        default_role: Union[str,None]=None,
        add_default_token: bool=None,
        default_token: Union[str,None]=None,
        default_token_type: Union[str,None]=None,
        template_name: Union[str,None]=None,
        template_object: Union[str,None]=None,
        gen_qrcode: bool=True,
        no_token_infos: bool=False,
        password: Union[str,None]=None,
        run_policies: bool=True,
        force: bool=False,
        verify_acls: bool=True,
        groups: Union[List,None]=None,
        default_roles: Union[List,None]=None,
        ldif_attributes: Union[str,None]=None,
        default_attributes: dict={},
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add user. """
        # Check if user exist on any site.
        result = backend.search(object_type="user",
                                attribute="name",
                                value=self.name,
                                return_type="oid")
        if result:
            user_oid = result[0]
            msg = _("User already exists: {user_oid}")
            msg = msg.format(user_oid=user_oid)
            return callback.error(msg)

        # Get template name set by policy.
        if template_name is None:
            template_name = self.template_name

        if self.template_object and template_name:
            msg = "Cannot create template from template."
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

        # If user gave us a default role we will not run defaultroles policy.
        if default_role:
            self.ignore_policy_types.append("defaultroles")
            if default_roles:
                default_roles.append(default_role)
                default_roles = list(set(default_roles))
            else:
                default_roles = [default_role]

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
                msg = _("Unknown token type: {default_token_type}")
                msg = msg.format(default_token_type=default_token_type)
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
                    msg = _("Unknown group: {group_name}")
                    msg = msg.format(group_name=group_name)
                    return callback.error(msg)
                _group = result[0]
                if verify_acls:
                    if not _group.verify_acl("add:token"):
                        msg = _("Group: {group_name}: Permission denied")
                        msg = msg.format(group_name=group_name)
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
                    msg = _("Unknown role: {role_name}")
                    msg = msg.format(role_name=role_name)
                    return callback.error(msg)
                _role = result[0]
                if verify_acls:
                    if not _role.verify_acl("add:token"):
                        msg = _("Role: {role_name}: Permission denied")
                        msg = msg.format(role_name=role_name)
                        return callback.error(msg)
                _default_roles.append(_role)

        # Handle default token from TOKENSTORE.
        _default_token = None
        if add_default_token:
            if default_token:
                default_token_path = f"{config.token_store_user}/{default_token}"
                result = backend.search(object_type="token",
                                        attribute="rel_path",
                                        value=default_token_path,
                                        return_type="instance",
                                        realm=self.realm,
                                        site=self.site)
                if not result:
                    msg = _("Unknown token: {default_token_path}")
                    msg = msg.format(default_token_path=default_token_path)
                    return callback.error(msg)
                _default_token = result[0]
                if password is not None:
                    if _default_token.token_type != "password":
                        msg = _("Unable to set password for token type: {default_token_token_type}")
                        msg = msg.format(default_token_token_type=_default_token.token_type)
                        return callback.error(msg)

            if default_token_type != "password":
                if password is not None:
                    msg = _("Unable to set password for token type: {default_token_type}")
                    msg = msg.format(default_token_type=default_token_type)
                    return callback.error(msg)

        # Get template.
        template = None
        if template_name:
            template = backend.get_object(object_type="user",
                                        realm=self.realm,
                                        site=self.site,
                                        name=template_name)
            if not template:
                msg = _("Unknown template: {template_name}")
                msg = msg.format(template_name=template_name)
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
                msg = _("Unknown group: {group}")
                msg = msg.format(group=group)
                return callback.error(msg)
            default_group = result[0]
            if verify_acls:
                if not default_group.verify_acl('add:default_group_user'):
                    msg = _("Group: {group}: Permission denied")
                    msg = msg.format(group=group)
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
                msg = _("{self_type_title} already exists.")
                msg = msg.format(self_type_title=self.type.title())
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
            inherit_error = _("WARNING: Unable to inherit ACLs from parent object: {e}")
            inherit_error = inherit_error.format(e=e)
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
                                new_user=True,
                                verify_acls=verify_acls,
                                callback=callback)
            except UnknownObject as e:
                msg = str(e)
                return callback.error(msg, exception=UnknownObject)
            except PermissionDenied as e:
               msg = "Permission denied while setting group."
               return callback.error(msg, exception=PermissionDenied)

        # Handle given LDIF attributes.
        if ldif_attributes:
            try:
                default_extensions = config.default_extensions[self.type]
            except:
                default_extensions = []
            for ext in default_extensions:
                ext_attrs = config.get_ldif_attributes(ext, self.type)
                for x in ldif_attributes:
                    try:
                        attr = x.split("=")[0]
                        value = x.split("=")[1]
                        value = value.replace("'", "")
                        value = value.replace('"', '')
                    except:
                        msg = _("Invalid attribute: {x}")
                        msg = msg.format(x=x)
                        return callback.error(msg)
                    if attr not in ext_attrs:
                        continue
                    if ext not in default_attributes:
                        default_attributes[ext] = {}
                    if attr == "uidNumber":
                        value = int(value)
                    default_attributes[ext][attr] = value

        # Add object using parent class BEFORE adding any token etc.
        add_result = super(User, self).add(template=template,
                                        run_policies=False,
                                        inherit_acls=False,
                                        verify_acls=verify_acls,
                                        default_attributes=default_attributes,
                                        verbose_level=verbose_level,
                                        callback=callback, **kwargs)
        if not add_result:
            return add_result

        # Make sure user has displayName attribute.
        self.add_attribute(attribute="displayName",
                        verify_acls=verify_acls,
                        callback=callback)

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
                msg = _("Unable to find template key script: {template_key_script}")
                msg = msg.format(template_key_script=template.key_script)
                return callback.error(msg)
            default_key_script = result[0]
        else:
            default_key_script = self.get_config_parameter("default_key_script")
        if verbose_level > 0:
            msg = _("Setting default key script: {default_key_script}")
            msg = msg.format(default_key_script=default_key_script)
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
                msg = _("Unable to find template agent script: {template_agent_script}")
                msg = msg.format(template_agent_script=template.agent_script)
                return callback.error(msg)
            default_agent_script = result[0]
        else:
            default_agent_script = self.get_config_parameter("default_agent_script")
        if verbose_level > 0:
            msg = _("Setting default agent script: {default_agent_script}")
            msg = msg.format(default_agent_script=default_agent_script)
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
                msg = _("Unable to find template login script: {template_login_script}")
                msg = msg.format(template_login_script=template.login_script)
                return callback.error(msg)
            default_login_script = result[0]
        else:
            default_login_script = self.get_config_parameter("default_login_script")
        if verbose_level > 0:
            msg = _("Setting default login script: {default_login_script}")
            msg = msg.format(default_login_script=default_login_script)
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
                msg = _("Unable to find template auth script: {template_auth_script}")
                msg = msg.format(template_auth_script=template.auth_script)
                return callback.error(msg)
            default_auth_script = result[0]
        else:
            default_auth_script = self.get_config_parameter("default_auth_script")
        if verbose_level > 0:
            msg = _("Setting default auth script: {default_auth_script}")
            msg = msg.format(default_auth_script=default_auth_script)
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
                new_token_path = f"{self.name}/{default_token_name}"
                _default_token.move(new_token_path,
                                    verify_acls=verify_acls,
                                    callback=callback)
                # Set default token password
                if password is not None:
                    _default_token.change_password(password=password,
                                                verify_acls=False,
                                                callback=callback)
            else:
                self.add_token(token_name=default_token_name,
                                token_type=default_token_type,
                                no_token_infos=no_token_infos,
                                gen_qrcode=gen_qrcode,
                                password=password,
                                verify_acls=False,
                                force=force,
                                callback=callback)
                _default_token = self.token(default_token_name)
            # Add default token to default roles.
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
            super(User, self)._run_post_add_policies(verify_acls=verify_acls,
                                                    verbose_level=verbose_level,
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
            msg = _("Unable to find {site_admin_role} role.")
            msg = msg.format(site_admin_role=config.site_admin_role)
            return callback.error(msg)

        site_admin_role = result[0]

        site_admin_role.add_token(token_path=admin_token.rel_path,
                                    verify_acls=verify_acls,
                                    callback=callback)

        # Add allow all ACL for admin token to own site.
        mysite = backend.get_object(object_type="site", uuid=config.site_uuid)
        acl = f"token:{admin_token.uuid}:all"
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
    @audit_log()
    def delete(
        self,
        force: bool=False,
        verify_acls: bool=True,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete user. """
        internal_users = config.get_internal_objects("user")
        if self.name in internal_users:
            msg = _("Cannot delete internal user: {self_name}")
            msg = msg.format(self_name=self.name)
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
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {self_name}")
                    msg = msg.format(self_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)
                # FIXME: do we need this check? allow deletion of user without permission to tokens???
                if not self.verify_acl("delete:token"):
                    msg = _("Permission denied: {self_name}")
                    msg = msg.format(self_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if not self.exists():
            return callback.error("User does not exist.")

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        token_list = self.get_tokens(return_type="instance")
        token_list_names = [i.name for i in token_list]

        if not force:
            if token_list:
                if self.confirmation_policy != "force":
                    if self.confirmation_policy == "paranoid":
                        msg = _("User has tokens: {token_list}\nPlease type '{self_name}' to delete object: ")
                        msg = msg.format(token_list=', '.join(token_list_names), self_name=self.name)
                        response = callback.ask(msg)
                        if response != self.name:
                            return callback.abort()
                    else:
                        msg = _("User has tokens: {token_list}\nDelete user '{self_name}'?: ")
                        msg = msg.format(token_list=', '.join(token_list_names), self_name=self.name)
                        response = callback.ask(msg)
                        if str(response).lower() != "y":
                            return callback.abort()
            else:
                if self.confirmation_policy == "paranoid":
                    msg = _(" Please type '{self_name}' to delete object: ")
                    msg = msg.format(self_name=self.name)
                    response = callback.ask(msg)
                    if response != self.name:
                        return callback.abort()

        # Remove user from group.
        if self.group_uuid:
            default_group = backend.get_object(uuid=self.group_uuid)
            if default_group:
                default_group.remove_default_group_user(self.uuid,
                                                verify_acls=False,
                                                ignore_missing=True,
                                                callback=callback)

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
                msg = _("Unable to remove token: {token_name}")
                msg = msg.format(token_name=token.name)
                return callback.error(msg)
            self.tokens.remove(token.uuid)

        # Remove used SOTPs.
        _used = self._get_used_sotp()
        for uuid in _used:
            used_oid = backend.get_oid(uuid)
            used_oid = oid.get(used_oid)
            try:
                backend.delete_object(used_oid, cluster=True)
            except Exception as e:
                log_msg = _("Error removing used SOTP '{used_object}' from backend: {e}", log=True)[1]
                log_msg = log_msg.format(used_object=used_object, e=e)
                logger.critical(log_msg)

        # Make sure to remove user from signers cache.
        sign_key_cache.del_cache(self.oid)

        # Delete object using parent class.
        del_status = super(User, self).delete(verbose_level=verbose_level,
                                            force=force, callback=callback)
        return del_status

    @check_acls(['remove:orphans'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def remove_orphans(
        self,
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        recursive: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

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
                msg = _("{self_type}|{self_name}: Found the following orphan ACLs: {acl_list}\n")
                msg = msg.format(self_type=self.type, self_name=self.name, acl_list=','.join(acl_list))

            if policy_list:
                msg = _("{self_type}|{self_name}: Found the following orphan policies: {policy_list}\n")
                msg = msg.format(self_type=self.type, self_name=self.name, policy_list=','.join(policy_list))

            if token_list:
                msg = _("{self_type}|{self_name}: Found the following orphan token UUIDs: {token_list}\n")
                msg = msg.format(self_type=self.type, self_name=self.name, token_list=','.join(token_list))

            if msg:
                ask_msg = _("{msg}Remove?: ")
                ask_msg = ask_msg.format(msg=msg)
                answer = callback.ask(ask_msg)
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
                    msg = _("Removing orphan token UUID: {i}")
                    msg = msg.format(i=i)
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
            msg = _("No orphan objects found for {self_type}: {self_name}")
            msg = msg.format(self_type=self.type, self_name=self.name)
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show(
        self,
        callback: JobCallback=default_callback,
        token_name: Union[str,None]=None,
        **kwargs,
        ):
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
                msg = _("Unknown token: {token_name}")
                msg = msg.format(token_name=token_name)
                return callback.error(msg)
            token_lines = token.show()
            return callback.ok(token_lines)

        from otpme.lib import cli

        lines = []
        lines.append("User info:\n")
        oid_string = f"\tOID:\t\t\t{self.oid.full_oid}\n"
        lines.append(oid_string)
        uuid_string = f"\tUUID:\t\t\t{self.uuid}\n"
        lines.append(uuid_string)
        if not self.enabled:
            lines.append("\tstatus:\t\t\tDisabled\n")
        else:
            lines.append("\tstatus:\t\t\tActive\n")

        if self.verify_acl("view:auto_disable") \
        or self.verify_acl("edit:auto_disable"):
            if self.auto_disable_time == 0:
                auto_disable = "\tauto-disable:\t\tdisabled\n"
            else:
                auto_disable = f"\tauto-disable:\t\t{self.auto_disable_time}\n"
            lines.append(auto_disable)
            unused_disable = f"\tunused-disable:\t\t{self.unused_disable}\n"
            lines.append(unused_disable)
        else:
            auto_disable = "\tauto-disable:\t\t\tPermission denied\n"
            lines.append(auto_disable)
            unused_disable = "\tunused-disable:\t\t\tPermission denied\n"
            lines.append(unused_disable)

        lines.append(f"\trealm:\t\t\t{self.realm}\n")
        lines.append(f"\tsite:\t\t\t{self.site}\n")
        if self.unit:
            lines.append(f"\tunit:\t\t\t{self.unit}\n")
        else:
            lines.append("\tunit:\t\t\t\n")

        if self.group:
            lines.append(f"\tgroup:\t\t\t{self.group}\n")
        else:
            lines.append("\tgroup:\t\t\t\n")

        if view_acl or edit_acl:
            auto_mount = "Disabled"
            if self.auto_mount:
                auto_mount = "Enabled"
            lines.append(f"\tauto-mount:\t\t{auto_mount}\n")

        if view_acl or edit_acl:
            autosign = "Disabled"
            if self.autosign_enabled:
                autosign = "Enabled"
            lines.append(f"\tauto-sign:\t\t{autosign}\n")

        if view_acl or edit_acl:
            lines.append(f"\tkey-mode:\t\t{self.key_mode}\n")

        if view_acl or edit_acl:
            allow_disabled_login = "Disabled"
            if self.allow_disabled_login:
                allow_disabled_login = "Enabled"
            lines.append(f"\tallow-disabled-login:\t{allow_disabled_login}\n")

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
                        auth_script = f"{auth_script} {auth_script_options}"
            lines.append(f"\tauth_script:\t\t{auth_script} ({auth_script_status})\n")

        if self.verify_acl("view:key_script"):
            key_script = "N/A"
            if self.key_script:
                x = backend.get_object(object_type="script", uuid=self.key_script)
                if x:
                    key_script = x.rel_path
                    if self.key_script_options:
                        key_script_options = " ".join(self.key_script_options)
                        key_script = f"{key_script} {key_script_options}"
            lines.append(f"\tkey_script:\t\t{key_script}\n")

        if self.verify_acl("view:agent_script"):
            agent_script = "N/A"
            if self.agent_script:
                x = backend.get_object(object_type="script", uuid=self.agent_script)
                if x:
                    agent_script = x.rel_path
                    if self.agent_script_options:
                        agent_script_options = " ".join(self.agent_script_options)
                        agent_script = f"{agent_script} {agent_script_options}"
            lines.append(f"\tagent_script:\t\t{agent_script}\n")

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
                        login_script = f"{login_script} {login_script_options}"
            lines.append(f"\tlogin_script:\t\t{login_script} ({login_script_status})\n")

        if self.acl_inheritance_enabled:
            lines.append("\tinherit_acls:\t\tEnabled\n")
        else:
            lines.append("\tinherit_acls:\t\tDisabled\n")

        language = "en"
        if self.language:
            language = self.language
        lines.append(f"\tlanguage:\t\t{language}\n")

        description = ""
        if self.description:
            description = self.description
        lines.append(f"\tdescription:\t\t{description}\n")

        create_time = self.create_time
        create_time = datetime.datetime.fromtimestamp(create_time)
        create_time = create_time.strftime('%d.%m.%Y %H:%M:%S')
        lines.append(f"\tcreated:\t\t{create_time}\n")

        last_modified = self.last_modified
        last_modified = datetime.datetime.fromtimestamp(last_modified)
        last_modified = last_modified.strftime('%d.%m.%Y %H:%M:%S')
        lines.append(f"\tmodified:\t\t{last_modified}\n")

        modifier = None
        if self.last_modified_by:
            if stuff.is_uuid(self.last_modified_by):
                modifier = backend.get_object(uuid=self.last_modified_by)
                if not modifier:
                    modifier = self.last_modified_by_cache
        if not modifier:
            modifier = self.last_modified_by
        lines.append(f"\tmodified_by:\t\t{modifier}\n")

        if self.last_used == 0:
            last_used = "Never"
        else:
            last_used = self.get_last_used_time(return_type="date")
            last_used = last_used.strftime('%d.%m.%Y %H:%M:%S')
        lines.append(f"\tlast_used:\t\t{last_used}\n")

        lines.append(f"\tchecksum:\t\t{self.checksum}\n")
        lines.append(f"\tsync_checksum:\t\t{self.sync_checksum}\n")
        origin = backend.get_object(uuid=self.origin)
        if not origin:
            origin = self.origin_cache
        lines.append(f"\torigin:\t\t\t{origin}\n")
        creator = None
        if self.creator:
            creator = backend.get_object(uuid=self.creator)
        if not creator:
            creator = self.creator_cache
        lines.append(f"\tcreator:\t\t{creator}\n")

        lines.append("\n")
        lines.append("User tokens:\n")

        token_lines = []
        search_regex = f"{self.name}/*"
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
