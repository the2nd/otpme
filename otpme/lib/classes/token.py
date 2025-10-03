# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from typing import List
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_pass
from otpme.lib.humanize import units
from otpme.lib.audit import audit_log
from otpme.lib.cache import config_cache
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.role import get_roles
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.register import register_module
from otpme.lib.classes.otpme_object import load_object
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.data_objects.used_otp import UsedOTP
from otpme.lib.classes.otpme_object import run_pre_post_add_policies
from otpme.lib.classes.data_objects.token_counter import TokenCounter

from otpme.lib.classes.otpme_object import \
    get_acls as _get_acls
from otpme.lib.classes.otpme_object import \
    get_value_acls as _get_value_acls
from otpme.lib.classes.otpme_object import \
    get_default_acls as _get_default_acls
from otpme.lib.classes.otpme_object import \
    get_recursive_default_acls as _get_recursive_default_acls

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

write_acls =  [
            "set_temp_password",
            "force_password",
        ]

read_acls = []

read_value_acls = {
                "view"  : [
                        "token_type",
                        "accessgroups",
                        "groups",
                        "roles",
                        "pin",
                        "pin_status",
                        "used_otp_salt",
                        "auto_disable",
                        "auth_script",
                        "dynamic_groups",
                        ],
            }

write_value_acls = {
                    "add"  : [
                                "dynamic_group",
                            ],
                    "remove"  : [
                                "dynamic_group",
                            ],
                    "edit"  : [
                                "config",
                                "auto_disable",
                            ],
                }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['dict_name'],
                    'oargs'             : ['dict_type'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'args'              : ['dict_name'],
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
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'job_type'          : 'process',
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("token"),
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'search_regex',
                                        'max_policies',
                                        'max_roles',
                                        'sort_by',
                                        'reverse',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        'realm',
                                        'site',
                                        ],
                    'job_type'          : 'thread',
                    },
                'exists'    : {
                    'method'            : 'show',
                    'args'              : ['realm'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'list'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.list_getter("token"),
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
                    'method'            : cli.list_getter("token"),
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
                    'args'              : ['new_token_path'],
                    'oargs'             : ['replace'],
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
    'dump'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump',
                    'job_type'          : 'process',
                    },
                },
            },
    'login_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_login_script',
                    'args'              : ['login_script'],
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
    'enable_offline'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_offline',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_offline'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_offline',
                    'job_type'          : 'process',
                    },
                },
            },
    'offline_expiry'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_offline_expiry',
                    'args'              : ['expiry'],
                    'job_type'          : 'process',
                    },
                },
            },
    'offline_unused_expiry'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_offline_unused_expiry',
                    'args'              : ['expiry'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_session_keep'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_session_keep',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_session_keep'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_session_keep',
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
    'list_policies'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_policies',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'list_hosts'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_hosts',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
                    },
                },
            },
    'list_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_groups',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'include_roles':False},
                    },
                },
            },
    'list_accessgroups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_access_groups',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'include_roles':False},
                    },
                },
            },
    'list_nodes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_nodes',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
                    },
                },
            },
    'list_roles'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_roles',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'recursive'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
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
    '_list_card_types'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_card_types',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_list_otp_formats'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_otp_formats',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_list_modes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_modes',
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
    'temp_password'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_temp_password',
                    'oargs'             : ['auto_password', 'temp_password', 'duration', 'remove'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_dynamic_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_dynamic_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'remove_dynamic_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_dynamic_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_dynamic_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_dynamic_groups',
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

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.accessgroup",
                "otpme.lib.classes.user",
                "otpme.lib.classes.policy",
                #"otpme.lib.classes.role",
                #"otpme.lib.token",
                "otpme.lib.classes.data_objects.used_otp",
                "otpme.lib.classes.data_objects.failed_pass",
                "otpme.lib.classes.data_objects.token_counter",
                ]

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_sync_settings()
    register_config_parameters()
    register_commands("token", commands)
    register_module("otpme.lib.classes.role")
    register_module("otpme.lib.classes.data_objects.used_otp")
    config.register_config_var("temp_pass_auth", bool, False)

def register_hooks():
    config.register_auth_on_action_hook("token", "move")
    config.register_auth_on_action_hook("token", "get_otp")
    config.register_auth_on_action_hook("token", "show_pin")
    config.register_auth_on_action_hook("token", "change_pin")
    config.register_auth_on_action_hook("token", "enable_pin")
    config.register_auth_on_action_hook("token", "disable_pin")
    config.register_auth_on_action_hook("token", "enable_mschap")
    config.register_auth_on_action_hook("token", "disable_mschap")
    config.register_auth_on_action_hook("token", "enable_offline")
    config.register_auth_on_action_hook("token", "disable_offline")
    config.register_auth_on_action_hook("token", "change_offline_expiry")
    config.register_auth_on_action_hook("token", "change_offline_unused_expiry")
    config.register_auth_on_action_hook("token", "enable_session_keep")
    config.register_auth_on_action_hook("token", "disable_session_keep")
    config.register_auth_on_action_hook("token", "enable_auth_script")
    config.register_auth_on_action_hook("token", "disable_auth_script")
    config.register_auth_on_action_hook("token", "change_auth_script")
    config.register_auth_on_action_hook("token", "change_password")
    config.register_auth_on_action_hook("token", "change_otp_format")
    config.register_auth_on_action_hook("token", "add_dynamic_group")
    config.register_auth_on_action_hook("token", "remove_dynamic_group")

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'user', 'name' ]
    read_oid_schema = [ 'realm', 'user', 'name' ]
    # OID regex stuff.
    user_path_re = oid.object_regex['user']['path']
    token_name_re = '([0-9a-z]([0-9a-z_.\-:]*[0-9a-z]){0,})'
    token_path_re = f'{user_path_re}[/]{token_name_re}'
    token_oid_re = f'token|{token_path_re}'
    oid.register_oid_schema(object_type="token",
                            valid_owners=['user'],
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=token_name_re,
                            path_regex=token_path_re,
                            oid_regex=token_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="token",
                                getter=rel_path_getter)
    # OID resovler.
    def token_oid_resolver(object_id):
        token_realm = oid.get_object_realm(object_id)
        token_user = object_id.split("|")[1].split("/")[1]
        token_name = object_id.split("|")[1].split("/")[-1]
        user_oid = f"user|{token_realm}/{token_user}"
        user_oid = oid.get(user_oid, resolve=True)
        token_oid = oid.get(object_type="token",
                            realm=token_realm,
                            site=user_oid.site,
                            user=token_user,
                            name=token_name)
        return token_oid.full_oid
    oid.register_oid_resolver(object_type="token",
                        resolver=token_oid_resolver)
    def get_object_site(object_id):
        """ Get object site from ID. """
        object_site = None
        oid_parts = object_id.split("|")[1].split("/")
        if len(oid_parts) > 3:
            object_site = oid_parts[1]
        return object_site
    oid.register_site_getter(object_type="token",
                        getter=get_object_site)
    def name_checker(object_type, object_name):
        """ Make sure object name is in correct format. """
        regex_string = oid.object_regex[object_type]['name']
        if "/" in object_name:
            regex_string = f"{oid.object_regex['token']['name']}/{regex_string}"
        regex = re.compile(f"^{regex_string}$")
        if regex.match(object_name):
            return True
    oid.register_name_checker(object_type="token",
                                getter=name_checker)
    def unit_getter(object_id):
        """ Get object unit from ID. """
        return None
    oid.register_unit_getter(object_type="token",
                            getter=unit_getter)

def register_config_parameters():
    """ Registger config parameters. """
    # Object types our config parameters are valid for.
    object_types = [
                        'site',
                        'unit',
                        'user',
                    ]
    # Allow to rename default token?
    config.register_config_parameter(name="allow_default_token_rename",
                                    ctype=bool,
                                    default_value=False,
                                    object_types=object_types)
    # Allow deletion of default token?
    config.register_config_parameter(name="allow_default_token_deletion",
                                    ctype=bool,
                                    default_value=False,
                                    object_types=object_types)
    # Allow temp passwords?
    object_types = [
                        'site',
                        'unit',
                        'user',
                        'token',
                    ]
    config.register_config_parameter(name="allow_temp_paswords",
                                    ctype=bool,
                                    default_value=False,
                                    object_types=object_types)

def register_backend():
    """ Register object for the file backend. """
    from otpme.lib import token
    # Extension for token dirs.
    token_dir_extension = "token"
    # Generic path getter.
    def _path_getter(token_oid, token_uuid, path_id):
        # Get user OID.
        user_oid = oid.get(object_type="user",
                            realm=token_oid.realm,
                            site=token_oid.site,
                            name=token_oid.user)
        user_uuid = backend.get_uuid(user_oid)
        # Get user "used" dir.
        user_used_dir = backend.get_object_dir(user_oid, user_uuid, "used_dir")
        user_used_dir = user_used_dir['used_dir']['path']
        # Build path to save used token OTPs/counters.
        used_otp_dir = f"{user_used_dir}/{path_id}/{token_uuid}"
        return used_otp_dir
    # Register used token OTP dir.
    otp_path_id = "used_otp"
    def opath_getter(token_oid, token_uuid):
        return _path_getter(token_oid, token_uuid, path_id=otp_path_id)
    backend.register_object_dir(object_type="token",
                                name=otp_path_id,
                                getter=opath_getter,
                                drop=True)
    # Register token counter dir.
    counter_path_id = "token_counter"
    def cpath_getter(token_oid, token_uuid):
        return _path_getter(token_oid, token_uuid, path_id=counter_path_id)
    backend.register_object_dir(object_type="token",
                                name=counter_path_id,
                                getter=cpath_getter,
                                drop=True)
    # Path getter for token paths.
    def path_getter(token_oid, token_uuid):
        """ Get data paths of token. """
        # Get token owner OID.
        user_oid = oid.get(object_type="user",
                            realm=token_oid.realm,
                            site=token_oid.site,
                            name=token_oid.user,
                            resolve=True,
                            full=True)
        # Get token owner config file path.
        user_paths = backend.get_config_paths(user_oid)
        if not user_paths:
            user_paths = backend.get_config_paths(user_oid, use_index=False)
        user_config_file = user_paths['config_file']

        config_paths = {}
        if not user_config_file:
            return config_paths

        # Build token config dir path.
        user_config_dir = os.path.dirname(user_config_file)
        config_dir_name = f"{token_oid.name}.{token_dir_extension}"
        config_dir = os.path.join(user_config_dir, config_dir_name)
        config_paths['config_dir'] = config_dir
        config_paths['rmtree_on_delete'] = [config_dir]

        # Add token dirs (e.g. registered above or by other token class).
        token_dirs = backend.get_object_dir(token_oid, token_uuid)
        for x in token_dirs:
            x_path = token_dirs[x]['path']
            if not x_path:
                continue
            config_paths[x] = x_path
            x_drop = token_dirs[x]['drop']
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
                'user',
                ]
        return backend.rebuild_object_index("token", objects, after)
    # Register object to config.
    config.register_object_type(object_type="token",
                            tree_object=True,
                            uniq_name=False,
                            add_after=["user"],
                            sync_after=["user"],
                            object_cache=10240,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'user', 'name'])
    # Register index attributes.
    config.register_index_attribute('token_type')
    config.register_index_attribute('owner_uuid')
    config.register_index_attribute('pass_type')
    # Register object to backend.
    class_getter = token.get_class
    class_getter_args = {'TOKEN_TYPE' : 'token_type'}
    backend.register_object_type(object_type="token",
                                dir_name_extension=token_dir_extension,
                                class_getter=class_getter,
                                class_getter_args=class_getter_args,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="token")
    config.register_object_sync(host_type="host", object_type="token")

@match_class_typing
class Token(OTPmeObject):
    """ Generic OTPme token object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        user: Union[str,None]=None,
        name: Union[str,None]=None,
        owner_uuid: Union[str,None]=None,
        path: Union[str,None]=None,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        dummy: bool=False,
        **kwargs,
        ):
        # Set our type (used in parent class)
        self.type = "token"

        self.mode = None

        # Needed for set_path in parent class init.
        self.rel_path = None
        self.owner_uuid = None
        if owner_uuid:
            self.owner_uuid = owner_uuid
        elif user and not dummy:
            self.owner = user

        # Call parent class init.
        super(Token, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        name=name,
                                        path=path,
                                        dummy=dummy,
                                        **kwargs)


        # Init global token variables but do not override when set in child
        # class.
        self.token_type = None
        self.pass_type = None
        self.otp_type = None
        self.allow_offline = None
        self.offline_expiry = None
        self.offline_unused_expiry = None
        self.keep_session = None
        self.sync_offline_otps = None
        self.sync_offline_token_counter = None
        self.counter_sync_time = None
        self.auth_script = None
        self.auth_script_options = None
        self.auth_script_enabled = None
        self.destination_token = None
        self.cross_site_links = False
        self.sftoken = None
        self.second_factor_token = None
        self.second_factor_token_enabled = False
        self.pin = None
        self.pin_len = 0
        self.pin_enabled = None
        self.pin_mandatory = None
        self.need_password = False
        # False means token type does not have a password.
        self.password_hash = False
        self.nt_hash = None
        self.mschap_enabled = None
        self.supported_hardware_tokens = []
        self.smartcard_id = None
        self.client_options = []
        self.used_otp_salt = None
        self.signatures = {}
        self.valid_token_options = []
        self.supports_qrcode = False
        self.offline_pinnable = False

        self.track_last_used = True
        self.acl_inheritance_enabled = True

        self.temp_password_expire = 0.0
        self._temp_password_hash = None
        self.temp_nt_hash = None
        self.user_acls = []
        self.token_acls = []
        self.creator_acls = []
        self.dynamic_groups = []

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "OWNER",
                            "PASS_TYPE",
                            "TOKEN_TYPE",
                            "EXTENSIONS",
                            "USED_OTP_SALT",
                            "OBJECT_CLASSES",
                            "CROSS_SITE_LINKS",
                            "DESTINATION_TOKEN",
                            "DYNAMIC_GROUPS",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "OWNER",
                            "PASS_TYPE",
                            "TOKEN_TYPE",
                            "EXTENSIONS",
                            "USED_OTP_SALT",
                            "KEEP_SESSION",
                            "OBJECT_CLASSES",
                            "CROSS_SITE_LINKS",
                            "DESTINATION_TOKEN",
                            "DYNAMIC_GROUPS",
                            ]
                        },
                    }

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is lowercase.
        self.name = name.lower()
        if self.rel_path:
            self.owner = self.rel_path.split("/")[0]

    def set_oid(self, new_oid: Union[oid.OTPmeOid,None]=None, **kwargs):
        """ Set our OID. """
        if not new_oid:
            new_oid = oid.OTPmeOid(object_type=self.type,
                                    realm=self.realm,
                                    site=self.site,
                                    user=self.owner,
                                    path=self.path,
                                    name=self.name)
        super(Token, self).set_oid(new_oid=new_oid, **kwargs)

    def set_path(self):
        """ Set object path. """
        if not self.owner:
            return
        self.path = f"/{self.realm}/{self.site}/{self.owner}/{self.name}"
        self.rel_path = f"{self.owner}/{self.name}"

    def _get_object_config(self, token_config: Union[dict,None]=None):
        """ Get object config dict. """
        token_base_config = {
                        'TOKEN_TYPE'                : {
                                                        'var_name'  : 'token_type',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },

                        'PASS_TYPE'                 : {
                                                        'var_name'  : 'pass_type',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },

                        'OWNER'                     : {
                                                        'var_name'  : 'owner_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
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

                        'ALLOW_OFFLINE'             : {
                                                        'var_name'  : 'allow_offline',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'OFFLINE_EXPIRY'            : {
                                                        'var_name'  : 'offline_expiry',
                                                        'type'      : int,
                                                        'required'  : None,
                                                    },

                        'OFFLINE_UNUSED_EXPIRY'     : {
                                                        'var_name'  : 'offline_unused_expiry',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'KEEP_SESSION'              : {
                                                        'var_name'  : 'keep_session',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'MODE'                      : {
                                                        'var_name'  : 'mode',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

                        'USED_OTP_SALT'            : {
                                                        'var_name'  : 'used_otp_salt',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },

                        'CROSS_SITE_LINKS'          : {
                                                        'var_name'  : 'cross_site_links',
                                                        'type'      : bool,
                                                        'required'  : True,
                                                    },
                        'TEMP_PASSWORD_HASH'        : {
                                                        'var_name'      : '_temp_password_hash',
                                                        'type'          : str,
                                                        'required'      : False,
                                                        'encryption'    : config.disk_encryption,
                                                    },

                        'TEMP_PASSWORD_HASH_PARAMS' : {
                                                        'var_name'      : 'temp_password_hash_params',
                                                        'type'          : list,
                                                    },

                        'TEMP_NT_HASH'              : {
                                                        'var_name'      : 'temp_nt_hash',
                                                        'type'          : str,
                                                        'required'      : False,
                                                        'encryption'    : config.disk_encryption,
                                                    },

                        'TEMP_PASSWORD_EXPIRY'      : {
                                                        'var_name'      : 'temp_password_expire',
                                                        'type'          : float,
                                                        'force_type'    : True,
                                                        'required'      : False,
                                                    },

                        'DYNAMIC_GROUPS'            : {
                                                        'var_name'      : 'dynamic_groups',
                                                        'type'          : list,
                                                        'required'      : False,
                                                    },
                        }

        object_config = {}
        # Merge token config with base token config.
        for i in token_base_config:
            if i in token_config:
                conf = token_config[i]
                token_config.pop(i)
            else:
                conf = token_base_config[i]
                object_config[i] = conf

        for i in token_config:
            object_config[i] = token_config[i]

        return object_config

    @property
    def temp_password_hash(self):
        if self.temp_password_expire is None:
            return
        now = time.time()
        if now >= self.temp_password_expire:
            return
        return self._temp_password_hash

    @temp_password_hash.setter
    def temp_password_hash(self, pass_hash: str):
        self._temp_password_hash = pass_hash

    def get_offline_config(self, second_factor_usage: bool=False):
        """
        Get offline config of token. this method should be overridden by the
        child class
        """
        # Make sure our object config is up-to-date.
        self.update_object_config()
        # Get a copy of our object config.
        offline_config = self.object_config.copy()
        # Default setting is that this token needs offline encryption.
        need_encryption = True
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    def get_parent_object(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        ):
        """ Get parent object of this token (user). """
        owner_uuid = self.owner_uuid
        if not owner_uuid:
            msg = _("Unable to get user of token: {token_oid}")
            msg = msg.format(token_oid=self.oid)
            return callback.error(msg)

        parent_object = backend.get_object(uuid=owner_uuid,
                                        object_type="user",
                                        run_policies=run_policies)
        if not parent_object:
            msg = _("Unknown parent object: {owner_uuid}")
            msg = msg.format(owner_uuid=owner_uuid)
            return callback.error(msg)

        return parent_object

    def get_sftoken(self, **kwargs):
        """ Get second factor token instance. """
        if not self.second_factor_token:
            msg = (_("No second factor token configured."))
            raise OTPmeException(msg)
        # Try to get pre set sftoken (e.g. when used offline).
        sftoken = self.sftoken
        # Load offline token if needed.
        if not sftoken:
            sftoken = backend.get_object(object_type="token",
                                uuid=self.second_factor_token)
            if not sftoken:
                msg = _("Uuuh, second factor token '{sf_token}' does not exists.")
                msg = msg.format(sf_token=self.second_factor_token)
                raise OTPmeException(msg)
            if not sftoken.pass_type in self.valid_2f_pass_types:
                msg = _("Uuuh, second factor token '{sf_token_path}' is not a valid second factor token.")
                msg = msg.format(sf_token_path=sftoken.rel_path)
                raise OTPmeException(msg)
        # Set tokens offline status.
        sftoken.offline = self.offline
        return sftoken

    def split_password(self, password: str):
        """ Split off password, OTP, PIN etc. """
        pin_len = 0
        otp_len = 0
        pin = None
        otp = None
        static_pass = None
        # If this is a OTP token get OTP len from it to cut
        # off OTP from static password/PIN.
        if self.pass_type == "otp":
            otp_len = self.otp_len
            if self.pin_enabled:
                pin_len = self.pin_len

        if self.second_factor_token and self.second_factor_token_enabled:
            # Try to load second factor token.
            sftoken = self.get_sftoken()
            # Handle OTP second factor token.
            if sftoken.pass_type == "otp":
                # Get OTP len of second factor token.
                otp_len = sftoken.otp_len
                if sftoken.pin_mandatory:
                    pin_len = sftoken.pin_len

        # Check if we have to cut off a OTP/PIN from the password.
        if otp_len is not None:
            if otp_len > 0:
                cutoff_len = otp_len
                if pin_len is not None:
                    if pin_len > 0:
                        cutoff_len += pin_len
                # Get OTP part of the password.
                pin = password[-cutoff_len:-otp_len]
                # Get OTP part of the password.
                otp = password[-otp_len:]
                # Get SSH key pass part from password.
                static_pass = password[:-cutoff_len]
            else:
                static_pass = password
        else:
            static_pass = password

        result = {
                'pin'   : pin,
                'otp'   : otp,
                'pass'  : static_pass,
                }

        return result

    def get_hash_args(self, hash_type: Union[str,None]=None):
        """ Get password hash arguments from config. """
        if hash_type is None:
            hash_type = self.get_config_parameter('default_pw_hash_type')
        hash_opts = config.get_hash_type_config_opts(hash_type)
        hash_args = {'hash_type':hash_type}
        for x_opt in hash_opts:
            x_arg = hash_opts[x_opt]['argument']
            x_val = self.get_config_parameter(x_opt)
            if x_val is None:
                x_val = hash_opts[x_opt]['default']
            hash_args[x_arg] = x_val
        # Generate salt used for password hashing.
        salt = stuff.gen_secret(16)
        hash_args['salt'] = salt
        return hash_args

    def gen_password_hash(self, password: str, quiet: bool=True):
        hash_args = self.password_hash_params
        password_hash = otpme_pass.gen_pass_hash(username=self.owner,
                                                password=password,
                                                quiet=quiet,
                                                hash_args=hash_args)['hash']
        return password_hash

    @check_acls(['upgrade_pass_hash'])
    @backend.transaction
    @audit_log()
    def upgrade_pass_hash(
        self,
        hash_type: Union[str,None]=None,
        hash_args: Union[dict,None]=None,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Upgrade password hash. """
        if hash_args is None:
            hash_args = self.get_hash_args(hash_type=hash_type)
        else:
            hash_args['hash_type'] = hash_type
        try:
            hash_data = otpme_pass.gen_pass_hash(username=self.owner,
                                        password=self.password_hash,
                                        hash_args=[hash_args])
        except OTPmeException as e:
            msg = _("Failed to upgrade password hash: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        except Exception as e:
            log_msg = _("Failed to upgrade password hash: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.critical(log_msg)
            msg = _("Internal server error.")
            return callback.error(msg)
        self.password_hash = hash_data.pop('hash')
        self.password_hash_params += hash_data['hash_args']
        return self._cache(callback=callback)

    def _gen_mschap(
        self,
        password: Union[str,None]=None,
        password_hash: Union[str,None]=None,
        callback: JobCallback=default_callback,
        ):
        """ Generate MSCHAP challenge response stuff for testing. """
        from otpme.lib import mschap_util
        return_msg = ""
        if password:
            return_msg = f"PASSWORD: {password}\n"
            password_hash = stuff.gen_nt_hash(password)
        nt_key, \
        challenge, \
        response = mschap_util.generate(self.name, password_hash)
        return_msg = f"{return_msg}NT_KEY: {nt_key}\nMSCHAP_CHALLENGE: {challenge}\nMSCHAP_RESPONSE: {response}"
        return callback.ok(return_msg)

    @cli.check_rapi_opts()
    def get_hosts(
        self,
        return_type: str="name",
        skip_disabled: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        search_attr = {
                    'token' : {
                        'value'     : self.uuid,
                        },
                    }
        if skip_disabled:
            search_attr['enabled'] = {}
            search_attr['enabled']['value'] = True
        return_attributes = ['uuid', return_type]
        hosts_search_result = backend.search(object_type="host",
                                    attributes=search_attr,
                                    return_attributes=return_attributes)
        result = []
        for uuid in hosts_search_result:
            x_result = hosts_search_result[uuid][return_type]
            if x_result in result:
                continue
            result.append(x_result)

        result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_nodes(
        self,
        return_type: str="name",
        skip_disabled: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        search_attr = {
                    'token' : {
                        'value'     : self.uuid,
                        },
                    }
        if skip_disabled:
            search_attr['enabled'] = {}
            search_attr['enabled']['value'] = True
        return_attributes = ['uuid', return_type]
        nodes_search_result = backend.search(object_type="node",
                                    attributes=search_attr,
                                    return_attributes=return_attributes)
        result = []
        for uuid in nodes_search_result:
            x_result = nodes_search_result[uuid][return_type]
            if x_result in result:
                continue
            result.append(x_result)

        result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_roles(
        self,
        return_type: str="read_oid",
        recursive: bool=False,
        _caller: str="API",
        skip_disabled: bool=True,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all roles this token is in. """
        search_attr = {
                    'token' : {
                        'value'     : self.uuid,
                        },
                    }
        if skip_disabled:
            search_attr['enabled'] = {}
            search_attr['enabled']['value'] = True
        return_attributes = ['uuid', 'site', return_type]
        roles_search_result = backend.search(object_type="role",
                                    attributes=search_attr,
                                    return_attributes=return_attributes)
        result = []
        for uuid in roles_search_result:
            if return_type == "name":
                x_result = roles_search_result[uuid]['name']
                x_site = roles_search_result[uuid]['site']
                if x_site != config.site:
                    x_result = f"{x_site}/{x_result}"
            else:
                x_result = roles_search_result[uuid][return_type]
            if x_result in result:
                continue
            result.append(x_result)

        # Get roles recursive.
        if recursive:
            return_attributes = ['uuid', 'site', return_type]
            for uuid in roles_search_result:
                role_roles = get_roles(role_uuid=uuid,
                                        parent=True,
                                        recursive=True,
                                        return_attributes=return_attributes)
                for x_role_data in role_roles:
                    if return_type == "name":
                        x_result = x_role_data['name']
                        x_site = x_role_data['site']
                        if x_site != config.site:
                            x_result = f"{x_site}/{x_result}"
                    else:
                        x_result = x_role_data[return_type]
                    if x_result in result:
                        continue
                    result.append(x_result)

        result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    def _get_access_groups(self, include_roles: bool=True):
        """ Return list with all access groups this token is in. """
        # Get access groups.
        all_groups = backend.search(realm=self.realm,
                                    attribute="name",
                                    value="*",
                                    object_type="accessgroup",
                                    return_type="instance")
        token_groups = []
        for group in all_groups:
            # Check if token is in access group.
            if self.uuid in group.tokens:
                token_groups.append(group)
                continue

            if not include_roles:
                continue

            # Check if token is one of access group's roles.
            for uuid in group.roles:
                role = backend.get_object(object_type="role", uuid=uuid)
                # Skip orphan roles.
                if not role:
                    continue
                if not role.enabled:
                    log_msg = _("Ignoring access groups of disabled role '{role_name}' for token: {token_path}", log=True)[1]
                    log_msg = log_msg.format(role_name=role.name, token_path=self.rel_path)
                    logger.debug(log_msg)
                    continue
                if self.uuid in role.tokens:
                    token_groups.append(group)
                    break
                # Check child roles too.
                child_roles = role.get_roles(return_type="instance",
                                            skip_disabled=True,
                                            recursive=True)
                for child_role in child_roles:
                    if self.uuid in child_role.tokens:
                        token_groups.append(group)
                        break
        return token_groups

    @cli.check_rapi_opts()
    def get_access_groups(
        self,
        include_roles: bool=True,
        return_type: str="name",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all access groups this token is in (cached) """
        token_groups = self._get_access_groups(include_roles=include_roles)
        result = []
        group_uuids = []
        for g in token_groups:
            group_uuids.append(g.uuid)
            if return_type == "instance":
                result.append(g)
            elif return_type == "uuid":
                result.append(g.uuid)
            elif return_type == "rel_path":
                result.append(g.oid.rel_path)
            elif return_type == "read_oid":
                result.append(g.oid.read_oid)
            elif return_type == "full_oid":
                result.append(g.oid.full_oid)
            elif return_type == "name":
                if g.site == config.site:
                    group_name = g.name
                else:
                    group_name = f"{g.site}/{g.name}"
                result.append(group_name)

        result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_groups(
        self,
        include_roles: bool=True,
        return_type: str="uuid",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all groups this token is in (cached) """
        # Get groups this token is assiged to.
        token_groups = backend.search(realm=self.realm,
                                    object_type="group",
                                    attribute="token",
                                    value=self.uuid,
                                    return_type=return_type)
        if not include_roles:
            if _caller == "RAPI":
                token_groups = ",".join(token_groups)
            if _caller == "CLIENT":
                token_groups = "\n".join(token_groups)
            return callback.ok(token_groups)
        # Get roles this token is assigned to.
        token_roles = backend.search(object_type="role",
                                    attribute="token",
                                    value=self.uuid,
                                    return_type="uuid")
        if not token_roles:
            return token_groups
        for uuid in list(token_roles):
            token_roles += get_roles(role_uuid=uuid,
                                    parent=True,
                                    recursive=True,
                                    return_type="uuid")
        # Get groups, token roles are assigned to.
        token_groups += backend.search(object_type="group",
                                    attribute="role",
                                    values=token_roles,
                                    return_type=return_type)
        if _caller == "RAPI":
            token_groups = ",".join(token_groups)
        if _caller == "CLIENT":
            token_groups = "\n".join(token_groups)
        return callback.ok(token_groups)

    @property
    def owner(self):
        """ Return name of token owner. """
        if not self.owner_uuid:
            return
        user_name = stuff.get_username_by_uuid(self.owner_uuid)
        return user_name

    @owner.setter
    def owner(self, owner_name: str):
        """ Set name of token owner. """
        if owner_name is None:
            return
        self.owner_uuid = stuff.get_user_uuid(owner_name)

    def is_admin(
        self,
        check_admin_user: bool=True,
        check_admin_role: bool=True,
        ):
        """ Check if the token has admin priviledges """
        if check_admin_user:
            if self.uuid == config.admin_token_uuid:
                return True

        if check_admin_role:
            # Check if the token is in site admin role.
            result = backend.search(attribute="uuid",
                                    value=config.admin_role_uuid,
                                    object_type="role",
                                    return_type="instance")
            if result:
                admin_role = result[0]
                if self.uuid in admin_role.tokens:
                    return True
        return False

        # This point should never be reached.
        msg = (_("WARNING: You may have hit a BUG of Token().is_admin()."))
        raise OTPmeException(msg)

    def gen_used_hash(self, data: str):
        """ Generate hash for used OTP/counter. """
        # FIXME: Are there any security implications with this????
        # Generate OTP hash from used OTP and salt. We use MD5 for this
        # because on server side we need performance and it is pointless to
        # secure the hash of an OTP that can be generated with token secrets
        # we own. On client side (e.g. a notebook) the salt is saved encrypted
        # in the token config (if possible) and thus it should also be save to
        # use MD5.
        used_salt = self.used_otp_salt
        used_hash = stuff.gen_md5(data + used_salt)
        return used_hash

    def _get_used_otps(self):
        """ Get used OTPs of this token. """
        # Check for replacement method when beeing offline (e.g. offline tokens)
        if self.offline:
            try:
                get_method = config.offline_methods['get_used_otps'][self.oid.read_oid]
            except KeyError:
                msg = _("Unable to get offline used OTPs method.")
                raise OTPmeException(msg)
            try:
                used_otps = get_method(self.oid)
            except Exception as e:
                log_msg = _("Failed to get used OTPs (offline): {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                logger.critical(log_msg)
                used_otps = []
        else:
            used_otps = backend.search(object_type="used_otp",
                                        attribute="token_uuid",
                                        value=self.uuid,
                                        return_type="instance")
        return used_otps

    #def __get_used_otps(self):
    #    """ Get used OTPs of this token. """
    #    # Check for replacement method when beeing offline (e.g. offline tokens)
    #    read_method = backend.read_config
    #    get_method = backend.get_used_otps
    #    if self.offline:
    #        try:
    #            read_method = config.offline_methods['read_config'][self.oid.read_oid]
    #        except:
    #            pass
    #        try:
    #            get_method = config.offline_methods['get_used_otps'][self.oid.read_oid]
    #        except:
    #            pass

    #    used_otps = {}
    #    for used_otp_hash in get_method(self.oid):
    #        otp_oid = oid.get(object_type="used_otp",
    #                            realm=self.realm,
    #                            site=self.site,
    #                            token_uuid=self.uuid,
    #                            pass_hash=used_otp_hash)

    #        # Try to get object config from backend.
    #        object_config = read_method(object_id=otp_oid)

    #        # Skip missing objects.
    #        # FIXME: Normally this should not happen. Should we log it?
    #        if not object_config:
    #            continue

    #        used_otps[otp_oid] = {}
    #        used_otps[otp_oid]['used_otp_hash'] = used_otp_hash
    #        used_otps[otp_oid]['object_config'] = object_config

    #    return used_otps

    def is_used_otp(self, otp: str):
        """ Check if given OTP is already used. """
        # Check for replacement method when beeing offline (e.g. offline tokens)
        delete_method = backend.delete_object
        if self.offline:
            try:
                delete_method = config.offline_methods['delete_object'][self.oid.read_oid]
            except:
                msg = _("Unable to get offline delete method.")
                raise OTPmeException(msg)

        # Indicates if OTP was already used.
        otp_was_used = False

        # Generate OTP hash.
        otp_hash = self.gen_used_hash(otp)

        # Get used OTPs.
        used_otps = self._get_used_otps()
        # Check if we got a already used OTP.
        for used_otp in used_otps:
            # Check if used OTP is expired.
            if time.time() > used_otp.expiry:
                log_msg = _("Removing expired used OTP from backend: {token_path}", log=True)[1]
                log_msg = log_msg.format(token_path=self.rel_path)
                logger.debug(log_msg)
                try:
                    if self.offline:
                        delete_method(used_otp.oid)
                    else:
                        used_otp.delete()
                except Exception as e:
                    log_msg = _("Error removing used OTP '{used_otp}' from backend: {e}", log=True)[1]
                    log_msg = log_msg.format(used_otp=used_otp, e=e)
                    logger.critical(log_msg)
                # Continue to next used OTP if this one has expired.
                continue

            # Check if token is outdated by token counter sync time (e.g. the
            # used OTP was used before the last token counter resync).
            if self.counter_sync_time:
                remove_otp = False
                # Used OTP may not have a sync time. This may happen e.g.
                # if the token was replaced by a new one and the previous one
                # did not support a sync time.
                if used_otp.sync_time is not None:
                    if used_otp.sync_time < self.counter_sync_time:
                        log_msg = _("Removing outdated (by token sync time) used OTP from backend: {token_path}", log=True)[1]
                        log_msg = log_msg.format(token_path=self.rel_path)
                        logger.debug(log_msg)
                        remove_otp = True
                if remove_otp:
                    try:
                        if self.offline:
                            delete_method(used_otp.oid)
                        else:
                            used_otp.delete()
                    except Exception as e:
                        log_msg = _("Error removing used OTP '{used_otp}' from backend: {e}", log=True)[1]
                        log_msg = log_msg.format(used_otp=used_otp, e=e)
                        logger.critical(log_msg)
                    # Continue to next used OTP if this one was outdated.
                    continue

            # Check if used OTP sum matches OTP checksum.
            if otp_hash == used_otp.object_hash:
                log_msg = _("Found already used OTP: {token_path}", log=True)[1]
                log_msg = log_msg.format(token_path=self.rel_path)
                logger.warning(log_msg)
                otp_was_used = True
                break

        return otp_was_used

    def _add_used_otp(
        self,
        otp: str,
        expiry: float,
        sync_time: Union[float,None]=None,
        session_uuid: Union[str,None]=None,
        quiet: bool=True,
        ):
        """ Add OTP to list of already used OTPs for this token. """
        if not quiet:
            log_msg = _("Adding OTP to list of used OTPs.", log=True)[1]
            logger.debug(log_msg)

        # Generate OTP hash.
        otp_hash = self.gen_used_hash(otp)

        used_otp = UsedOTP(token_uuid=self.uuid,
                            object_hash=otp_hash,
                            expiry=expiry,
                            sync_time=sync_time,
                            session_uuid=session_uuid,
                            realm=config.realm,
                            site=config.site,
                            no_transaction=True)
        if self.offline:
            try:
                add_method = config.offline_methods['add_used_otp'][self.oid.read_oid]
            except:
                msg = _("Unable to get offline add used OTP method.")
                raise OTPmeException(msg)
            try:
                add_method(used_otp)
            except Exception as e:
                log_msg = _("Failed to add used OTP (offline): {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                logger.warning(log_msg)
        else:
            try:
                used_otp.add()
            except Exception as e:
                log_msg = _("Failed to add used OTP: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                logger.warning(log_msg)

    def _add_token_counter(
        self,
        token_counter: int,
        session_uuid: Union[str,None]=None,
        ):
        """ Add token counter to shared list of this token. """
        if not isinstance(token_counter, int):
            raise OTPmeException("Need token_counter as <int>.")

        # Generate counter hash.
        counter_hash = self.gen_used_hash(str(token_counter))

        # Get sync time.
        counter_sync_time = self.counter_sync_time
        if not counter_sync_time:
            counter_sync_time = time.time()

        _token_counter = TokenCounter(token_uuid=self.uuid,
                                    counter=token_counter,
                                    object_hash=counter_hash,
                                    sync_time=counter_sync_time,
                                    session_uuid=session_uuid,
                                    realm=config.realm,
                                    site=config.site,
                                    no_transaction=True)
        if self.offline:
            try:
                add_method = config.offline_methods['add_token_counter'][self.oid.read_oid]
            except:
                msg = _("Unable to get offline add token counter method.")
                raise OTPmeException(msg)
            try:
                add_method(_token_counter)
            except Exception as e:
                msg = _("Failed to add offline token counter: {e}")
                msg = msg.format(e=e)
                raise OTPmeException(msg)
        else:
            try:
                _token_counter.add()
            except AlreadyExists:
                pass

    def _get_token_counter(self):
        """ Get all token counters. """
        if self.offline:
            try:
                get_method = config.offline_methods['get_token_counter'][self.oid.read_oid]
            except:
                msg = _("Unable to get offline token counter method.")
                raise OTPmeException(msg)
            token_counter =  get_method(self.oid)
        else:
            token_counter = backend.search(object_type="token_counter",
                                            attribute="token_uuid",
                                            value=self.uuid,
                                            return_type="instance")
        return token_counter

    def get_token_counter(self):
        """ Get the highest counter and remove all others. """
        # Check for replacement method when beeing offline (e.g. offline tokens)
        if self.offline:
            try:
                delete_method = config.offline_methods['delete_object'][self.oid.read_oid]
            except:
                msg = _("Unable to get offline delete token counter method.")
                raise OTPmeException(msg)

        counter_list = self._get_token_counter()

        # Get highest counter and delete all others.
        prev_counter = None
        highest_counter_data = (0, -1)
        for token_counter in counter_list:
            if token_counter.sync_time >= highest_counter_data[0]:
                if token_counter.counter >= highest_counter_data[1]:
                    highest_counter_data = (token_counter.sync_time,
                                            token_counter.counter)
                    if prev_counter:
                        if self.offline:
                            delete_method(prev_counter.oid)
                        else:
                            prev_counter.delete()
                    prev_counter = token_counter
                    # Continue to prevent this counter from beeing deleted.
                    continue
            if self.offline:
                delete_method(token_counter.oid)
            else:
                token_counter.delete()

        # Check if counter from token config is higher than the highest
        # backend counter.
        try:
            config_counter = self.object_config['COUNTER']
        except KeyError:
            config_counter = None
        if isinstance(config_counter, int):
            if self.counter_sync_time >= highest_counter_data[0]:
                if config_counter > highest_counter_data[1]:
                    highest_counter_data = (self.counter_sync_time, config_counter)
        # Set highest counter from highest_counter_data.
        highest_counter = highest_counter_data[1]

        return highest_counter

    @check_acls(['view_all:pin'])
    def show_pin(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Show token PIN. """
        if not self.pin:
            return callback.error(_("No PIN saved for this token."))
        if run_policies:
            try:
                self.run_policies("show_pin",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        return callback.ok(self.pin)

    @check_acls(['enable:pin'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_pin(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable optional token PIN. """
        # Check if PIN is already enabled.
        if self.pin_enabled:
            return callback.error(_("PIN is already enabled for this token."))

        if not self.pin:
            return callback.error(_("No PIN saved for thist token."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_pin",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._enable_pin(pre=True, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        self.pin_enabled = True

        return self._cache(callback=callback)

    @check_acls(['disable:pin'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_pin(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable optional token PIN. """
        if self.pin_mandatory:
            return callback.error(_("PIN is mandatory for this token."))

        if not self.pin:
            return callback.error(_("No PIN saved for thist token."))

        # Check if PIN is already disabled.
        if not self.pin_enabled:
            return callback.error(_("PIN is already disabled for this token."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_pin",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._disable_pin(pre=True, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        self.pin_enabled = False

        return self._cache(callback=callback)

    @check_acls(['enable:mschap'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_mschap(
        self,
        run_policies: bool=True,
        force: bool=False,
        quiet: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable optional MSCHAP authentication. """
        if not force:
            if not self.password_hash:
                return callback.error(_("Token does not have a password."))

        # Check if MSCHAP is already enabled.
        if self.mschap_enabled:
            return callback.error(_("MSCHAP is already enabled for this token."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_mschap",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.mschap_enabled = True

        if not quiet:
            callback.send(_("You have to set the token password after enabling "
                            "MSCHAP authentication."))

        return self._cache(callback=callback)

    @check_acls(['disable:mschap'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_mschap(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable optional MSCHAP authentication. """
        if not self.password_hash:
            return callback.error(_("Token does not have a password."))

        # Check if MSCHAP is already disabled.
        if not self.mschap_enabled:
            return callback.error(_("MSCHAP is already disabled for this token."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_mschap",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.mschap_enabled = False
        self.nt_hash = None

        return self._cache(callback=callback)

    @check_acls(['enable:offline'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_offline(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable offline usage of this token. """
        # Check if token supports offline usage.
        if self.allow_offline is None:
            return callback.error(_("Offline usage not supported by this token."))

        # Check if offline usage is already enabled.
        if self.allow_offline:
            return callback.error(_("Offline usage already enabled for this token."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_offline",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._enable_offline(pre=True, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        self.allow_offline = True
        self.update_index('allow_offline', self.allow_offline)

        # Call child class method to do object specific stuff.
        try:
            if not self._enable_offline(pre=False, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        return self._cache(callback=callback)

    @check_acls(['disable:offline'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_offline(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable offline usage of this token. """
        # Check if token supports offline usage.
        if self.allow_offline is None:
            return callback.error(_("Offline usage not supported by this token."))

        # Check if offline usage is already disabled.
        if not self.allow_offline:
            return callback.error(_("Offline usage already disabled for this token."))

        # Call child class method to do object specific stuff.
        try:
            if not self._disable_offline(pre=True, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_offline",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.allow_offline = False
        self.update_index('allow_offline', self.allow_offline)

        # Call child class method to do object specific stuff.
        try:
            if not self._disable_offline(pre=False, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        return self._cache(callback=callback)

    @check_acls(['edit:offline_expiry'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_offline_expiry(
        self,
        expiry: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Set offline expiry of this token. """
        # Check if token supports offline usage.
        if self.allow_offline is None:
            return callback.error(_("Offline usage not supported by this token."))

        # Handle human readable values.
        try:
            expiry = units.time2int(expiry, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for expiry: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_offline_expiry",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._change_offline_expiry(pre=True,
                                                callback=callback,
                                                **kwargs):
                return callback.abort()
        except:
            pass

        self.offline_expiry = expiry

        # Call child class method to do object specific stuff.
        try:
            if not self._change_offline_expiry(pre=False,
                                                callback=callback,
                                                **kwargs):
                return callback.abort()
        except:
            pass

        return self._cache(callback=callback)

    @check_acls(['edit:offline_unused_expiry'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_offline_unused_expiry(
        self,
        expiry: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set offline unused expiry of this token. """
        # Check if token supports offline usage.
        if self.allow_offline is None:
            return callback.error(_("Offline usage not supported by this token."))

        # Handle human readable values.
        try:
            expiry = units.time2int(expiry, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for expiry: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_offline_unused_expiry",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._change_offline_unused_expiry(pre=True,
                                                    callback=callback,
                                                    **kwargs):
                return callback.abort()
        except:
            pass

        self.offline_unused_expiry = expiry

        # Call child class method to do object specific stuff.
        try:
            if not self._change_offline_unused_expiry(pre=False,
                                                    callback=callback,
                                                    **kwargs):
                return callback.abort()
        except:
            pass

        return self._cache(callback=callback)

    @check_acls(['enable:session_keep'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_session_keep(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable keeping of REALM sessions for re-use after beeing offline. """
        # Check if token supports session keeping.
        if self.keep_session == None:
            return callback.error(_("Session keeping not supported by this token."))

        # Check if session keeping is already enabled.
        if self.keep_session:
            return callback.error(_("Session keeping is already enabled for this token."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_session_keep",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._enable_session_keep(pre=True,
                                            callback=callback,
                                            **kwargs):
                return callback.abort()
        except:
            pass

        self.keep_session = True
        self.update_index('keep_session', self.keep_session)

        # Call child class method to do object specific stuff.
        try:
            if not self._enable_session_keep(pre=False,
                                            callback=callback,
                                            **kwargs):
                return callback.abort()
        except:
            pass

        return self._cache(callback=callback)

    @check_acls(['disable:session_keep'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_session_keep(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable session keeping for this token. """
        # Check if token supports session keeping.
        if self.keep_session == None:
            return callback.error(_("Session keeping not supported by this "
                                    "token."))

        # Check if session keeping is already disabled.
        if not self.keep_session:
            return callback.error(_("Session keeping is already disabled for "
                                    "this token."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_session_keep",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method to do object specific stuff.
        try:
            if not self._disable_session_keep(pre=True,
                                            callback=callback,
                                            **kwargs):
                return callback.abort()
        except:
            pass

        self.keep_session = False
        self.update_index('keep_session', self.keep_session)

        # Call child class method to do object specific stuff.
        try:
            if not self._disable_session_keep(pre=False,
                                            callback=callback,
                                            **kwargs):
                return callback.abort()
        except:
            pass

        return self._cache(callback=callback)

    @check_acls(['enable:auth_script'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_auth_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable token auth script. """
        if not self.auth_script:
            return callback.error(_("No auth script set."))
        # Check if auth_script is already enabled
        if self.auth_script_enabled:
            return callback.error(_("Authorization script already enabled for "
                                    "this token."))
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
        self.auth_script_enabled = True
        self.update_index('auth_script_enabled', self.auth_script_enabled)
        return self._cache(callback=callback)

    @check_acls(['disable:auth_script'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_auth_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable token auth script. """
        # Check if auth_script is already disabled.
        if not self.auth_script_enabled:
            return callback.error(_("Authorization script already disabled for "
                                    "this token."))
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

    @check_acls(['edit:auth_script'])
    @object_lock(full_lock=True)
    @backend.transaction
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
        """ Change token auth script. """
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
                        script_options=script_options,
                        script_options_var='auth_script_options',
                        script=auth_script, callback=callback)

    def check_password(
        self,
        password: str,
        callback: JobCallback=default_callback,
        ):
        """ Check password via assiged policy. """
        # Check if token or user has configured a password policy.
        pass_policies = self.get_policies(hook='check_password',
                                        return_type="instance")
        if not pass_policies:
            user = backend.get_object(object_type="user", uuid=self.owner_uuid)
            pass_policies = user.get_policies(hook='check_password',
                                            return_type="instance")
        # Without password policy we do nothing.
        if not pass_policies:
            return True

        for x in pass_policies:
            if not x.enabled:
                continue
            if not x.handle_hook(hook_object=self,
                                hook_name="check_password",
                                password=password,
                                callback=callback):
                return callback.error()

        return callback.ok()

    def verify_temp_password(
        self,
        password: str,
        password_hash: Union[str,None]=None,
        **kwargs,
        ):
        """ Verify token temp password. """
        if password is None:
            msg = _("Attribute <password> required.")
            raise OTPmeException(msg)
        if self.temp_password_hash is None:
            return
        if self.offline:
            return
        # Create password hash if none was given.
        if not password_hash:
            hash_params = self.temp_password_hash_params
            password_hash = otpme_pass.gen_pass_hash(username=self.owner,
                                                    password=password,
                                                    hash_args=hash_params)['hash']
        # Verify temp password.
        if password_hash != self.temp_password_hash:
            return
        log_msg = _("Token verified by temp password: {token_path}", log=True)[1]
        log_msg = log_msg.format(token_path=self.rel_path)
        logger.info(log_msg)
        config.temp_pass_auth = True
        return True

    def verify_mschap_static(
        self,
        challenge: str,
        response: str,
        temp: bool=False,
        **kwargs,
        ):
        """ Verify MSCHAP challenge/response against static passwords. """
        from otpme.lib import mschap_util
        # Verify second factor token if enabled.
        if self.second_factor_token_enabled:
            log_msg = _("Cannot verify MSCHAP requests if second factor token is enabled.", log=True)[1]
            logger.warning(log_msg)
            return None, False, False

        if not self.mschap_enabled:
            log_msg = _("No MSCHAP authentication enabled for this token.", log=True)[1]
            logger.warning(log_msg)
            return None, False, False

        if temp:
            nt_hash = self.temp_nt_hash
        else:
            nt_hash = self.nt_hash

        if not nt_hash:
            log_msg = _("No NT_HASH set for this token.", log=True)[1]
            logger.debug(log_msg)
            return None, False, False

        # Get NT key from verify_mschap()
        status, \
        nt_key = mschap_util.verify(nt_hash, challenge, response)
        if status:
            if temp:
                log_msg = _("Token verified by temp password: {token_path}", log=True)[1]
                log_msg = log_msg.format(token_path=self.rel_path)
                logger.info(log_msg)
                config.temp_pass_auth = True
            return status, nt_key, nt_hash

        # Default should be None -> Token hash does not match request.
        return None, False, False

        # This point should never be reached.
        msg = _("WARNING: You may have hit a BUG of Token().verify_mschap_static().")
        raise Exception(msg)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log(ignore_args=['password'])
    def change_password(
        self,
        password: Union[str,None]=None,
        auto_password: bool=False,
        verify_current_pass: bool=False,
        force: bool=False,
        verify_acls: bool=True,
        temp: bool=False,
        run_policies=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token password. """
        if force:
            if not self.verify_acl("force_password"):
                msg = _("You are not allowed to force a unsecure password.")
                return callback.error(msg)
        # Use destination token if we have one.
        if self.destination_token:
            # Before changing password of the destination token we have to run
            # policies of this token first e.g. to run a AuthOnModify policy.
            if run_policies:
                try:
                    self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                    self.run_policies("change_password",
                                    callback=callback,
                                    _caller=_caller)
                except Exception as e:
                    return callback.error()

            dst_token = self.get_destination_token()
            return dst_token.change_password(password=password,
                                            auto_password=auto_password,
                                            force=force,
                                            verify_acls=verify_acls,
                                            callback=callback,
                                            **kwargs)
        if self.password_hash is False and not temp:
            msg = _("Token type '{token_type}' does not have a password.")
            msg = msg.format(token_type=self.token_type)
            return callback.error(msg)

        if verify_acls:
            if not self.verify_acl("edit:password"):
                msg = _("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)

        # Run policies on password change (e.g. auth_on_action).
        if run_policies and not temp:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_password",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if auto_password:
            pass_len = self.get_config_parameter("default_static_pass_len")
            password = stuff.gen_password(pass_len)

        if verify_current_pass and self.password_hash:
            current_pass = callback.askpass(_("Current password: "))
            current_hash = self.gen_password_hash(password=current_pass)
            if current_hash != self.password_hash:
                return callback.error(_("Wrong password."))

        password_checked = False
        if not password:
            while True:
                new_password1 = callback.askpass(_("New password: "))
                if new_password1 is None:
                    return callback.abort()

                if isinstance(new_password1, int):
                    new_password1 = str(new_password1)

                if not isinstance(new_password1, str):
                    msg = _("Expected password as <str> but got {password_type}.")
                    msg = msg.format(password_type=type(new_password1))
                    return callback.error(msg)

                if len(new_password1) == 0:
                    msg = _("Received empty password.")
                    return callback.error(msg)

                new_password2 = callback.askpass(_("Re-type password: "))

                if new_password2 is None:
                    return callback.abort()

                if isinstance(new_password2, int):
                    new_password2 = str(new_password2)

                if not isinstance(new_password2, str):
                    msg = _("Expected password as <str> but got {password_type}.")
                    msg = msg.format(password_type=type(new_password2))
                    return callback.error(msg)

                if new_password1 == new_password2:
                    password = new_password1
                    if not force:
                        if not self.check_password(new_password1,
                                                callback=callback):
                            return callback.error()
                        password_checked = True
                    break
                else:
                    return callback.error(_("Sorry, passwords do not match."))

        # Make sure password is a string.
        password = str(password)

        if password == "":
            return callback.error(_("Cannot set empty password."))

        if not force:
            if not password_checked:
                if not self.check_password(password, callback=callback):
                    return callback.error()

        # Create password hash.
        hash_args = self.get_hash_args()
        x = otpme_pass.gen_pass_hash(username=self.owner,
                                    password=password,
                                    hash_args=[hash_args])
        if temp:
            self.temp_password_hash = x.pop('hash')
            self.temp_password_hash_params = x['hash_args']
        else:
            self.password_hash = x.pop('hash')
            self.password_hash_params = x['hash_args']

        # Create NT hash.
        if self.mschap_enabled:
            if temp:
                self.temp_nt_hash = stuff.gen_nt_hash(password)
            else:
                self.nt_hash = stuff.gen_nt_hash(password)

        if auto_password:
            return_message = _("New password: {password}")
            return_message = return_message.format(password=password)
            callback.send(return_message)

        # Remove sessions with old password.
        if not temp:
            token_sessions = backend.get_sessions(token=self.uuid,
                                                return_type="instance")
            for session in token_sessions:
                if session.access_group == config.realm_access_group:
                    continue
                session.delete(force=True,
                            verify_acls=False)

        return self._cache(callback=callback)

    @check_acls(['set_temp_password'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log(ignore_args=['temp_password'])
    def set_temp_password(
        self,
        temp_password: Union[str,None]=None,
        auto_password: bool=False,
        duration: str="1h",
        force: bool=False,
        verify_acls: bool=True,
        remove: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set token temp password. """
        temp_passwords_allowed = self.get_config_parameter('allow_temp_paswords')
        if not temp_passwords_allowed:
            msg = _("Temporary password not allowed.")
            return callback.error(msg)
        # Use destination token if we have one.
        if self.destination_token:
            # Before changing password of the destination token we have to run
            # policies of this token first e.g. to run a AuthOnModify policy.
            if run_policies:
                try:
                    self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                    self.run_policies("change_password",
                                    callback=callback,
                                    _caller=_caller)
                except Exception as e:
                    return callback.error()

            dst_token = self.get_destination_token()
            return dst_token.set_temp_password(password=temp_password,
                                            auto_password=auto_password,
                                            remove=remove,
                                            verify_acls=verify_acls,
                                            force=force,
                                            callback=callback,
                                            **kwargs)
        # Remove temp password.
        if remove:
            self.temp_password_expire = 0.0
            self.temp_password_hash = None
            self.temp_password_hash_params = None
            return self._cache(callback=callback)

        # Run policies on password change (e.g. auth_on_action).
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("set_temp_password",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Set temp password.
        change_result = self.change_password(password=temp_password,
                                            auto_password=auto_password,
                                            verify_acls=verify_acls,
                                            force=force,
                                            temp=True,
                                            callback=callback)
        if not change_result:
            return change_result

        try:
            duration_seconds = units.time2int(duration, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for relogin timeout: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        self.temp_password_expire = time.time() + duration_seconds

        msg, log_msg = _("Token temp password set: {token_path}", log=True)
        msg = msg.format(token_path=self.rel_path)
        log_msg = log_msg.format(token_path=self.rel_path)
        add_info = [f'Duration: {duration}']
        if config.auth_token:
            add_info.append(f'Auth token: {config.auth_token.rel_path}')
        add_info = ", ".join(add_info)
        msg = f"{msg} ({add_info})"
        log_msg = f"{log_msg} ({add_info})"
        logger.info(log_msg)
        callback.send(msg)

        return self._cache(callback=callback)

    def check_pin(
        self,
        pin: str,
        callback: JobCallback=default_callback,
        ):
        """ Check PIN via assiged policy. """
        # Check if token or user has configured a PIN policy.
        pin_policies = self.get_policies(hook='check_pin',
                                        return_type="instance")
        if not pin_policies:
            user = backend.get_object(object_type="user", uuid=self.owner_uuid)
            pin_policies = user.get_policies(hook='check_pin',
                                            return_type="instance")
        # Without PIN policy we do nothing.
        if not pin_policies:
            return True

        for x in pin_policies:
            if not x.handle_hook(hook_object=self,
                                hook_name="check_pin",
                                pin=pin,
                                callback=callback):
                return callback.error()

        return callback.ok()

    @check_acls(['edit:pin'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log(ignore_args=['pin'])
    def change_pin(
        self,
        pin: Union[str,None]=None,
        auto_pin: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token PIN. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_pin",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Call child class method that may return a new PIN or just do some
        # other checks. If the method returns a int its used as the new PIN.
        # If the method returns False we abort PIN changing else we continue as
        # usual.
        x = self._change_pin(pin=pin, pre=True, callback=callback, **kwargs)
        if not isinstance(x, bool):
            pin = x
        if x is False:
            return callback.abort()

        if not pin and not auto_pin:
            answer = False
            while not answer:
                answer = callback.ask(_("Use auto-generated PIN?: "))
            if answer.lower() == "y":
                auto_pin = True

        if auto_pin:
            pin = stuff.gen_pin(self.default_pin_len)

        if not pin:
            while True:
                new_pin1 = callback.askpass(_("New PIN: "))
                if not self.check_pin(new_pin1, callback=callback):
                    return callback.error()

                new_pin2 = callback.askpass(_("Re-type PIN: "))
                if new_pin1 == new_pin2:
                    pin = new_pin1
                    break
                else:
                    return callback.error(_("Sorry, PINs do not match."))

        if not self.check_pin(pin, callback=callback):
            return callback.error()

        if auto_pin:
            return_message = _("New PIN: {pin}")
            return_message = return_message.format(pin=pin)
        else:
            return_message = None

        # Run child class method (e.g. handle token specific stuff when
        # changing the PIN).
        if not self._change_pin(pin=pin, callback=callback, **kwargs):
            return callback.abort()

        # Set new PIN.
        self.pin = pin

        # Remove sessions with old PIN.
        token_sessions = backend.get_sessions(token=self.uuid,
                                            return_type="instance")
        for session in token_sessions:
            if session.access_group == config.realm_access_group:
                continue
            session.delete(force=True, verify_acls=False)

        if return_message:
            callback.send(return_message)

        return self._cache(callback=callback)

    def get_otp(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Gen OTP and return it as string. """
        if self.destination_token:
            verify_token = self.get_destination_token()
            if not verify_token:
                return callback.error(_("Unable to get destination token."))
        else:
            verify_token = self
        if verify_token.pass_type != "otp":
            return callback.error(_("This is not a OTP token."))

        if run_policies:
            try:
                self.run_policies("get_otp",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        otp = verify_token.gen_otp(callback=callback, **kwargs)[0]
        return callback.ok(otp)

    def change_mode(self, callback: JobCallback=default_callback, **kwargs):
        """ This method must be overridden by the token child class """
        return callback.error(_("Token does not have different operation modes."))

    @check_acls(['edit:otp_format'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_otp_format(
        self,
        otp_format: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token OTP format. """
        try:
            if otp_format not in self.valid_otp_formats:
                msg = _("Unknown format: {otp_format}")
                msg = msg.format(otp_format=otp_format)
                return callback.error(msg)
        except:
            return callback.error(_("Token does not support different OTP formats."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_otp_format",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.otp_format = otp_format
        return self._cache(callback=callback)

    def get_otp_formats(
        self,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Get valid token OTP formats """
        try:
            otp_formats = self.valid_otp_formats
        except:
            otp_formats = []
        if _caller == "CLIENT":
            otp_formats = "\n".join(otp_formats)
        return callback.ok(otp_formats)

    def get_modes(
        self,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Get valid token OTP modes """
        try:
            modes = self.valid_modes
        except:
            modes = []
        if _caller == "CLIENT":
            modes = "\n".join(modes)
        return callback.ok(modes)

    def resync(self, callback: JobCallback=default_callback, **kwargs):
        """ Dummy method. """
        return callback.error(_("Invalid command for this token: resync"))

    @object_lock()
    def inherit_acls(self, callback: JobCallback=default_callback, **kwargs):
        """ Wrapper method to inherit ACLs from token owner instead of unit. """
        # Our parent object is the token owner which may already be locked
        # if this is a token add/del. So we have to acquire no lock.
        user = backend.get_object(object_type="user", uuid=self.owner_uuid)
        if not user:
            msg, log_msg = _("Unable to find user with UUID: {owner_uuid}", log=True)
            msg = msg.format(owner_uuid=self.owner_uuid)
            log_msg = log_msg.format(owner_uuid=self.owner_uuid)
            logger.critical(log_msg)
            return callback.error(msg)

        return super(Token, self).inherit_acls(parent_object=user,
                                        callback=callback, **kwargs)

    def pre_deploy(
        self,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """
        Deploy token. This method could be overridden by the token child class
        """
        return callback.ok()

    def deploy(
        self,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """
        Deploy token. This method should be overridden by the token child class
        """
        return callback.error(_("This token does not support deploying."))

    @object_lock(full_lock=True)
    @load_object(force=False)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log(ignore_args=['password'])
    def add(
        self,
        owner_uuid: str,
        verbose_level: int=0,
        write: bool=True,
        run_policies: bool=True,
        force: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add token. """
        # Set owner before running _prepare_add() to ensure parent object can
        # be determined.
        self.owner_uuid = owner_uuid
        # Update index.
        self.add_index('token_type', self.token_type)
        self.add_index('pass_type', self.pass_type)
        self.add_index('owner_uuid', self.owner_uuid)
        ## Tokens should not inherit ACLs by default.
        #self.acl_inheritance_enabled = False

        # Run parent class stuff e.g. verify ACLs.
        check_exists = True
        if force:
            check_exists = False
        prepare_add_kwargs = kwargs.copy()
        prepare_add_kwargs.pop("verify_acls")
        result = self._prepare_add(verify_acls=False,
                                    check_exists=check_exists,
                                    run_policies=run_policies,
                                    callback=callback,
                                    **prepare_add_kwargs)
        if result is False:
            return callback.error()

        # Call child class method (to do token specific stuff).
        self._add(owner_uuid=owner_uuid,
                _caller=_caller,
                callback=callback,
                verbose_level=verbose_level,
                **kwargs)

        # Add object using parent class.
        add_status = super(Token, self).add(verbose_level=verbose_level,
                                            write=write,
                                            callback=callback,
                                            **kwargs)
        return add_status

    def is_default_token(self, callback: JobCallback=default_callback):
        """ Check if token is users default token. """
        token_owner = backend.get_object(object_type="user",
                                        uuid=self.owner_uuid)
        if not token_owner:
            return False
        if self.uuid == token_owner.default_token:
            return True
        return False

    def is_special_object(self, return_true_false: bool=True):
        """ Check if object is a base or internal object. """
        base_object, \
        internal_object = cli.check_special_object("user", self.owner)
        if not return_true_false:
            return base_object, internal_object
        if base_object:
            return True
        if internal_object:
            return True
        return False

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
        """ Rename a token. """
        if self.is_default_token(callback=callback):
            allow_rename = self.get_config_parameter('allow_default_token_rename')
            if not allow_rename:
                msg = _("Default token rename is not allowed.")
                return callback.error(msg)

        # Build new OID.
        new_oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            user=self.owner,
                            name=new_name)

        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def move(
        self,
        new_token_path: str,
        force: bool=False,
        replace: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Move a token from one user to another. """
        try:
            new_owner_name = new_token_path.split("/")[0]
            new_token_name = new_token_path.split("/")[1]
        except:
            new_owner_name = new_token_path
            new_token_name = None

        owner = backend.get_object(object_type="user", uuid=self.owner_uuid)
        if not owner:
            msg = _("Uuuh, token owner does not exist: {owner_uuid}")
            msg = msg.format(owner_uuid=self.owner_uuid)
            return callback.error(msg)

        new_owner = backend.get_object(object_type="user",
                                        name=new_owner_name,
                                        realm=config.realm)
        if not new_owner:
            msg = _("Unknown user: {user_name}")
            msg = msg.format(user_name=new_owner_name)
            return callback.error(msg)

        if new_owner.site != config.site:
            msg = _("Cross site token moves are not supported yet.")
            return callback.error(msg)

        # Try to determine new token name when moving from/to TOKENSTORE.
        send_moved_message = False
        if new_owner.name == config.token_store_user:
            if new_token_name is not None:
                msg = _("Token name will be generated automatically when moving a token to the {token_store_user}.")
                msg = msg.format(token_store_user=config.token_store_user)
                return callback.error(msg)
            send_moved_message = True
            counter = 0
            # Find free token name.
            while True:
                counter_str = ""
                if counter > 0:
                    counter_str = str(counter)
                new_token_name = f"{owner.name}:{self.name}{counter_str}"
                token_path = f"{new_owner.name}/{new_token_name}"
                result = backend.search(object_type="token",
                                        attribute="rel_path",
                                        value=token_path,
                                        return_type="uuid")
                if not result:
                    break
                counter += 1

        elif owner.name == config.token_store_user:
            if new_token_name is None:
                try:
                    new_token_name = self.name.split(":")[1]
                    send_moved_message = True
                except:
                    pass

        if new_token_name is None:
            msg = _("Need token name.")
            return callback.error(msg)

        old_token_uuid = False
        is_default_token = False
        x_token = backend.get_object(object_type="token",
                                    realm=self.realm,
                                    site=self.site,
                                    name=new_token_name,
                                    user=new_owner_name)
        if x_token:
            if new_owner.default_token == x_token.uuid:
                is_default_token = True
            if not replace:
                if not force:
                    if is_default_token:
                        msg = _("Override default token: {token_path}: ")
                        msg = msg.format(token_path=x_token.rel_path)
                    else:
                        msg = _("Override existing token: {token_path}: ")
                        msg = msg.format(token_path=x_token.rel_path)
                    answer = str(callback.ask(msg))
                    if answer.lower() != "y":
                        return callback.abort()
            old_token_uuid = x_token.uuid
            # Delete object from backend instead of calling del_token()
            # to preserve token roles etc.
            del_status = backend.delete_object(x_token.oid, cluster=True)
            if not del_status:
                return del_status

        # Remove token from old owner.
        try:
            owner.del_token(token_name=self.name,
                            force=True,
                            keep_token=True,
                            remove_default_token=True,
                            _caller=_caller,
                            callback=callback)
        except Exception as e:
            msg = _("Failed to remove token from user: {owner}: {error}")
            msg = msg.format(owner=self.owner, error=e)
            return callback.error(msg)

        # Reload token config e.g. to get new ACLs after calling del_token().
        self._load()

        # FIXME: A token move is mostly a move in the backend. This will change
        #        when we support cross site moves.
        # Build new OID.
        new_oid = oid.get(object_type=self.type,
                        realm=self.realm,
                        site=self.site,
                        user=new_owner.name,
                        name=new_token_name)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("move",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        # Set new name.
        self.name = new_oid.name
        # Set new owner.
        self.owner = new_owner.name
        self.owner_uuid = new_owner.uuid
        # Update index.
        self.update_index('owner_uuid', self.owner_uuid)
        # Set new object ID.
        old_oid = self.oid
        self.set_oid(new_oid=new_oid, switch_lock=True, lock_caller="move")
        # Set new paths.
        self.set_path()
        # Update object config.
        self.update_object_config()

        # Actually move token in backend.
        if not replace:
            try:
                backend.rename_object(old_oid, new_oid)
            except Exception as e:
                config.raise_exception()
                msg = _("Error renaming {object_type} '{new_name}': {error}")
                msg = msg.format(object_type=self.type, new_name=new_oid.name, error=e)
                return callback.error(msg)

        # Set token UUID of replaced token.
        if old_token_uuid:
            self.uuid = old_token_uuid

        # Write token before adding it to new owner.
        self._write(callback=callback)

        # Add token to new owner.
        try:
            new_owner.add_token(token_name=new_token_name,
                            new_token=self,
                            replace=replace,
                            force=True,
                            _caller=_caller,
                            callback=callback)
        except Exception as e:
            msg = _("Failed to add token to user: {owner_name}: {error}")
            msg = msg.format(owner_name=new_owner.name, error=e)
            return callback.error(msg)

        # Config options may be defined per user, so we need
        # to clear the cache.
        config_cache.invalidate()

        if send_moved_message:
            msg = _("Moved token to: {owner_name}/{token_name}")
            msg = msg.format(owner_name=new_owner.name, token_name=new_token_name)
            callback.send(msg)

        return self._write(callback=callback)

    def delete_used_data_objects(self):
        """ Delete 'used' objects (e.g. token counter). """
        if self.pass_type != "otp":
            return
        # Used OTPs must be deleted for counter based tokens too.
        used_otps = self._get_used_otps()
        for used_otp in used_otps:
            used_otp.delete()
        if self.otp_type != "counter":
            return
        counter_list = self._get_token_counter()
        for token_counter in counter_list:
            token_counter.delete()

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def delete(
        self,
        force: bool=False,
        remove_default_token: bool=False,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Delete token. """
        exception = []

        if self.uuid == config.admin_token_uuid:
            if config.site_uuid == config.admin_token_uuid:
                return callback.error(_("Cannot delete realm admin token."))

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {token_path}")
                    msg = msg.format(token_path=self.rel_path)
                    return callback.error(msg, exception=PermissionDenied)

        check_default_token = False
        if not remove_default_token:
            if self.is_default_token(callback=callback):
                check_default_token = True

        if check_default_token:
            allow_delete = self.get_config_parameter('allow_default_token_deletion')
            if not allow_delete:
                msg = _("Default token deletion is not allowed.")
                return callback.error(msg)

        # Get roles to remove token from.
        token_roles = self.get_roles(return_type="instance", recursive=False)
        _token_roles = []
        for x in token_roles:
            _token_roles.append(x.name)

        # Get groups to remove token from.
        token_groups = self.get_groups(include_roles=False,
                                    return_type="instance")
        _token_groups = []
        for x in token_groups:
            _token_groups.append(x.name)

        # Get accessgroups to remove token from.
        token_accessgroups = self.get_access_groups(include_roles=False,
                                                    return_type="instance")
        _token_accessgroups = []
        for x in token_accessgroups:
            _token_accessgroups.append(x.name)

        if token_roles:
             msg = _("Token '{token_name}' is in the following roles: {roles}")
             msg = msg.format(token_name=self.name, roles=', '.join(_token_roles))
             exception.append(msg)

        if token_groups:
             msg = _("Token '{token_name}' is in the following groups: {groups}")
             msg = msg.format(token_name=self.name, groups=', '.join(_token_groups))
             exception.append(msg)

        if token_accessgroups:
             msg = _("Token '{token_name}' is in the following access groups: {access_groups}")
             msg = msg.format(token_name=self.name, access_groups=', '.join(_token_accessgroups))
             exception.append(msg)

        if self.confirmation_policy == "force":
            force = True

        if not force:
            if exception:
                if self.confirmation_policy == "paranoid":
                    msg = _("{exception_list}\nPlease type '{token_name}' to delete object: ")
                    msg = msg.format(exception_list=chr(10).join(exception), token_name=self.name)
                    response = callback.ask(msg)
                    if response != self.name:
                        return callback.abort()
                else:
                    msg = _("{exception_list}\nDelete token?: ")
                    msg = msg.format(exception_list=chr(10).join(exception))
                    response = callback.ask(msg)
                    if str(response).lower() != "y":
                        return callback.abort()
            else:
                if self.confirmation_policy == "paranoid":
                    msg = _("Please type '{token_name}' to delete object: ")
                    msg = msg.format(token_name=self.name)
                    response = callback.ask(msg)
                    if response != self.name:
                        return callback.abort()
                else:
                    msg = _("Delete token '{token_name}'?: ")
                    msg = msg.format(token_name=self.name)
                    response = callback.ask(msg)
                    if str(response).lower() != "y":
                        return callback.abort()

        # Our parent object is the token owner which may already be locked
        # if this is a token add/del. So we have to acquire no lock.
        user = backend.get_object(object_type="user", uuid=self.owner_uuid)
        # Delete sessions of this token.
        if user:
            session_list = backend.get_sessions(user=user.uuid,
                                            return_type="instance")
            for session in session_list:
                if session.auth_token != self.uuid:
                    continue
                session.delete(force=True,
                            recursive=True,
                            verify_acls=False)

        # Remove token from found objects.
        member_objects = token_roles + token_groups + token_accessgroups
        for x in member_objects:
            if x.site != config.site:
                continue
            x.remove_token(self.uuid, verify_acls=False, callback=callback)

        # Delete used OTPs and counters of this token.
        self.delete_used_data_objects()

        # Delete object using parent class.
        return super(Token, self).delete(verbose_level=verbose_level,
                                    force=force, callback=callback)

    def show_config(
        self,
        config_lines: List=[],
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Show token config. """
        lines = []

        lines.append(f'TOKEN_PATH="{self.rel_path}"')

        if self.verify_acl("view:token_type"):
            lines.append(f'TOKEN_TYPE="{self.token_type}"')
        else:
            lines.append('TOKEN_TYPE=""')

        lines.append(f'OWNER="{self.owner}"')

        if self.verify_acl("view:pass_type"):
            lines.append(f'PASS_TYPE="{self.pass_type}"')
        else:
            lines.append('PASS_TYPE=""')

        if self.verify_acl("view:accessgroups"):
            access_groups = ",".join(self.get_access_groups(include_roles=False))
            lines.append(f'ACCESS_GROUPS="{access_groups}"')
        else:
            lines.append('ACCESS_GROUPS=""')

        if self.verify_acl("view:groups"):
            groups = ",".join(self.get_groups(include_roles=False))
            lines.append(f'GROUPS="{groups}"')
        else:
            lines.append('GROUPS=""')

        if self.pin:
            if self.verify_acl("view_all:pin"):
                lines.append(f'PIN="{self.pin}"')
            else:
                lines.append('PIN=""')

            if self.verify_acl("view:pin_status"):
                lines.append(f'PIN_ENABLED="{self.pin_enabled}"')
            else:
                lines.append('PIN_ENABLED=""')

        if self.password_hash:
            if self.verify_acl("view_all:password"):
                lines.append(f'PASSWORD_HASH="{self.password_hash}"')
            else:
                lines.append('PASSWORD_HASH=""')

        if self.temp_password_hash:
            if self.verify_acl("view_all:password"):
                lines.append(f'TEMP_PASSWORD_HASH="{self.temp_password_hash}"')
            else:
                lines.append('TEMP_PASSWORD_HASH=""')

        if self.temp_password_expire:
            if self.verify_acl("view:temp_password_expire"):
                lines.append(f'TEMP_PASSWORD_EXPIRY="{self.temp_password_expire}"')
            else:
                lines.append('TEMP_PASSWORD_EXPIRY=""')

        if isinstance(self.mschap_enabled, bool):
            if self.verify_acl("view:mschap") \
                or self.verify_acl("enable:mschap") \
                or self.verify_acl("disable:mschap"):
                lines.append(f'MSCHAP_ENABLED="{self.mschap_enabled}"')
            else:
                lines.append('MSCHAP_ENABLED=""')

        if self.nt_hash:
            if self.verify_acl("view_all:nt_hash"):
                lines.append(f'NT_HASH="{self.nt_hash}"')
            else:
                lines.append('NT_HASH=""')

        # FIXME: Currently we output secret in OTPmeObject()
        #        but this may change in the future.
        #if self.secret:
        #    if self.verify_acl("view_all:secret"):
        #        lines.append(f'SECRET="{self.secret}"')
        #    else:
        #        lines.append('SECRET=""')

        auth_script = ""
        auth_script_options = ""
        if self.verify_acl("view_all:auth_script") \
        or self.verify_acl("edit:auth_script"):
            if self.auth_script:
                x = backend.get_object(object_type="script", uuid=self.auth_script)
                if x:
                    auth_script = x.rel_path
            if self.auth_script_options:
                auth_script_options = " ".join(self.auth_script_options)

        lines.append(f'AUTH_SCRIPT="{auth_script}"')
        lines.append(f'AUTH_SCRIPT_OPTIONS="{auth_script_options}"')

        if self.auth_script_enabled is not None:
            if self.verify_acl("view:auth_script") \
                or self.verify_acl("enable:auth_script") \
                or self.verify_acl("disable:auth_script"):
                lines.append(f'AUTH_SCRIPT_ENABLED="{self.auth_script_enabled}"')
            else:
                lines.append('AUTH_SCRIPT_ENABLED=""')

        if isinstance(self.allow_offline, bool):
            if self.verify_acl("view:offline_status") \
                or self.verify_acl("enable:offline") \
                or self.verify_acl("disable:offline"):
                lines.append(f'ALLOW_OFFLINE="{self.allow_offline}"')
            else:
                lines.append('ALLOW_OFFLINE=""')

        if isinstance(self.offline_expiry, int):
            if self.verify_acl("view:offline_expiry") \
                or self.verify_acl("edit:offline_expiry"):
                lines.append(f'OFFLINE_EXPIRY="{self.offline_expiry}"')
            else:
                lines.append('OFFLINE_EXPIRY=""')

        if isinstance(self.offline_unused_expiry, int):
            if self.verify_acl("view:offline_unused_expiry") \
                or self.verify_acl("edit:offline_unused_expiry"):
                lines.append(f'OFFLINE_UNUSED_EXPIRY="{self.offline_unused_expiry}"')
            else:
                lines.append('OFFLINE_UNUSED_EXPIRY=""')

        if isinstance(self.keep_session, bool):
            if self.verify_acl("view:session_keep") \
                or self.verify_acl("enable:session_keep") \
                or self.verify_acl("disable:session_keep"):
                lines.append(f'KEEP_SESSION="{self.keep_session}"')
            else:
                lines.append('KEEP_SESSION=""')

        if self.used_otp_salt is not None:
            if self.verify_acl("view_all:used_otp_salt") \
            or self.verify_acl("edit:used_otp_salt"):
                used_otp_salt = self.used_otp_salt
            else:
                used_otp_salt = ""
            lines.append(f'USED_OTP_SALT="{used_otp_salt}"')

        if self.mode is not None:
            if self.verify_acl("view:mode") or self.verify_acl("edit:mode"):
                lines.append(f'MODE="{self.mode}"')
            else:
                lines.append('MODE=""')

        lines.append(f'CROSS_SITE_LINKS="{self.cross_site_links}"')

        # Append lines from child class.
        lines += config_lines

        return super(Token, self).show_config(config_lines=lines,
                                                callback=callback,
                                                **kwargs)
