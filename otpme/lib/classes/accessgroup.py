# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.humanize import units
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.cache import assigned_host_cache
from otpme.lib.cache import assigned_device_cache
from otpme.lib.cache import assigned_token_cache
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.classes.otpme_object import name_len_setter
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

read_acls = []

write_acls = [
                "add",
                "remove",
        ]

read_value_acls = {
                "view"      : [
                            "tokens",
                            "roles",
                            "hosts",
                            "devices",
                            "child_groups",
                            "child_sessions",
                            "sessions_enabled",
                            "sotp_signing",
                            "force_sotp_signing",
                            "timeout_pass_on",
                            "max_fail",
                            "max_fail_reset",
                            "max_sessions",
                            "relogin_timeout",
                            "session_timeout",
                            "unused_session_timeout",
                            ],
            }

write_value_acls = {
                "join"       : [
                            "node",
                            "host",
                            ],
                "leave"     : [
                            "node",
                            "host",
                            ],
                "add"       : [
                            "token",
                            "role",
                            "host",
                            "device",
                            "child_group",
                            "child_session",
                            ],
                "remove"    : [
                            "token",
                            "role",
                            "host",
                            "device",
                            "child_group",
                            "child_session",
                            ],

                "set"       : [
                            "config",
                            ],
                "edit"      : [
                            "sign_public_keys",
                            "max_fail",
                            "max_fail_reset",
                            "max_sessions",
                            "relogin_timeout",
                            "session_timeout",
                            "unused_session_timeout",
                            ],
                "enable"    : [
                            "sessions",
                            "sotp_signing",
                            "force_sotp_signing",
                            "timeout_pass_on",
                            ],
                "disable"   : [
                            "sessions",
                            "sotp_signing",
                            "force_sotp_signing",
                            "timeout_pass_on",
                            ],
}

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'default'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'job_type'          : 'process',
                    },
                },
            },
    'get_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_config_parameter',
                    'args'              : ['parameter'],
                    'dargs'             : {'verify_acls':True},
                    'job_type'          : 'process',
                    },
                },
            },
    'changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_changelog',
                    'job_type'          : 'process',
                    },
                },
            },
    'edit_changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'edit_changelog',
                    'args'              : ['entry_id', 'comment'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_changelog',
                    'args'              : ['entry_id'],
                    'job_type'          : 'process',
                    },
                },
            },
    'clear_changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'clear_changelog',
                    'job_type'          : 'process',
                    },
                },
            },
    'touch'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'touch',
                    'job_type'          : 'process',
                    },
                },
            },
    'show'   : {
            'default'    : {
                'missing'    : {
                    'method'            : cli.show_getter("accessgroup"),
                    'args'              : ['realm'],
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'max_policies',
                                        'limit',
                                        'search_regex',
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
            'default'    : {
                'missing'    : {
                    'method'            : cli.list_getter("accessgroup"),
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
                    'method'            : cli.list_getter("accessgroup"),
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
            'default'    : {
                'exists'    : {
                    'method'            : 'delete',
                    'job_type'          : 'process',
                    },
                },
            },
    'show_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : ['parameter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable',
                    'job_type'          : 'process',
                    },
                },
            },
    'rename'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'rename',
                    'args'              : ['new_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'move'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'move',
                    'args'              : ['new_unit'],
                    'oargs'             : ['keep_acls'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_acl_inheritance'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_acl_inheritance'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_sessions'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable_sessions',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_sessions'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable_sessions',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_sotp_signing'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable_sotp_signing',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_sotp_signing'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable_sotp_signing',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_force_sotp_signing'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable_force_sotp_signing',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_force_sotp_signing'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable_force_sotp_signing',
                    'job_type'          : 'process',
                    },
                },
            },
    'update_sign_public_keys'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'update_sign_public_keys',
                    'oargs'             : ['username'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_timeout_pass_on'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable_timeout_pass_on',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_timeout_pass_on'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable_timeout_pass_on',
                    'job_type'          : 'process',
                    },
                },
            },
    'max_fail'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_max_fail',
                    'args'              : ['max_fail'],
                    'job_type'          : 'process',
                    },
                },
            },
    'max_fail_reset'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_max_fail_reset',
                    'args'              : ['reset_time'],
                    'job_type'          : 'process',
                    },
                },
            },
    'max_sessions'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_max_sessions',
                    'args'              : ['max_sessions'],
                    'job_type'          : 'process',
                    },
                },
            },
    'relogin_timeout'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_relogin_timeout',
                    'args'              : ['relogin_timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'timeout'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_session_timeout',
                    'args'              : ['timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'unused_timeout'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_unused_session_timeout',
                    'args'              : ['unused_timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['token_options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_role'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_role'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_host'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_host',
                    'args'              : ['host_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_host'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_host',
                    'args'              : ['host_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_device'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_device',
                    'args'              : ['device_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_device'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_device',
                    'args'              : ['device_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_child_group'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_child_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_child_group'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_child_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_child_session'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_child_session',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_child_session'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_child_session',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_policies'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_policies',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'list_tokens'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_tokens',
                    'oargs'             : ['return_type', 'token_types'],
                    'dargs'             : {'return_type':'rel_path', 'skip_disabled':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'list_roles'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_roles',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_hosts'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_hosts',
                    'job_type'          : 'process',
                    },
                },
            },
    'list_devices'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_devices',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_extension'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_extension',
                    'args'              : ['extension'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_extension'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_extension',
                    'args'              : ['extension'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_attribute'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_attribute',
                    'args'              : ['attribute'],
                    'oargs'             : ['value'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_attribute'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_attribute',
                    'args'              : ['attribute'],
                    'oargs'             : ['value'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_object_class'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_object_class',
                    'args'              : ['object_class'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_object_class'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_object_class',
                    'args'              : ['object_class'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_acl'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls',],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl'],
                    'oargs'             : ['recursive_acls', 'apply_default_acls'],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'add_policy'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_policy'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'description'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_description',
                    'oargs'             : ['description'],
                    'job_type'          : 'process',
                    },
                },
            },
    'info'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_info',
                    'oargs'             : ['info', 'language'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'dump_info'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'dump_info',
                    'oargs'             : ['language'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'export'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'export_config',
                    'oargs'             : ['password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_orphans'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_orphans',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
                    },
                },
            },
    '_show_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_config',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_list_valid_object_classes'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_valid_object_classes',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_list_valid_attributes'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_valid_attributes',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_attributes'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_attributes',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_object_classes'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_object_classes',
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_ldif'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_ldif',
                    'oargs'             : ['attributes'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_default_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_recursive_default_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'recursive_default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    'config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'set_config_param',
                    'args'              : ['parameter'],
                    'oargs'             : ['value', 'append', 'delete'],
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(split=False, **kwargs):
    result = _get_value_acls(read_value_acls, write_value_acls, split=split, **kwargs)
    config_params = config.get_config_parameters("accessgroup")
    if split:
        read_acls = result[0]['view']
        set_acls = result[1]['set']
    else:
        read_acls = result['view']
        set_acls = result['set']
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        set_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    acls = _get_default_acls(default_acls, **kwargs)
    acls += config.get_default_acls("accessgroup")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("accessgroup")
    return acls

DEFAULT_UNIT = "accessgroups"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                #"otpme.lib.classes.token",
                "otpme.lib.classes.group",
                ]

def register():
    register_oid()
    config.register_config_parameter(name="max_accessgroup_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("accessgroup", commands)
    # Register index attributes.
    config.register_index_attribute("host")
    config.register_index_attribute("device")
    config.register_index_attribute("child_group")
    config.register_index_attribute("child_session")
    config.register_index_attribute("max_fail")
    config.register_index_attribute("max_fail_reset")
    config.register_index_attribute("max_sessions")
    config.register_index_attribute("session_timeout")
    config.register_index_attribute("timeout_pass_on")
    config.register_index_attribute("sessions_enabled")
    config.register_index_attribute("relogin_timeout")
    config.register_index_attribute("unused_session_timeout")
    config.register_recursive_default_acl("site", "+accessgroup")
    config.register_default_acl("unit", "+accessgroup")
    config.register_recursive_default_acl("unit", "+accessgroup")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("accessgroup", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    accessgroup_name_re = '([0-9A-Za-z]([0-9A-Za-z_.-]*[0-9A-Za-z]){0,})'
    accessgroup_path_re = f'{unit_path_re}[/]{accessgroup_name_re}'
    accessgroup_oid_re = f'accessgroup|{accessgroup_path_re}'
    oid.register_oid_schema(object_type="accessgroup",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=accessgroup_name_re,
                            path_regex=accessgroup_path_re,
                            oid_regex=accessgroup_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="accessgroup",
                                getter=rel_path_getter)

def register_hooks():
    config.register_auth_on_action_hook("accessgroup", "add_token")
    config.register_auth_on_action_hook("accessgroup", "remove_token")
    config.register_auth_on_action_hook("accessgroup", "add_child_group")
    config.register_auth_on_action_hook("accessgroup", "remove_child_group")
    config.register_auth_on_action_hook("accessgroup", "add_child_session")
    config.register_auth_on_action_hook("accessgroup", "remove_child_session")
    config.register_auth_on_action_hook("accessgroup", "change_max_sessions")
    config.register_auth_on_action_hook("accessgroup", "change_relogin_timeout")
    config.register_auth_on_action_hook("accessgroup", "change_session_timeout")
    config.register_auth_on_action_hook("accessgroup", "change_unused_session_timeout")
    config.register_auth_on_action_hook("accessgroup", "change_max_fail")
    config.register_auth_on_action_hook("accessgroup", "change_max_fail_reset")
    config.register_auth_on_action_hook("accessgroup", "enable_sessions")
    config.register_auth_on_action_hook("accessgroup", "disable_sessions")
    config.register_auth_on_action_hook("accessgroup", "enable_sotp_signing")
    config.register_auth_on_action_hook("accessgroup", "disable_sotp_signing")
    config.register_auth_on_action_hook("accessgroup", "enable_force_sotp_signing")
    config.register_auth_on_action_hook("accessgroup", "disable_force_sotp_signing")
    config.register_auth_on_action_hook("accessgroup", "update_sign_public_keys")
    config.register_auth_on_action_hook("accessgroup", "enable_timeout_pass_on")
    config.register_auth_on_action_hook("accessgroup", "disable_timeout_pass_on")
    config.register_auth_on_action_hook("accessgroup", "set_config_parameter")

def register_backend():
    """ Register object for the file backend. """
    accessgroup_dir_extension = "accessgroup"
    def path_getter(ag_oid, ag_uuid):
        return backend.config_path_getter(ag_oid, accessgroup_dir_extension)
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
                'token',
                ]
        return backend.rebuild_object_index("accessgroup", objects, after)
    # Register object to config.
    config.register_object_type(object_type="accessgroup",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["role"],
                            sync_after=["user", "token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: AccessGroup
    backend.register_object_type(object_type="accessgroup",
                                dir_name_extension=accessgroup_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="accessgroup")

@match_class_typing
class AccessGroup(OTPmeObject):
    """ Creates access group object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        name: Union[str,None]=None,
        unit: Union[str,None]=None,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        path: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class)
        self.type = "accessgroup"

        # Call parent class init.
        super().__init__(object_id=object_id,
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

        # Set max_sessions to 0 (infinite) if none was read from config.
        self.max_sessions = 0
        # Set default relogin_timeout to 0 (immediately).
        self.relogin_timeout = 0
        # Set default max_fail.
        self.max_fail = 5
        # Reset max fail after x seconds.
        self.max_fail_reset = 0
        # Set default session timeout.
        self.session_timeout = 1800
        # Set default unused session timeout.
        self.unused_session_timeout = 300

        # Accessgroups should not inherit ACLs by default.
        self.acl_inheritance_enabled = False
        self.sessions_enabled = False
        self.timeout_pass_on = False
        # Require the client to sign the SOTP it authenticates with. Only
        # users whose sign public key is stored in the accessgroup have to
        # sign, the others authenticate as before.
        self.sotp_signing = False
        # Require every user to sign, even those without a sign public key
        # stored in the accessgroup. Those can no longer authenticate.
        self.force_sotp_signing = False

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "ROLES",
                            "TOKENS",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "SOTP_SIGNING",
                            "FORCE_SOTP_SIGNING",
                            "SIGN_PUBLIC_KEYS",
                            "ROLES",
                            "TOKENS",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'SESSIONS'                  : {
                                                        'var_name'  : 'sessions_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'PASS_ON_TIMEOUTS'          : {
                                                        'var_name'  : 'timeout_pass_on',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'SOTP_SIGNING'              : {
                                                        'var_name'  : 'sotp_signing',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'FORCE_SOTP_SIGNING'        : {
                                                        'var_name'  : 'force_sotp_signing',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'SIGN_PUBLIC_KEYS'          : {
                                                        'var_name'  : 'sign_public_keys',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },

                        'MAX_SESSIONS'              : {
                                                        'var_name'  : 'max_sessions',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'RELOGIN_TIMEOUT'           : {
                                                        'var_name'  : 'relogin_timeout',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'MAX_FAIL'                   : {
                                                        'var_name'  : 'max_fail',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'MAX_FAIL_RESET'                   : {
                                                        'var_name'  : 'max_fail_reset',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'SESSION_TIMEOUT'           : {
                                                        'var_name'  : 'session_timeout',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'UNUSED_SESSION_TIMEOUT'    : {
                                                        'var_name'  : 'unused_session_timeout',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        'HOSTS'                     : {
                                                        'var_name'  : 'hosts',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'DEVICES'                   : {
                                                        'var_name'  : 'devices',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'CHILD_GROUPS'              : {
                                                        'var_name'  : 'child_groups',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'CHILD_SESSIONS'            : {
                                                        'var_name'  : 'child_sessions',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'ROLES'                     : {
                                                        'var_name'  : 'roles',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'TOKENS'                    : {
                                                        'var_name'  : 'tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'TOKEN_OPTIONS'             : {
                                                        'var_name'  : 'token_options',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },

                        'TOKEN_LOGIN_INTERFACES'    : {
                                                        'var_name'  : 'token_login_interfaces',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
            }

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # If unused_session_timeout is greater than session_timeout set it to
        # session_timeout.
        if self.unused_session_timeout is not None \
        and self.session_timeout is not None:
            if self.unused_session_timeout > self.session_timeout:
                self.unused_session_timeout = self.session_timeout
        # Set OID.
        self.set_oid()

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is a string.
        name = str(name)
        # Only base accessgroups must have uppercase names.
        base_access_groups = config.get_base_objects("accessgroup")
        if name.upper() in base_access_groups:
            self.name = name.upper()
        else:
            self.name = name.lower()

    def get_master_group(self):
        parents = self.parents(recursive=True,
                            return_type="instance")
        if not parents:
            return None
        master = parents[-1]
        return master

    @assigned_token_cache.cache_method()
    def is_assigned_token(
        self,
        token_uuid: str,
        skip_disabled_roles: bool=True,
        skip_disabled_groups: bool=True,
        check_parent_groups: bool=False,
        ):
        """ Check if token is assigned to this acccessgroup. """
        if token_uuid in self.tokens:
            return self.uuid
        for role_uuid in self.roles:
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if not role:
                continue
            if skip_disabled_roles:
                if not role.enabled:
                    continue
            if role.is_assigned_token(token_uuid):
                return role.uuid
        if not check_parent_groups:
            return False
        parent_groups = self.parents(recursive=False,
                                    return_type="instance",
                                    skip_disabled=skip_disabled_groups)
        for group in parent_groups:
            if skip_disabled_groups:
                if not group.enabled:
                    continue
            if group.is_assigned_token(token_uuid):
                return group.uuid
        return False

    @assigned_host_cache.cache_method()
    def is_assigned_host(
        self,
        host_uuid: str,
        skip_disabled_roles: bool=True,
        skip_disabled_groups: bool=True,
        check_parent_groups: bool=False,
        ):
        """ Check if host is assigned to this acccessgroup. """
        if host_uuid in self.hosts:
            return self.uuid
        for role_uuid in self.roles:
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if not role:
                continue
            if skip_disabled_roles:
                if not role.enabled:
                    continue
            if role.is_assigned_host(host_uuid):
                return role.uuid
        if not check_parent_groups:
            return False
        parent_groups = self.parents(recursive=False,
                                    return_type="instance",
                                    skip_disabled=skip_disabled_groups)
        for group in parent_groups:
            if skip_disabled_groups:
                if not group.enabled:
                    continue
            if group.is_assigned_host(host_uuid):
                return group.uuid
        return False

    @assigned_device_cache.cache_method()
    def is_assigned_device(
        self,
        device_uuid: str,
        skip_disabled_roles: bool=True,
        skip_disabled_groups: bool=True,
        check_parent_groups: bool=False,
        ):
        """ Check if device is assigned to this acccessgroup. """
        if device_uuid in self.devices:
            return self.uuid
        for role_uuid in self.roles:
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if not role:
                continue
            if skip_disabled_roles:
                if not role.enabled:
                    continue
            if role.is_assigned_device(device_uuid):
                return role.uuid
        if not check_parent_groups:
            return False
        parent_groups = self.parents(recursive=False,
                                    return_type="instance",
                                    skip_disabled=skip_disabled_groups)
        for group in parent_groups:
            if skip_disabled_groups:
                if not group.enabled:
                    continue
            if group.is_assigned_device(device_uuid):
                return group.uuid
        return False

    def parents(
        self,
        sessions: bool=None,
        recursive: bool=False,
        return_type: str='name',
        skip_disabled: bool=True,
        ):
        """ Get all parent groups of this group. """
        child_attribute = "child_group"
        if sessions:
            child_attribute = "child_session"
        result = backend.search(realm=self.realm,
                                site=self.site,
                                object_type="accessgroup",
                                attribute=child_attribute,
                                value=self.uuid,
                                return_type="instance")
        _result = []
        for x_ag in result:
            if skip_disabled:
                if not x_ag.enabled:
                    continue
            if return_type == "uuid":
                _result.append(x_ag.uuid)
            elif return_type == "name":
                _result.append(x_ag.name)
            elif return_type == "oid":
                _result.append(x_ag.oid)
            elif return_type == "read_oid":
                _result.append(x_ag.oid.read_oid)
            elif return_type == "full_oid":
                _result.append(x_ag.oid.full_oid)
            elif return_type == "instance":
                _result.append(x_ag)
            else:
                msg = _("Unsupported return type: {return_type}")
                msg = msg.format(return_type=return_type)
                raise OTPmeException(msg)
            if not recursive:
                continue
            _result += x_ag.parents(recursive=recursive,
                                    sessions=sessions,
                                    return_type=return_type)
        return _result

    def childs(
        self,
        recursive: bool=False,
        sessions: bool=False,
        return_type: str='name',
        skip_disabled: bool=True,
        ):
        """ Get all child groups of this group. """
        result = []
        join_attribute = "child_group"
        if sessions:
            join_attribute = "child_session"
        return_attrs = ['uuid', 'enabled']
        if return_type != "instance":
            return_attrs.append(return_type)
        # Get child accessgroups/sessions.
        childs = backend.search(object_type="accessgroup",
                                join_object_type="accessgroup",
                                join_search_attr="uuid",
                                join_search_val=self.uuid,
                                join_attribute=join_attribute,
                                attribute="uuid",
                                value="*",
                                return_attributes=return_attrs)
        if recursive and childs:
            child_childs = list(childs)
            while True:
                check_childs = list(child_childs)
                child_childs = []
                for uuid in check_childs:
                    x_childs = backend.search(object_type="accessgroup",
                                            join_object_type="accessgroup",
                                            join_search_attr="uuid",
                                            join_search_val=uuid,
                                            join_attribute=join_attribute,
                                            attribute="uuid",
                                            value="*",
                                            return_attributes=return_attrs)
                    if not x_childs:
                        continue
                    for x_uuid in x_childs:
                        if x_uuid in childs:
                            continue
                        childs[x_uuid] = x_childs[x_uuid]
                    child_childs += x_childs
                if not child_childs:
                    break

        for uuid in childs:
            if skip_disabled:
                try:
                    group_enabled = childs[uuid]['enabled'][0]
                except Exception:
                    group_enabled = False
                if not group_enabled:
                    continue
            if return_type == "instance":
                p = backend.get_object(object_type="accessgroup", uuid=uuid)
                result.append(p)
            elif return_type == "uuid":
                result.append(uuid)
            else:
                return_attribute = childs[uuid][return_type]
                result.append(return_attribute)
        return result

    @check_acls(['add:child_group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("add child group {group_name}")
    def add_child_group(
        self,
        group_name: str,
        force: bool=False,
        verify_acls: bool=True,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a child group to this group. """
        group = backend.get_object(object_type="accessgroup",
                                    realm=config.realm,
                                    site=self.site,
                                    name=group_name)
        if not group:
            msg = _("Accessgroup does not exist: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        if group.uuid == self.uuid:
            msg = _("Cannot add a group as child group of itself.")
            return callback.error(msg)

        # Check for current parent.
        result = backend.search(object_type="accessgroup",
                                attribute="child_group",
                                value=group.uuid,
                                realm=config.realm,
                                site=self.site,
                                return_type="name")
        if result:
            current_parent = result[0]
            if current_parent:
                msg = _("Group is already a child group of group: {current_parent}")
                msg = msg.format(current_parent=current_parent)
                return callback.error(msg)

        # Access is inherited from parent to child: is_assigned_token()
        # walks parents(), so our tokens and the tokens of our roles gain
        # access to the child group. This way in must not be cheaper than
        # putting them there directly, and the decorator only covers us --
        # the group the caller already controls.
        # Either ACL is enough, because either one alone already produces
        # the same access directly: add:token by entering the tokens,
        # add:role by adding a role that holds them.
        # add:host is not needed: is_assigned_host() has a parent branch but
        # no caller passes check_parent_groups, so hosts do not inherit.
        if verify_acls:
            if not group.verify_acl("add:token") \
            and not group.verify_acl("add:role"):
                msg = _("Permission denied: {group_name}")
                msg = msg.format(group_name=group.name)
                return callback.error(msg, exception=PermissionDenied)

        if group.uuid in self.childs(return_type="uuid"):
            msg = _("Group is already a child group of this group.")
            return callback.error(msg)

        result = backend.search(realm=self.realm,
                                site=self.site,
                                object_type="accessgroup",
                                attribute="child_group",
                                value=group.uuid,
                                return_type="name")
        if result:
            group_name = result[0]
            msg = _("Group is already in child groups of group '{group_name}'.")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        msg = _("Add child group '{child_group}' to accessgroup '{group_name}'? The tokens of this group gain access to the child group.: ")
        msg = msg.format(child_group=group.name, group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_child_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Append child group UUID to child groups.
        self.child_groups.append(group.uuid)
        # Update index.
        self.add_index("child_group", group.uuid)

        return self._cache(callback=callback)

    @check_acls(['remove:child_group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("remove child group {group_name}")
    def remove_child_group(
        self,
        group_name: str,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Removes a child group from this group. """
        group = backend.get_object(object_type="accessgroup",
                                realm=config.realm,
                                site=self.site,
                                name=group_name)
        if not group:
            msg = _("Accessgroup does not exist: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        if not group.uuid in self.childs(return_type="uuid"):
            msg = _("Group is not a child group of group '{group_name}'.")
            msg = msg.format(group_name=self.name)
            return callback.error(msg)

        msg = _("Remove child group '{child_group}' from accessgroup '{group_name}'?: ")
        msg = msg.format(child_group=group.name, group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_child_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Remove child group UUID from child groups.
        self.child_groups.remove(group.uuid)
        # Update index.
        self.del_index("child_group", group.uuid)

        return self._cache(callback=callback)

    @check_acls(['add:child_session'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("add child session group {group_name}")
    def add_child_session(
        self,
        group_name: str,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a child session to this group. """
        group = backend.get_object(object_type="accessgroup",
                                realm=config.realm,
                                site=self.site,
                                name=group_name)
        if not group:
            msg = _("Accessgroup does not exist: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        if group.uuid == self.uuid:
            msg = _("Cannot add a group as child session of itself.")
            return callback.error(msg)

        if group.uuid in self.childs(sessions=True, return_type="uuid"):
            msg = _("Group is already a child sessions of this group.")
            return callback.error(msg)

        result = backend.search(realm=self.realm,
                                site=self.site,
                                object_type="accessgroup",
                                attribute="child_session",
                                value=group.uuid,
                                return_type="name")
        if result:
            group_name = result[0]
            msg = _("Group is already in child sessions of group '{group_name}'.")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        msg = _("Add child session group '{child_group}' to accessgroup '{group_name}'?: ")
        msg = msg.format(child_group=group.name, group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_child_session",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Append child group UUID to child sessions.
        self.child_sessions.append(group.uuid)
        # Update index.
        self.add_index("child_session", group.uuid)

        return self._cache(callback=callback)

    @check_acls(['remove:child_session'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("remove child session group {group_name}")
    def remove_child_session(
        self,
        group_name: str,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Removes a child session from this group. """
        group = backend.get_object(object_type="accessgroup",
                                realm=config.realm,
                                site=self.site,
                                name=group_name)
        if not group:
            msg = _("Accessgroup does not exist: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        if not group.uuid in self.childs(sessions=True, return_type="uuid"):
            msg = _("Group is not a child session of group '{group_name}'.")
            msg = msg.format(group_name=self.name)
            return callback.error(msg)

        msg = _("Remove child session group '{child_group}' from accessgroup '{group_name}'?: ")
        msg = msg.format(child_group=group.name, group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_child_session",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Remove child group UUID from child sessions.
        self.child_sessions.remove(group.uuid)
        # Update index.
        self.del_index("child_session", group.uuid)

        return self._cache(callback=callback)

    @check_acls(['edit:max_sessions'])
    @object_lock()
    @audit_log()
    @object_changelog("change max sessions to {max_sessions}")
    def change_max_sessions(
        self,
        max_sessions: int=0,
        run_policies: bool=True,
        force: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change max sessions for this group. """
        msg = _("Change max sessions of accessgroup '{group_name}' to '{max_sessions}'?: ")
        msg = msg.format(group_name=self.name, max_sessions=max_sessions)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_max_sessions",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        try:
            self.max_sessions = int(max_sessions)
        except Exception:
            return callback.error("Max sessions must be an integer.")
        # Update index.
        self.update_index("max_sessions", self.max_sessions)
        return self._cache(callback=callback)

    @check_acls(['edit:relogin_timeout'])
    @object_lock()
    @audit_log()
    @object_changelog("change relogin timeout to {relogin_timeout}")
    def change_relogin_timeout(
        self,
        relogin_timeout: str,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change relogin timeout for this group. """
        try:
            new_timeout = units.time2int(relogin_timeout, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for relogin timeout: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        msg = _("Change relogin timeout of accessgroup '{group_name}' to '{relogin_timeout}'?: ")
        msg = msg.format(group_name=self.name, relogin_timeout=relogin_timeout)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        relogin_timeout = new_timeout

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_relogin_timeout",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.relogin_timeout = relogin_timeout
        # Update index.
        self.update_index("relogin_timeout", self.relogin_timeout)
        return self._cache(callback=callback)

    @check_acls(['edit:max_fail'])
    @object_lock()
    @audit_log()
    @object_changelog("change max fail to {max_fail}")
    def change_max_fail(
        self,
        max_fail: int,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change max authentication failures for this group. """
        msg = _("Change max fail of accessgroup '{group_name}' to '{max_fail}'?: ")
        msg = msg.format(group_name=self.name, max_fail=max_fail)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_max_fail",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        try:
            self.max_fail = int(max_fail)
        except Exception:
            return callback.error("Max fail must be an integer.")
        # Update index.
        self.update_index("max_fail", self.max_fail)
        return self._cache(callback=callback)

    @check_acls(['edit:max_fail_reset'])
    @object_lock()
    @audit_log()
    @object_changelog("change max fail reset time to {reset_time}")
    def change_max_fail_reset(
        self,
        reset_time: str,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change max authentication failures for this group. """
        msg = _("Change max fail reset time of accessgroup '{group_name}' to '{reset_time}'?: ")
        msg = msg.format(group_name=self.name, reset_time=reset_time)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_max_fail_reset",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        try:
            reset_time = units.time2int(reset_time, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for reset time: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)
        try:
            self.max_fail_reset = int(reset_time)
        except Exception:
            return callback.error("Max fail reset must be an integer.")
        # Update index.
        self.update_index("max_fail_reset", self.max_fail_reset)
        return self._cache(callback=callback)

    @check_acls(['edit:session_timeout'])
    @object_lock()
    @audit_log()
    @object_changelog("change session timeout to {timeout}")
    def change_session_timeout(
        self,
        timeout: str,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change session timeout for sessions this group creates. """
        try:
            session_timeout = units.time2int(timeout, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for session timeout: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        if session_timeout != 0 and session_timeout < self.unused_session_timeout:
            msg = _("Session timeout cannot be lower than unused session timeout.")
            return callback.error(msg)

        msg = _("Change session timeout of accessgroup '{group_name}' to '{timeout}'?: ")
        msg = msg.format(group_name=self.name, timeout=timeout)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_session_timeout",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.session_timeout = session_timeout
        # Update index.
        self.update_index("session_timeout", self.session_timeout)
        return self._cache(callback=callback)

    @check_acls(['edit:unused_session_timeout'])
    @object_lock()
    @audit_log()
    @object_changelog("change unused session timeout to {unused_timeout}")
    def change_unused_session_timeout(
        self,
        unused_timeout: str,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change unused session timeout for sessions this group creates. """
        try:
            unused_session_timeout = units.time2int(unused_timeout,
                                                    time_unit="s")
        except Exception as e:
            msg = _("Invalid value for unused session timeout: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        if unused_session_timeout > self.session_timeout:
            msg = _("Unused session timeout cannot be higher than session timeout.")
            return callback.error(msg)

        msg = _("Change unused session timeout of accessgroup '{group_name}' to '{unused_timeout}'?: ")
        msg = msg.format(group_name=self.name, unused_timeout=unused_timeout)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_unused_session_timeout",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.unused_session_timeout = unused_session_timeout
        # Update index.
        self.update_index("unused_session_timeout", self.unused_session_timeout)
        return self._cache(callback=callback)

    @check_acls(['enable:sessions'])
    @object_lock()
    @audit_log()
    @object_changelog("enable sessions")
    def enable_sessions(
        self,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable sessions for this access group. """
        if self.name == config.mgmt_access_group:
            return callback.error("Cannot enable sessions for MGMT accessgroup.")
        if self.sessions_enabled:
            return callback.error("Sessions already enabled for this group.")

        msg = _("Enable sessions for accessgroup '{group_name}'?: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sessions",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sessions_enabled = True
        # Update index.
        self.update_index("sessions_enabled", self.sessions_enabled)
        return self._cache(callback=callback)

    @check_acls(['disable:sessions'])
    @object_lock()
    @audit_log()
    @object_changelog("disable sessions")
    def disable_sessions(
        self,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable sessions for this access group. """
        if self.name == config.realm_access_group:
            msg = _("Cannot disable sessions for REALM accessgroup.")
            return callback.error(msg)
        if not self.sessions_enabled:
            msg = _("Sessions already disabled for this group.")
            return callback.error(msg)

        msg = _("Disable sessions for accessgroup '{group_name}'?: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sessions",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sessions_enabled = False
        # Update index.
        self.update_index("sessions_enabled", self.sessions_enabled)
        return self._cache(callback=callback)

    @check_acls(['enable:timeout_pass_on'])
    @object_lock()
    @audit_log()
    @object_changelog("enable timeout pass on")
    def enable_timeout_pass_on(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable session timeout pass on for this group. """
        if self.timeout_pass_on:
            msg = _("Timeout pass on already enabled for this group.")
            return callback.error(msg)

        msg = _("Enable timeout pass on for accessgroup '{group_name}'?: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_timeout_pass_on",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.timeout_pass_on = True
        # Update index.
        self.update_index("timeout_pass_on", self.timeout_pass_on)
        return self._cache(callback=callback)

    @check_acls(['disable:timeout_pass_on'])
    @object_lock()
    @audit_log()
    @object_changelog("disable timeout pass on")
    def disable_timeout_pass_on(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable session timeout pass on for this access group. """
        if not self.timeout_pass_on:
            msg = _("Timeout pass on already disabled for this group.")
            return callback.error(msg)

        msg = _("Disable timeout pass on for accessgroup '{group_name}'?: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_timeout_pass_on",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.timeout_pass_on = False
        # Update index.
        self.update_index("timeout_pass_on", self.timeout_pass_on)
        return self._cache(callback=callback)

    def get_sign_public_key(self, user_uuid: str):
        """ Get users sign public key stored in this accessgroup.

        The key has to come from the accessgroup and not from the user
        object: the users site may be a different one and we do not
        want it to be able to swap the key that guards our resources.
        """
        try:
            return self.sign_public_keys[user_uuid]
        except KeyError:
            return None

    def add_sign_public_key(
        self,
        user,
        callback: JobCallback=default_callback,
        ):
        """ Store users sign public key in the accessgroup. """
        if not user.sign_public_key:
            msg = _("User misses sign public key: {user_name}")
            msg = msg.format(user_name=user.name)
            return callback.error(msg)
        if self.sign_public_keys.get(user.uuid) == user.sign_public_key:
            return True
        self.sign_public_keys[user.uuid] = user.sign_public_key
        return True

    def del_sign_public_key(
        self,
        token_uuid: str,
        callback: JobCallback=default_callback,
        ):
        """ Remove users sign public key if their last token was removed.

        The key stays as long as any token of the user is still
        assigned to the accessgroup.
        """
        token = backend.get_object(object_type="token", uuid=token_uuid)
        if not token:
            return True
        user_uuid = token.owner_uuid
        if user_uuid not in self.sign_public_keys:
            return True
        user = backend.get_object(object_type="user", uuid=user_uuid)
        if user:
            for x_uuid in user.get_tokens():
                if x_uuid not in self.tokens:
                    continue
                msg = _("Not removing sign public key because of other assigned token.")
                callback.send(msg)
                return True
        self.sign_public_keys.pop(user_uuid)
        return True

    @check_acls(['enable:sotp_signing'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("enable SOTP signing")
    def enable_sotp_signing(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Require clients to sign the SOTP they authenticate with.

        Only users whose sign public key is stored in the accessgroup
        have to sign. A user without a key authenticates as before, which
        makes it possible to enable signing before every user has a key.
        Use enable_force_sotp_signing() to require it from everyone.
        """
        if self.sotp_signing:
            return callback.error(_("SOTP signing already enabled."))

        # Get sign public keys of all users with a token assigned.
        group_users = self.get_token_users(return_type="instance")
        key_users = []
        missing_keys = []
        for user in group_users:
            if not user.sign_public_key:
                missing_keys.append(user.name)
                continue
            key_users.append(user)
        if missing_keys:
            msg = _("Users without sign public key (they will not sign): {user_names}")
            msg = msg.format(user_names=",".join(sorted(missing_keys)))
            callback.send(msg)

        msg = _("Enable SOTP signing for accessgroup '{group_name}'? Clients of users with a sign key stored in the accessgroup have to sign.: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sotp_signing",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        for user in key_users:
            if not self.add_sign_public_key(user, callback=callback):
                return callback.error()

        self.sotp_signing = True

        self.update_index('sotp_signing', self.sotp_signing)

        return self._cache(callback=callback)

    @check_acls(['disable:sotp_signing'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("disable SOTP signing")
    def disable_sotp_signing(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Do no longer require clients to sign their SOTP. """
        if not self.sotp_signing:
            return callback.error(_("SOTP signing already disabled."))

        msg = _("Disable SOTP signing for accessgroup '{group_name}'?: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sotp_signing",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # The stored keys are only used for SOTP signing. Enabling it
        # again reads them from the users anyway.
        if self.sign_public_keys:
            for user_uuid in list(self.sign_public_keys):
                self.sign_public_keys.pop(user_uuid)
            self.set_changelog("removed sign public keys")

        self.sotp_signing = False
        # Forcing it without signing being enabled makes no sense.
        self.force_sotp_signing = False

        self.update_index('sotp_signing', self.sotp_signing)
        self.update_index('force_sotp_signing', self.force_sotp_signing)

        return self._cache(callback=callback)

    @check_acls(['enable:force_sotp_signing'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("enable forced SOTP signing")
    def enable_force_sotp_signing(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Require every user to sign the SOTP, not just those with a key.

        Without this a user whose sign public key is missing in the
        accessgroup authenticates without signing. That is what makes a
        rollout possible, but it also means a user can be talked out of
        signing by removing their key. Forcing closes that door: a user
        without a key can no longer authenticate at all.
        """
        if not self.sotp_signing:
            msg = _("SOTP signing not enabled.")
            return callback.error(msg)

        if self.force_sotp_signing:
            return callback.error(_("Forced SOTP signing already enabled."))

        # A role would bring in tokens without us noticing, so their
        # users sign public keys would be missing.
        if self.roles:
            msg = _("Forced SOTP signing does not support roles. Please remove all roles from the accessgroup first.")
            return callback.error(msg)

        # Every user with a token assigned needs a key we can verify against.
        group_users = self.get_token_users(return_type="instance")
        missing_keys = []
        for user in group_users:
            if self.sign_public_keys.get(user.uuid):
                continue
            missing_keys.append(user.name)
        if missing_keys:
            msg = _("Users without sign public key: {user_names}")
            msg = msg.format(user_names=",".join(sorted(missing_keys)))
            return callback.error(msg)

        msg = _("Force SOTP signing for accessgroup '{group_name}'? Clients without a sign key cannot authenticate anymore.: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_force_sotp_signing",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        self.force_sotp_signing = True

        self.update_index('force_sotp_signing', self.force_sotp_signing)

        return self._cache(callback=callback)

    @check_acls(['disable:force_sotp_signing'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("disable forced SOTP signing")
    def disable_force_sotp_signing(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Only require users with a stored sign public key to sign.

        SOTP signing itself stays enabled. The stored keys are kept, so
        the users that have one keep signing.
        """
        if not self.force_sotp_signing:
            return callback.error(_("Forced SOTP signing already disabled."))

        msg = _("Do no longer force SOTP signing for accessgroup '{group_name}'?: ")
        msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_force_sotp_signing",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        self.force_sotp_signing = False

        self.update_index('force_sotp_signing', self.force_sotp_signing)

        return self._cache(callback=callback)

    @check_acls(['edit:sign_public_keys'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("update sign public keys")
    def update_sign_public_keys(
        self,
        username: Union[str,None]=None,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Take over the current sign public keys of the token users.

        A user that generates a new key pair cannot reach the copy in
        the accessgroup, so their access breaks until someone with
        write access to the accessgroup takes over the new key. That is
        on purpose: updating the copy automatically (e.g. from a hook on
        the user) would hand the users site exactly the control the copy
        is meant to take away from it.
        """
        if not self.sotp_signing:
            msg = _("SOTP signing not enabled.")
            return callback.error(msg)

        all_group_users = self.get_token_users(return_type="instance")
        group_users = all_group_users
        if username is not None:
            group_users = []
            for user in all_group_users:
                if user.name != username:
                    continue
                group_users.append(user)
            if not group_users:
                msg = _("User does not have a token assigned to this accessgroup: {user_name}")
                msg = msg.format(user_name=username)
                return callback.error(msg)

        # Users whose key differs from the one we have.
        update_users = []
        missing_keys = []
        for user in group_users:
            if not user.sign_public_key:
                missing_keys.append(user.name)
                continue
            if self.sign_public_keys.get(user.uuid) == user.sign_public_key:
                continue
            update_users.append(user)

        if username is not None and missing_keys:
            msg = _("User misses sign public key: {user_name}")
            msg = msg.format(user_name=username)
            return callback.error(msg)

        # Keys without a token in the accessgroup. Adding and removing
        # tokens keeps them in sync, so this is only for leftovers (e.g.
        # from a token that was deleted instead of removed).
        orphan_uuids = []
        if username is None:
            group_user_uuids = []
            for user in all_group_users:
                group_user_uuids.append(user.uuid)
            for user_uuid in self.sign_public_keys:
                if user_uuid in group_user_uuids:
                    continue
                orphan_uuids.append(user_uuid)

        for user_name in sorted(missing_keys):
            msg = _("User misses sign public key: {user_name}")
            msg = msg.format(user_name=user_name)
            callback.send(msg)

        if not update_users and not orphan_uuids:
            msg = _("Sign public keys are up to date.")
            return callback.ok(msg)

        update_names = []
        for user in update_users:
            update_names.append(user.name)
        if orphan_uuids:
            msg = _("Removing sign public keys without a token: {key_count}")
            msg = msg.format(key_count=len(orphan_uuids))
            callback.send(msg)

        if update_names:
            msg = _("Update sign public keys of accessgroup '{group_name}'? Users: {user_names}: ")
            msg = msg.format(group_name=self.name, user_names=",".join(sorted(update_names)))
        else:
            msg = _("Update sign public keys of accessgroup '{group_name}'?: ")
            msg = msg.format(group_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("update_sign_public_keys",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        for user in update_users:
            if not self.add_sign_public_key(user, callback=callback):
                return callback.error()
        for user_uuid in orphan_uuids:
            self.sign_public_keys.pop(user_uuid)

        detail = f"updated {len(update_users)} sign public key(s), removed {len(orphan_uuids)}"
        self.set_changelog(detail)

        return self._cache(callback=callback)

    @object_lock()
    def add_token(
        self,
        token_path: str,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add token to accessgroup. """
        user = None
        if self.sotp_signing:
            if not "/" in token_path:
                msg = _("Invalid token path: {token_path}")
                msg = msg.format(token_path=token_path)
                return callback.error(msg)
            token_user = token_path.split("/")[0]
            result = backend.search(object_type="user",
                                    attribute="name",
                                    value=token_user,
                                    realm=config.realm,
                                    return_type="instance")
            if not result:
                msg = _("Unknown user: {token_user}")
                msg = msg.format(token_user=token_user)
                return callback.error(msg)
            user = result[0]
            if not user.sign_public_key:
                # With signing forced the user cannot authenticate without
                # a key, so refuse the token before the parent class adds
                # it. Without force the user just does not sign.
                if self.force_sotp_signing:
                    msg = _("User misses sign public key: {user_name}")
                    msg = msg.format(user_name=user.name)
                    return callback.error(msg)
                msg = _("User misses sign public key and will not sign: {user_name}")
                msg = msg.format(user_name=user.name)
                callback.send(msg)
                user = None

        # Add token by parent class.
        result = super().add_token(token_path=token_path,
                                callback=callback, **kwargs)

        if not result:
            return result

        # The parent class cached the object for writing, so the key we
        # add here goes to the backend with it.
        if user:
            if not self.add_sign_public_key(user, callback=callback):
                return callback.error()

        return result

    @object_lock()
    def remove_token(
        self,
        token_path: str,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove token from accessgroup. """
        token_uuid = None
        if self.sotp_signing:
            token_uuid = self.get_assigned_token_uuid(token_path)

        # Remove token by parent class.
        result = super().remove_token(token_path=token_path,
                                    callback=callback, **kwargs)

        if not result:
            return result

        # The parent class cached the object for writing, so the key we
        # remove here goes to the backend with it.
        if token_uuid:
            self.del_sign_public_key(token_uuid, callback=callback)

        return result

    def get_assigned_token_uuid(self, token_path: str):
        """ Get UUID of an assigned token by path or UUID. """
        for token_uuid in self.tokens:
            if token_uuid == token_path:
                return token_uuid
        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            return None
        token_uuid = result[0]
        if token_uuid not in self.tokens:
            return None
        return token_uuid

    @object_lock()
    def add_role(
        self,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add role to accessgroup. """
        # A role would bring in tokens without us noticing, so their
        # users sign public keys would be missing. Without force that is
        # fine, those users just do not sign.
        if self.force_sotp_signing:
            msg = _("Accessgroups with forced SOTP signing do not support roles.")
            return callback.error(msg)
        return super().add_role(*args, callback=callback, **kwargs)

    @object_lock()
    def remove_role(
        self,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove role from accessgroup. """
        if self.force_sotp_signing:
            msg = _("Accessgroups with forced SOTP signing do not support roles.")
            return callback.error(msg)
        return super().remove_role(*args, callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @object_changelog("rename from {self.name} to {new_name}")
    def rename(
        self,
        new_name: str,
        force: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename accessgroup. """
        base_access_groups = config.get_base_objects("accessgroup")
        if self.name in base_access_groups:
            return callback.error("Cannot rename base accessgroup.")

        msg = _("Rename accessgroup '{group_name}' to '{new_name}'?: ")
        msg = msg.format(group_name=self.name, new_name=new_name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        # Build new OID.
        new_oid = oid.get(object_type="accessgroup",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(
        self,
        uuid: Union[str,None]=None,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a accessgroup. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        # Update index.
        self.add_index("max_fail", self.max_fail)
        self.add_index("max_fail_reset", self.max_fail_reset)
        self.add_index("max_sessions", self.max_sessions)
        self.add_index("session_timeout", self.session_timeout)
        self.add_index("timeout_pass_on", self.timeout_pass_on)
        self.add_index("sessions_enabled", self.sessions_enabled)
        self.add_index("sotp_signing", self.sotp_signing)
        self.add_index("force_sotp_signing", self.force_sotp_signing)
        self.add_index("relogin_timeout", self.relogin_timeout)
        self.add_index("unused_session_timeout", self.unused_session_timeout)
        return OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(
        self,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete accessgroup. """
        if not self.exists():
            return callback.error("Accessgroup does not exist.")

        base_access_groups = config.get_base_objects("accessgroup")
        if self.name in base_access_groups:
            return callback.error("Cannot delete base accessgroup.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {name}")
                    msg = msg.format(name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        exception = ""

        # Get list with parent groups.
        parent_groups = self.parents(recursive=False)

        if parent_groups:
            if not force:
                exception = _("Group '{name}' has parent groups: {parent_groups}\n")
                exception = exception.format(name=self.name, parent_groups=', '.join(parent_groups))

        # Get list with parent sessions.
        parent_sessions = self.parents(recursive=False, sessions=True)

        if parent_sessions:
            if not force:
                msg = _("{exception}Group '{name}' has parent sessions: {parent_sessions}\n")
                exception = msg.format(exception=exception, name=self.name, parent_sessions=', '.join(parent_sessions))

        # Get list with child groups.
        child_groups = self.childs()

        if child_groups:
            if not force:
                msg = _("{exception}Group '{name}' has child groups: {child_groups}\n")
                exception = msg.format(exception=exception, name=self.name, child_groups=', '.join(child_groups))

        # Get list with child sessions.
        child_sessions = self.childs(sessions=True)

        if child_sessions:
            if not force:
                msg = _("{exception}Group '{name}' has child sessions: {child_sessions}\n")
                exception = msg.format(exception=exception, name=self.name, child_sessions=', '.join(child_sessions))

        # Get list with all clients.
        all_clients = backend.search(realm=self.realm,
                                    site=self.site,
                                    attribute="name",
                                    value="*",
                                    object_type="client",
                                    return_type="instance")

        # List that will hold all clients that uses this group.
        client_list = []

        # Find clients that uses this group.
        for client in all_clients:
            if self.name == client.access_group:
               client_list.append(client.name)

        if client_list:
            if not force:
                msg = _("{exception}Group '{name}' is used by this clients: {client_list}\n")
                exception = msg.format(exception=exception, name=self.name, client_list=', '.join(client_list))

        # List that will hold all tokens that uses this group.
        token_list = []

        # Get all tokens from this group.
        for t_uuid in self.tokens:
            token = backend.get_object(uuid=t_uuid, object_type="token")
            if not token:
                continue
            token_list.append(token.rel_path)

        if token_list:
            if not force:
                msg = _("{exception}Group '{name}' is used by this tokens: {token_list}\n")
                exception = msg.format(exception=exception, name=self.name, token_list=', '.join(token_list))

        exception_str = exception if exception != "" else None
        if not self.ask_delete_confirmation(force=force, exception=exception_str, callback=callback):
            return callback.abort()

        # Remove group from parent groups.
        for parent_group in parent_groups:
            group = backend.get_object(object_type="accessgroup",
                                        realm=self.realm,
                                        site=self.site,
                                        name=parent_group)
            if not group:
                continue
            group.remove_child_group(self.name, force=True)

        # Remove group from parent sessions.
        for parent_session in parent_sessions:
            group = backend.get_object(object_type="accessgroup",
                                        realm=self.realm,
                                        site=self.site,
                                        name=parent_session)
            if not group:
                continue
            group.remove_child_session(self.name, force=True)

        # Remove group from client access groups.
        for client_name in client_list:
            client = backend.get_object(object_type="client",
                                        realm=self.realm,
                                        site=self.site,
                                        name=client_name)
            if not client:
                continue
            client.change_access_group(force=True)

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

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
        extra_ref_lists = [
                ('tokens', 'token', ['token_options', 'token_login_interfaces']),
                ('roles', 'role', None),
                ('child_groups', 'accessgroup', None),
                ('hosts', 'host', None),
                ('devices', 'device', None),
                ]
        return super().remove_orphans(force=force,
                                    run_policies=run_policies,
                                    verbose_level=verbose_level,
                                    recursive=recursive,
                                    extra_ref_lists=extra_ref_lists,
                                    callback=callback,
                                    _caller=_caller,
                                    **kwargs)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show accessgroup config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        if self.verify_acl("view:tokens") \
        or self.verify_acl("add:token") \
        or self.verify_acl("remove:token"):
            token_list = []
            for i in self.tokens:
                token_oid = backend.get_oid(uuid=i,
                                    object_type="token",
                                    instance=True)
                # Add UUIDs of orphan tokens.
                if not token_oid:
                    token_list.append(i)
                    continue
                token_path = token_oid.rel_path
                token_list.append(token_path)
            token_list.sort()
        else:
            token_list = ""

        if self.verify_acl("view:roles") \
        or self.verify_acl("add:role") \
        or self.verify_acl("remove:role"):
            role_list = []
            for i in self.roles:
                role_oid = backend.get_oid(uuid=i,
                                        object_type="role",
                                        instance=True)
                # Add UUIDs of orphan roles.
                if not role_oid:
                    role_list.append(i)
                    continue
                role_name = role_oid.name
                role_list.append(role_name)
            role_list.sort()
        else:
            role_list = ""

        if self.verify_acl("view:hosts") \
        or self.verify_acl("add:host") \
        or self.verify_acl("remove:host"):
            host_list = []
            for i in self.hosts:
                host_oid = backend.get_oid(uuid=i,
                                        object_type="host",
                                        instance=True)
                # Add UUIDs of orphan hosts.
                if not host_oid:
                    host_list.append(i)
                    continue
                host_name = host_oid.name
                host_list.append(host_name)
            host_list.sort()
        else:
            host_list = ""

        if self.verify_acl("view:devices") \
        or self.verify_acl("add:device") \
        or self.verify_acl("remove:device"):
            devices_list = []
            for i in self.devices:
                device_oid = backend.get_oid(uuid=i,
                                        object_type="device",
                                        instance=True)
                # Add UUIDs of orphan devices.
                if not device_oid:
                    devices_list.append(i)
                    continue
                device_name = device_oid.name
                devices_list.append(device_name)
            devices_list.sort()
        else:
            devices_list = ""

        lines = []

        sessions_enabled = ""
        if self.verify_acl("view:sessions_enabled") \
        or self.verify_acl("enable:sessions") \
        or self.verify_acl("disable:sessions"):
            sessions_enabled = str(self.sessions_enabled)
        lines.append(f'SESSIONS="{sessions_enabled}"')

        timeout_pass_on = ""
        if self.verify_acl("view:timeout_pass_on") \
        or self.verify_acl("edit:timeout_pass_on"):
            timeout_pass_on = str(self.timeout_pass_on)
        lines.append(f'PASS_ON_TIMEOUTS="{timeout_pass_on}"')

        session_timeout = ""
        if self.verify_acl("view:session_timeout") \
        or self.verify_acl("edit:session_timeout"):
            session_timeout = str(self.session_timeout)
        lines.append(f'SESSION_TIMEOUT="{session_timeout}"')

        unused_session_timeout = ""
        if self.verify_acl("view:unused_session_timeout") \
        or self.verify_acl("edit:unused_session_timeout"):
            unused_session_timeout = str(self.unused_session_timeout)
        lines.append(f'UNUSED_SESSION_TIMEOUT="{unused_session_timeout}"')

        max_fail = ""
        if self.verify_acl("view:max_fail") \
        or self.verify_acl("edit:max_fail"):
            max_fail = str(self.max_fail)
        lines.append(f'MAX_FAIL="{max_fail}"')

        max_fail_reset = ""
        if self.verify_acl("view:max_fail_reset") \
        or self.verify_acl("edit:max_fail_reset"):
            max_fail_reset = str(self.max_fail_reset)
        lines.append(f'MAX_FAIL_RESET="{max_fail_reset}"')

        max_sessions = ""
        if self.verify_acl("view:max_sessions") \
        or self.verify_acl("edit:max_sessions"):
            max_sessions = str(self.max_sessions)
        lines.append(f'MAX_SESSIONS="{max_sessions}"')

        childs = ""
        if self.verify_acl("view:child_groups") \
        or self.verify_acl("add:child_group") \
        or self.verify_acl("remove:child_group"):
            childs = str(",".join(self.childs()))
        lines.append(f'CHILD_GROUPS="{childs}"')

        sessions = ""
        if self.verify_acl("view:child_sessions") \
        or self.verify_acl("add:child_session") \
        or self.verify_acl("remove:child_session"):
            sessions = str(",".join(self.childs(sessions=True)))
        lines.append(f'CHILD_SESSIONS="{sessions}"')

        lines.append(f'ROLES="{",".join(role_list)}"')
        lines.append(f'TOKENS="{",".join(token_list)}"')

        lines.append(f'HOSTS="{",".join(host_list)}"')
        lines.append(f'DEVICES="{",".join(devices_list)}"')

        token_options = {}
        for uuid in self.token_options:
            token = backend.get_object(uuid=uuid, object_type="token")
            if token:
                token_path = token.rel_path
            else:
                token_path = uuid
            token_options[token_path] = self.token_options[uuid]
        lines.append(f'TOKEN_OPTIONS="{token_options}"')

        return OTPmeObject.show_config(self, config_lines=lines,
                                    callback=callback, **kwargs)
    def show(self, **kwargs):
        """ Show accessgroup details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
