# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.humanize import units
from otpme.lib.audit import audit_log
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.cache import assigned_token_cache
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.otpme_object import OTPmeObject
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
                            "token",
                            "role",
                            "child_group",
                            "child_session",
                            "sessions_enabled",
                            "session_master",
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
                            "child_group",
                            "child_session",
                            ],
                "remove"    : [
                            "token",
                            "role",
                            "child_group",
                            "child_session",
                            ],

                "edit"      : [
                            "config",
                            "max_fail",
                            "max_fail_reset",
                            "max_sessions",
                            "relogin_timeout",
                            "session_timeout",
                            "unused_session_timeout",
                            ],
                "enable"    : [
                            "sessions",
                            "session_master",
                            "timeout_pass_on",
                            ],
                "disable"   : [
                            "sessions",
                            "session_master",
                            "timeout_pass_on",
                            ],
}

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
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
    'touch'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'touch',
                    'job_type'          : 'process',
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("accessgroup"),
                    'args'              : ['realm'],
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
                    'oargs'             : ['keep_acls'],
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
    'enable_sessions'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sessions',
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
    'enable_session_master'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_session_master',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_session_master'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_session_master',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_timeout_pass_on'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_timeout_pass_on',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_timeout_pass_on'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_timeout_pass_on',
                    'job_type'          : 'process',
                    },
                },
            },
    'max_fail'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_max_fail',
                    'args'              : ['max_fail'],
                    'job_type'          : 'process',
                    },
                },
            },
    'max_fail_reset'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_max_fail_reset',
                    'args'              : ['reset_time'],
                    'job_type'          : 'process',
                    },
                },
            },
    'max_sessions'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_max_sessions',
                    'args'              : ['max_sessions'],
                    'job_type'          : 'process',
                    },
                },
            },
    'relogin_timeout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_relogin_timeout',
                    'args'              : ['relogin_timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'timeout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_session_timeout',
                    'args'              : ['timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'unused_timeout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_unused_session_timeout',
                    'args'              : ['unused_timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['token_options', 'login_interfaces', 'sign', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['keep_sign'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_child_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_child_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_child_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_child_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_child_session'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_child_session',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_child_session'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_child_session',
                    'args'              : ['group_name'],
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
    'list_tokens'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_tokens',
                    'oargs'             : ['return_type', 'token_types'],
                    'dargs'             : {'return_type':'rel_path', 'skip_disabled':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'list_roles'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_roles',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
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

DEFAULT_UNIT = "accessgroups"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                #"otpme.lib.classes.token",
                "otpme.lib.classes.group",
                ]

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("accessgroup", commands)
    # Register index attributes.
    config.register_index_attribute("child_group")
    config.register_index_attribute("child_session")
    config.register_index_attribute("max_fail")
    config.register_index_attribute("max_fail_reset")
    config.register_index_attribute("max_sessions")
    config.register_index_attribute("session_master")
    config.register_index_attribute("session_timeout")
    config.register_index_attribute("timeout_pass_on")
    config.register_index_attribute("sessions_enabled")
    config.register_index_attribute("relogin_timeout")
    config.register_index_attribute("unused_session_timeout")

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
    config.register_auth_on_action_hook("accessgroup", "enable_session_master")
    config.register_auth_on_action_hook("accessgroup", "disable_session_master")
    config.register_auth_on_action_hook("accessgroup", "enable_timeout_pass_on")
    config.register_auth_on_action_hook("accessgroup", "disable_timeout_pass_on")

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
        super(AccessGroup, self).__init__(object_id=object_id,
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
        self.session_master = False
        self.timeout_pass_on = False

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

                        'SESSION_MASTER'            : {
                                                        'var_name'  : 'session_master',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'PASS_ON_TIMEOUTS'          : {
                                                        'var_name'  : 'timeout_pass_on',
                                                        'type'      : bool,
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
            return True
        for role_uuid in self.roles:
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if not role:
                continue
            if skip_disabled_roles:
                if not role.enabled:
                    continue
            if role.is_assigned_token(token_uuid):
                return role
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
                return group
        return False

    def parents(
        self,
        recursive: bool=False,
        sessions: bool=None,
        session_master: bool=False,
        return_type: str='name',
        skip_disabled: bool=True,
        ):
        """ Get all parent groups of this group. """
        result = []
        child_attribute = "child_group"
        if sessions:
            child_attribute = "child_session"
        return_attrs = ['uuid', 'enabled']
        if session_master:
            return_attrs.append("session_master")
        if return_type != "instance":
            return_attrs.append(return_type)
        # Get parent accessgroups.
        parents = backend.search(realm=self.realm,
                                site=self.site,
                                object_type="accessgroup",
                                attribute=child_attribute,
                                value=self.uuid,
                                return_attributes=return_attrs)
        if not parents:
            return result
        if recursive:
            parent_parents = list(parents)
            while True:
                check_parents = list(parent_parents)
                parent_parents = []
                for uuid in check_parents:
                    x_parents = backend.search(realm=self.realm,
                                                site=self.site,
                                                object_type="accessgroup",
                                                attribute=child_attribute,
                                                value=uuid,
                                                return_attributes=return_attrs)
                    if not x_parents:
                        continue
                    for x_uuid in x_parents:
                        if x_uuid in parents:
                            continue
                        parents[x_uuid] = x_parents[x_uuid]
                    parent_parents += x_parents
                if not parent_parents:
                    break

        # Check for session master.
        if session_master:
            return_attr = None
            for uuid in parents:
                try:
                    session_master = parents[uuid]['session_master'][0]
                except:
                    continue
                if not session_master:
                    continue
                if return_type == "instance":
                    return_attr = backend.get_object(object_type="accessgroup",
                                                    uuid=uuid)
                elif return_type == "uuid":
                    return_attr = uuid
                else:
                    return_attr = parents[uuid][return_type]
            return return_attr

        for uuid in parents:
            if skip_disabled:
                try:
                    group_enabled = parents[uuid]['enabled'][0]
                except:
                    group_enabled = False
                if not group_enabled:
                    continue
            if return_type == "instance":
                p = backend.get_object(object_type="accessgroup", uuid=uuid)
                result.append(p)
            elif return_type == "uuid":
                result.append(uuid)
            else:
                return_attribute = parents[uuid][return_type]
                result.append(return_attribute)
        return result

    def childs(
        self,
        recursive: bool=False,
        sessions: bool=False,
        session_master: bool=False,
        return_type: str='name',
        skip_disabled: bool=True,
        ):
        """ Get all child groups of this group. """
        result = []
        join_attribute = "child_group"
        if sessions:
            join_attribute = "child_session"
        return_attrs = ['uuid', 'enabled']
        if session_master:
            return_attrs.append("session_master")
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

        # Check for session master.
        if session_master:
            return_attr = None
            for uuid in childs:
                try:
                    session_master = childs[uuid]['session_master'][0]
                except:
                    continue
                if not session_master:
                    continue
                if return_type == "instance":
                    return_attr = backend.get_object(object_type="accessgroup",
                                                    uuid=uuid)
                elif return_type == "uuid":
                    return_attr = uuid
                else:
                    return_attr = childs[uuid][return_type]
            return return_attr

        for uuid in childs:
            if skip_disabled:
                try:
                    group_enabled = childs[uuid]['enabled'][0]
                except:
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

    def get_session_master(self, return_type: str='name'):
        """ Get session master of session tree. """
        # Check if we are the session master.
        if self.session_master:
            if return_type == "name":
                return self.name
            if return_type == "uuid":
                return self.uuid
            if return_type == "instance":
                return self

        # Try to get session master from parent sessions.
        session_master = self.parents(recursive=True,
                                    sessions=True,
                                    session_master=True,
                                    return_type=return_type)
        if session_master:
            return session_master

        # Try to get session master from child sessions.
        session_master = self.childs(recursive=True,
                                    sessions=True,
                                    session_master=True,
                                    return_type=return_type)
        if session_master:
            return session_master

    @check_acls(['add:child_group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def add_child_group(
        self,
        group_name: str,
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

        if group.uuid in self.childs(return_type="uuid"):
            msg = _("Group is already in child groups of group '{group_name}'.")
            msg = msg.format(group_name=self.name)
            return callback.error(msg)

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
    def remove_child_group(
        self,
        group_name: str,
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
    def add_child_session(
        self,
        group_name: str,
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
            msg = _("Group is already in child sessions of group '{group_name}'.")
            msg = msg.format(group_name=self.name)
            return callback.error(msg)

        # Get session master of own session tree.
        session_master = self.get_session_master()
        # Get session master of child session tree.
        child_session_master = group.get_session_master()

        # Check if there is a session master in both session trees.
        if (session_master and child_session_master) \
        and (session_master != child_session_master):
            msg = _("Cannot add group as child session because both session trees contain a session master.")
            return callback.error(msg)

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
    def remove_child_session(
        self,
        group_name: str,
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
    def change_max_sessions(
        self,
        max_sessions: int=0,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change max sessions for this group. """
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
        except:
            return callback.error("Max sesssions must be an integer.")
        # Update index.
        self.update_index("max_sessions", self.max_sessions)
        return self._cache(callback=callback)

    @check_acls(['edit:relogin_timeout'])
    @object_lock()
    @audit_log()
    def change_relogin_timeout(
        self,
        relogin_timeout: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change relogin timeout for this group. """
        try:
            relogin_timeout = units.time2int(relogin_timeout, time_unit="s")
        except Exception as e:
            msg = _("Invalid value for relogin timeout: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

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
    def change_max_fail(
        self,
        max_fail: int,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change max authentication failures for this group. """
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
        except:
            return callback.error("Max fail must be an integer.")
        # Update index.
        self.update_index("max_fail", self.max_fail)
        return self._cache(callback=callback)

    @check_acls(['edit:max_fail_reset'])
    @object_lock()
    @audit_log()
    def change_max_fail_reset(
        self,
        reset_time: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change max authentication failures for this group. """
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
        except:
            return callback.error("Max fail reset must be an integer.")
        # Update index.
        self.update_index("max_fail_reset", self.max_fail_reset)
        return self._cache(callback=callback)

    @check_acls(['edit:session_timeout'])
    @object_lock()
    @audit_log()
    def change_session_timeout(
        self,
        timeout: str,
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
    def change_unused_session_timeout(
        self,
        unused_timeout: str,
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
    def enable_sessions(
        self,
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
    def disable_sessions(
        self,
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

    @check_acls(['enable:session_master'])
    @object_lock()
    @audit_log()
    def enable_session_master(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable session master feature for this group. """
        if self.session_master:
            return callback.error("Group is already session master.")
        # Check if there is already a session master in our session tree.
        session_master = self.get_session_master()
        if session_master:
            msg = _("Cannot enable session master. Session master already exists in session tree: '{session_master}'.")
            msg = msg.format(session_master=session_master)
            return callback.error(msg)

        if self.session_master:
            msg = _("Session master already enabled for this group.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_session_master",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.session_master = True
        # Update index.
        self.update_index("session_master", self.session_master)
        return self._cache(callback=callback)

    @check_acls(['disable:session_master'])
    @object_lock()
    @audit_log()
    def disable_session_master(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable session master feature for this access group. """
        if not self.session_master:
            msg = _("Session master already disabled for this group.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_session_master",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.session_master = False
        # Update index.
        self.update_index("session_master", self.session_master)
        return self._cache(callback=callback)

    @check_acls(['enable:timeout_pass_on'])
    @object_lock()
    @audit_log()
    def enable_timeout_pass_on(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable session timeout pass on for this group. """
        if self.timeout_pass_on:
            msg = _("Timeout pass on already enabled for this group.")
            return callback.error(msg)

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
    def disable_timeout_pass_on(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable session timeout pass on for this access group. """
        if not self.timeout_pass_on:
            msg = _("Timeout pass on already disabled for this group.")
            return callback.error(msg)

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

    @object_lock(full_lock=True)
    @backend.transaction
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename accessgroup. """
        base_access_groups = config.get_base_objects("accessgroup")
        if self.name in base_access_groups:
            return callback.error("Cannot rename base accessgroup.")

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
        self.add_index("session_master", self.session_master)
        self.add_index("session_timeout", self.session_timeout)
        self.add_index("timeout_pass_on", self.timeout_pass_on)
        self.add_index("sessions_enabled", self.sessions_enabled)
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
            return callback.error("Accessgroup does not exist exists.")

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

        if exception != "":
            if self.confirmation_policy != "force":
                if self.confirmation_policy == "paranoid":
                    msg = _("Please type '{name}' to delete object: ")
                    msg = msg.format(name=self.name)
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
                else:
                    msg = _("{exception}Delete accessgroup? ")
                    msg = msg.format(exception=exception)
                    answer = callback.ask(msg)
                    if answer.lower() != "y":
                        return callback.abort()
        else:
            if not force:
                if self.confirmation_policy == "paranoid":
                    msg = _("Please type '{name}' to delete object: ")
                    msg = msg.format(name=self.name)
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()

        # Remove group from parent groups.
        for parent_group in parent_groups:
            group = backend.get_object(object_type="accessgroup",
                                        realm=self.realm,
                                        site=self.site,
                                        name=parent_group)
            if not group:
                continue
            group.remove_child_group(self.name)

        # Remove group from parent sessions.
        for parent_session in parent_sessions:
            group = backend.get_object(object_type="accessgroup",
                                        realm=self.realm,
                                        site=self.site,
                                        name=parent_session)
            if not group:
                continue
            group.remove_child_session(self.name)

        # Remove group from client access groups.
        for client_name in client_list:
            client = backend.get_object(object_type="client",
                                        realm=self.realm,
                                        site=self.site,
                                        name=client_name)
            if not client:
                continue
            client.change_access_group()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

    @check_acls(['remove:orphans'])
    @object_lock()
    @audit_log()
    def remove_orphans(
        self,
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
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
                return callback.error()

        acl_list = self.get_orphan_acls()
        policy_list = self.get_orphan_policies()

        token_list = []
        token_uuids = set(self.tokens + list(self.token_options))
        for i in token_uuids:
            token_oid = backend.get_oid(object_type="token", uuid=i)
            if not token_oid:
                token_list.append(i)

        role_list = []
        for i in self.roles:
            role_oid = backend.get_oid(object_type="role", uuid=i)
            if not role_oid:
                role_list.append(i)

        if not force:
            msg = ""
            if acl_list:
                orphan_msg = _("{msg}{type}|{name}: Found the following orphan ACLs: {acl_list}\n")
                msg += orphan_msg.format(msg=msg, type=self.type, name=self.name, acl_list=','.join(acl_list))

            if policy_list:
                orphan_msg = _("{msg}{type}|{name}: Found the following orphan policies: {policy_list}\n")
                msg += orphan_msg.format(msg=msg, type=self.type, name=self.name, policy_list=','.join(policy_list))

            if token_list:
                orphan_msg = _("{msg}{type}|{name}: Found the following orphan token UUIDs: {token_list}\n")
                msg += orphan_msg.format(msg=msg, type=self.type, name=self.name, token_list=','.join(token_list))

            if role_list:
                orphan_msg = _("{msg}{type}|{name}: Found the following orphan role UUIDs: {role_list}\n")
                msg += orphan_msg.format(msg=msg, type=self.type, name=self.name, role_list=','.join(role_list))

            if group_list:
                orphan_msg = _("{msg}{type}|{name}: Found the following orphan group UUIDs: {group_list}\n")
                msg += orphan_msg.format(msg=msg, type=self.type, name=self.name, group_list=','.join(group_list))

            if msg:
                ask_msg = _("{msg}Remove? ")
                ask_msg = ask_msg.format(msg=msg)
                answer = callback.ask(ask_msg)
                if answer.lower() != "y":
                    return callback.abort()

        object_changed = False
        if acl_list:
            if self.remove_orphan_acls(force=True, verbose_level=verbose_level,
                                        callback=callback, **kwargs):
                object_changed = True

        if policy_list:
            if self.remove_orphan_policies(force=True, verbose_level=verbose_level,
                                                callback=callback, **kwargs):
                object_changed = True

        for i in token_list:
            if verbose_level > 0:
                msg = _("Removing orphan token UUID: {uuid}")
                msg = msg.format(uuid=i)
                callback.send(msg)
            object_changed = True
            if i in self.tokens:
                self.tokens.remove(i)
            if i in self.token_options:
                self.token_options.pop(i)

        for i in role_list:
            if verbose_level > 0:
                msg = _("Removing orphan role UUID: {uuid}")
                msg = msg.format(uuid=i)
                callback.send(msg)
            object_changed = True
            self.roles.remove(i)

        if not object_changed:
            msg = None
            if verbose_level > 0:
                msg = _("No orphan objects found for {type}: {name}")
                msg = msg.format(type=self.type, name=self.name)
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show accessgroup config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        if self.verify_acl("view:token") \
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

        if self.verify_acl("view:role") \
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

        lines = []

        sessions_enabled = ""
        if self.verify_acl("view:sessions_enabled") \
        or self.verify_acl("enable:sessions") \
        or self.verify_acl("disable:sessions"):
            sessions_enabled = str(self.sessions_enabled)
        lines.append(f'SESSIONS="{sessions_enabled}"')

        session_master = ""
        if self.verify_acl("view:session_master") \
        or self.verify_acl("enable:session_master") \
        or self.verify_acl("disable:session_master"):
            session_master = str(self.session_master)
        lines.append(f'SESSION_MASTER="{session_master}"')

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
        if self.verify_acl("view:child_group") \
        or self.verify_acl("add:child_group") \
        or self.verify_acl("remove:child_group"):
            childs = str(",".join(self.childs()))
        lines.append(f'CHILD_GROUPS="{childs}"')

        sessions = ""
        if self.verify_acl("view:child_session") \
        or self.verify_acl("add:child_session") \
        or self.verify_acl("remove:child_session"):
            sessions = str(",".join(self.childs(sessions=True)))
        lines.append(f'CHILD_SESSIONS="{sessions}"')

        lines.append(f'ROLES="{",".join(role_list)}"')
        lines.append(f'TOKENS="{",".join(token_list)}"')

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
