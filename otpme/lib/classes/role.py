# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.idle import notify
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.classes.realm import ADMIN_USER
from otpme.lib.register import register_module
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.otpme_object import run_pre_post_add_policies
from otpme.lib.classes.otpme_object import name_len_setter

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

read_acls = []
write_acls = []

read_value_acls = {
                    "view"      : [
                                    "hosts",
                                    "user",
                                    "tokens",
                                    "shares",
                                    "accessgroups",
                                    "groups",
                                    "policies",
                                    "roles",
                                    "scopes",
                                    "dynamic_groups",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                    "user",
                                    "token",
                                    "role",
                                    "device",
                                    "host",
                                    "dynamic_group",
                                ],
                    "edit"       : [
                                    "config",
                                ],
                    "remove"    : [
                                    "user",
                                    "token",
                                    "role",
                                    "device",
                                    "host",
                                    "dynamic_group",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'groups', 'roles'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'groups', 'roles'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_config_parameter',
                    'args'              : ['parameter'],
                    'dargs'             : {'verify_acls':True},
                    'job_type'          : 'process',
                    },
                },
            },
    'changelog'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_changelog',
                    'job_type'          : 'process',
                    },
                },
            },
    'edit_changelog'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'edit_changelog',
                    'args'              : ['entry_id', 'comment'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_changelog'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_changelog',
                    'args'              : ['entry_id'],
                    'job_type'          : 'process',
                    },
                },
            },
    'clear_changelog'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'clear_changelog',
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
                    'method'            : cli.show_getter("role"),
                    'args'              : ['realm'],
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'search_regex',
                                        'sort_by',
                                        'reverse',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        'realm',
                                        'site',
                                        'max_roles',
                                        'max_tokens',
                                        'max_ags',
                                        'max_groups',
                                        'max_scopes',
                                        'max_policies',
                                        'limit',
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
                    'method'            : cli.list_getter("role"),
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
                    'method'            : cli.list_getter("role"),
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
                    'oargs'              : ['parameter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable',
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'disable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable',
                    'oargs'             : ['share_notifications', 'persist_mount'],
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
    'add_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['token_options', 'login_interfaces', 'sign', 'tags', 'share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['keep_sign', 'share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_host'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_host',
                    'args'              : ['host_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_host'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_host',
                    'args'              : ['host_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_device'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_device',
                    'args'              : ['device_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_device'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_device',
                    'args'              : ['device_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_hosts'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_hosts',
                    'job_type'          : 'process',
                    },
                },
            },
    'list_devices'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_devices',
                    'job_type'          : 'process',
                    },
                },
            },
    'list_shares'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_shares',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type', 'recursive'],
                    'dargs'             : {'return_type':'path', 'recursive':False, 'skip_disabled':False},
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
    'add_sync_user'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_sync_user',
                    'args'              : ['user_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_sync_user'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_sync_user',
                    'args'              : ['user_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_sync_users'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_sync_users',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_users'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_token_users',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_tokens'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_tokens',
                    'oargs'             : ['return_type', 'token_types'],
                    'dargs'             : {'return_type':'rel_path', 'skip_disabled':False},
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_roles'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_roles',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_policies'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_policies',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'list_dynamic_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_dynamic_groups',
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_scopes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_scopes',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
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
                    'args'              : ['acl'],
                    'oargs'             : ['recursive_acls', 'apply_default_acls'],
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
    'info'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_info',
                    'oargs'             : ['info', 'language'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'dump_info'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump_info',
                    'oargs'             : ['language'],
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
    'list_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_acls',
                    'job_type'          : 'process',
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
    config_params = config.get_config_parameters("role")
    if split:
        read_acls = result[0]['view']
        write_acls = result[1]['edit']
    else:
        read_acls = result['view']
        write_acls = result['edit']
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        write_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    acls = _get_default_acls(default_acls, **kwargs)
    acls += config.get_default_acls("role")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("role")
    return acls

DEFAULT_UNIT = "roles"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                ]

def register():
    register_dn()
    register_oid()
    config.register_config_parameter(name="max_role_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_ldap_object()
    register_sync_settings()
    register_config_parameters()
    register_commands("role", commands)
    register_module("otpme.lib.classes.token")
    config.register_recursive_default_acl("site", "+role")
    config.register_default_acl("unit", "+role")
    config.register_recursive_default_acl("unit", "+role")

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("role", "cn")

def register_hooks():
    config.register_auth_on_action_hook("role", "add")
    config.register_auth_on_action_hook("role", "delete")
    config.register_auth_on_action_hook("role", "add_role")
    config.register_auth_on_action_hook("role", "remove_role")
    config.register_auth_on_action_hook("role", "add_token")
    config.register_auth_on_action_hook("role", "remove_token")
    config.register_auth_on_action_hook("role", "add_dynamic_group")
    config.register_auth_on_action_hook("role", "remove_dynamic_group")
    config.register_auth_on_action_hook("role", "set_config_parameter")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("role", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    role_name_re = '([0-9A-Za-z]([0-9A-Za-z_:.-]*[0-9A-Za-z]){0,})'
    role_path_re = f'{unit_path_re}[/]{role_name_re}'
    role_oid_re = f'role|{role_path_re}'
    oid.register_oid_schema(object_type="role",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=role_name_re,
                            path_regex=role_path_re,
                            oid_regex=role_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="role",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    role_dir_extension = "role"
    def path_getter(role_oid, role_uuid):
        return backend.config_path_getter(role_oid, role_dir_extension)
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
                'accessgroup',
                'client',
                ]
        return backend.rebuild_object_index("role", objects, after)
    # Register object to config.
    config.register_object_type(object_type="role",
                            tree_object=True,
                            uniq_name=True,
                            # FIXME: must be roles added before tokens?
                            #        This is required in client/sync1.py
                            #add_after=["token"],
                            add_before=["token"],
                            sync_before=["token", "user"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Role
    backend.register_object_type(object_type="role",
                                dir_name_extension=role_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="role")
    config.register_object_sync(host_type="host", object_type="role")

def register_ldap_object():
    """ Register LDAP object settings. """
    config.register_ldap_object(object_type="role",
                                default_scope="one",
                                scopes=['one'])

def register_config_parameters():
    # SSO device tokens suffix.
    config.register_config_parameter(name="device_token_suffix",
                                    ctype=str,
                                    object_types=['role'])

def get_roles(role_uuid=None, skip_disabled=False, parent=False,
    recursive=True, return_type="name", return_attributes=None):

    def _get_roles(uuid, parent=False, return_attributes=None):
        return_attrs = ['name', 'enabled', 'full_oid', 'site']
        if return_attributes is not None:
            return_attrs = list(set(return_attrs + return_attributes))
        if parent:
            result = backend.search(object_type="role",
                                    attribute="role",
                                    value=uuid,
                                    return_attributes=return_attrs)
        else:
            child_roles = backend.search(object_type="role",
                                        attribute="uuid",
                                        value=uuid,
                                        return_attributes=['role'])
            result = []
            if child_roles:
                result = backend.search(object_type="role",
                                        attribute="uuid",
                                        values=child_roles,
                                        return_attributes=return_attrs)
        return result

    result = []
    processed_roles = []
    # Get roles roles.
    check_roles = _get_roles(uuid=role_uuid,
                            parent=parent,
                            return_attributes=return_attributes)
    if not check_roles:
        return result
    oid_result = backend.search(object_type="role",
                            attribute="uuid",
                            value=role_uuid,
                            return_type="oid")
    role_oid = oid_result[0]
    role_site = role_oid.site

    loop_found = False
    role_uuid_list = []
    while True:
        for uuid in list(check_roles):
            x_role_data = check_roles.pop(uuid)
            if uuid == role_uuid:
                continue
            # Get role data.
            x_name = x_role_data['name']
            x_site = x_role_data['site']
            x_full_oid = x_role_data['full_oid']
            x_enabled = x_role_data['enabled'][0]
            if uuid in role_uuid_list:
                continue
            if skip_disabled:
                if not x_enabled:
                    continue
            role_uuid_list.append(uuid)
            if return_attributes:
                result.append(x_role_data)
            elif return_type == "instance":
                role = backend.get_object(object_type="role", uuid=uuid)
                result.append(role)
            elif return_type == "uuid":
                result.append(uuid)
            elif return_type == "full_oid":
                result.append(x_full_oid)
            elif return_type == "name":
                if x_site == role_site:
                    role_name = x_name
                else:
                    role_name = f"{x_site}/{x_name}"
                result.append(role_name)
            else:
                msg = _("Unknown return type: {return_type}")
                msg = msg.format(return_type=return_type)
                raise OTPmeException(msg)
            if uuid in processed_roles:
                loop_found = True
                continue
            processed_roles.append(uuid)
            # Gets role roles.
            _result = _get_roles(uuid=uuid, parent=parent,
                            return_attributes=return_attributes)
            for x in _result:
                check_roles[x] = _result[x]
        if not recursive:
            break
        if not check_roles:
            break
        if loop_found:
            break
    if not return_attributes:
        result = sorted(result)
    return result

@match_class_typing
class Role(OTPmeObject):
    """ Role object """
    commands = commands

    @classmethod
    def get_backup_data(cls, object_id, object_uuid, object_config, file_content):
        # Get role roles.
        role_roles = backend.search(object_type="role",
                                    attribute="role",
                                    value=object_uuid,
                                    realm=config.realm,
                                    site=config.site)
        file_content['role_roles'] = role_roles
        # Get role groups.
        role_groups = backend.search(object_type="group",
                                    attribute="role",
                                    value=object_uuid,
                                    realm=config.realm,
                                    site=config.site)
        file_content['role_groups'] = role_groups
        return file_content

    @classmethod
    def restore_object_data(cls, object_id, object_uuid, object_data, callback):
        role_roles = object_data['role_groups']
        for x_group_uuid in role_roles:
            x_group = backend.get_object(uuid=x_group_uuid)
            if not x_group:
                msg = _("Unknown group: {x_group_uuid}")
                msg = msg.format(x_group_uuid=x_group_uuid)
                return callback.error(msg)
            x_group.add_role(role_uuid=object_uuid,
                            callback=callback,
                            verify_acls=False)
        role_roles = object_data['role_roles']
        for x_role_uuid in role_roles:
            x_role = backend.get_object(uuid=x_role_uuid)
            if not x_role:
                msg = _("Unknown role: {x_role_uuid}")
                msg = msg.format(x_role_uuid=x_role_uuid)
                return callback.error(msg)
            x_role.add_role(role_uuid=object_uuid,
                            callback=callback,
                            verify_acls=False)
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
        # Set our type (used in parent class)
        self.type = "role"

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

        # Roles should not inherit ACLs by default.
        self.acl_inheritance_enabled = False
        self.dynamic_groups = []

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "TOKENS",
                            "ROLES",
                            "SYNC_USERS",
                            "DYNAMIC_GROUPS",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "TOKENS",
                            "ROLES",
                            "SYNC_USERS",
                            "DYNAMIC_GROUPS",
                            "CONFIG_PARAMS:device_token_suffix",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'SYNC_USERS'                : {
                                                        'var_name'  : 'sync_users',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'ROLES'                    : {
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

                        'DYNAMIC_GROUPS'            : {
                                                        'var_name'  : 'dynamic_groups',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
            }

        return object_config

    def set_variables(self):
        """ Set instance variables """
        # Set OID.
        self.set_oid()

    def _set_name(self, name: str):
        """ Set object name. """
        # Only base roles must have uppercase names.
        base_roles = config.get_base_objects("role")
        if name.upper() in base_roles:
            self.name = name.upper()
        else:
            self.name = name.lower()

    @cli.check_rapi_opts()
    @check_acls(acls=['view:roles'])
    def list_roles(
        self,
        **kwargs,
        ):
        """ Return list with all roles of this role. """
        return self.get_roles(**kwargs)

    def get_roles(
        self,
        return_type: str="name",
        parent: bool=False,
        skip_disabled: bool=False,
        recursive: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Get all roles of this role. """
        result = get_roles(role_uuid=self.uuid,
                            parent=parent,
                            return_type=return_type,
                            skip_disabled=skip_disabled,
                            recursive=recursive)
        if _caller == "API":
            return result
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_access_groups(
        self,
        return_type: str="name",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all access group names this role is in. """
        result = backend.search(realm=self.realm,
                            site=self.site,
                            attribute="role",
                            value=self.uuid,
                            object_type="accessgroup",
                            return_type=return_type)
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @cli.check_rapi_opts()
    @check_acls(acls=['view:groups'])
    def list_groups(
        self,
        **kwargs,
        ):
        """ Return list with all group names this role is in. """
        return self.get_groups(**kwargs)

    def get_groups(
        self,
        return_type: str="uuid",
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all group names this role is in. """
        result = backend.search(realm=self.realm,
                            site=self.site,
                            attribute="role",
                            value=self.uuid,
                            object_type="group",
                            return_type=return_type)
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @cli.check_rapi_opts()
    @check_acls(acls=['view:shares'])
    def list_shares(
        self,
        **kwargs,
        ):
        """ Return list with all shares this role has accces to. """
        return self.get_shares(**kwargs)

    def get_shares(
        self,
        return_type: str="path",
        recursive: bool=False,
        skip_disabled: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        search_attrs = {
                        'role' : {'value':self.uuid},
                    }
        role_shares = backend.search(object_type="share",
                                    attributes=search_attrs,
                                    return_type="instance")
        if recursive:
            role_roles = self.get_roles(return_type="uuid", parent=True, recursive=True)
            if role_roles:
                search_attrs = {
                                'role' : {'values':role_roles},
                            }
                role_shares += backend.search(object_type="share",
                                            attributes=search_attrs,
                                            return_type="instance")
        result = []
        for share in role_shares:
            if skip_disabled:
                if not share.enabled:
                    continue
            if return_type == "instance":
                result.append(share)
            elif return_type == "read_oid":
                result.append(share.oid.read_oid)
            elif return_type == "full_oid":
                result.append(share.oid.full_oid)
            elif return_type == "uuid":
                result.append(share.uuid)
            elif return_type == "path":
                result.append(share.share_id)
            else:
                msg = _("Invalid resturn type: {return_type}")
                msg = msg.format(return_type=return_type)
                if _caller == "API":
                    raise OTPmeException(msg)
                return callback.error(msg)
        if _caller == "API":
            return result
        return callback.ok("\n".join(result))

    @check_acls(['add:token'])
    @object_lock()
    def add_token(
        self,
        token_path: str,
        persist_mount: bool=None,
        share_notifications: bool=None,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Check if token add will add new share permissions. """
        # Try to add token by parent class.
        result = super().add_token(*args, token_path=token_path,
                                    callback=callback, **kwargs)
        if not result:
            return result

        username = token_path.split("/")[0]
        if username == ADMIN_USER:
            return result

        role_shares = self.get_shares(recursive=True,
                                    skip_disabled=False,
                                    return_type="instance")
        if not role_shares:
            return result

        if persist_mount is None:
            persist_mount = True

        def post_method():
            shares = {}
            for share in role_shares:
                # Get share nodes.
                share_nodes = share.get_nodes(include_pools=True,
                                            return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                node_fqdns = []
                for node in share_nodes:
                    node_fqdns.append(node.fqdn)
                share_hosts = []
                if share.limit_by_hosts:
                    share_hosts = share.get_hosts(include_groups=True,
                                                include_roles=True,
                                                return_type="name")
                share_id = share.share_id
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['limit_hosts'] = share.limit_by_hosts
                shares[share_id]['hosts'] = share_hosts
                shares[share_id]['encrypted'] = share.encrypted
                shares[share_id]['tokens'] = [token_path]
                shares[share_id]['persist'] = persist_mount

            notify(username=username, event_type="share_mount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_config_parameter("send_share_notifications")

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @object_lock()
    @check_acls(['remove:token'])
    def remove_token(
        self,
        token_path: str,
        persist_mount: bool=None,
        share_notifications: bool=None,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Check if token remove will remove share permissions. """
        # Remove token by parent class.
        result = super().remove_token(*args, token_path=token_path,
                                    callback=callback, **kwargs)

        if not result:
            return result

        username = token_path.split("/")[0]
        if username == ADMIN_USER:
            return result

        # Get shares of this role.
        role_shares = set(self.get_shares(recursive=True,
                                          skip_disabled=False,
                                          return_type="instance"))

        if persist_mount is None:
            persist_mount = True

        def post_method():
            shares = {}
            for share in role_shares:
                share_tokens = share.get_tokens(skip_disabled=False,
                                              include_roles=True,
                                              return_type="rel_path")
                # If token is still valid for the share skip notification.
                if token_path in share_tokens:
                    continue
                share_nodes = share.get_nodes(include_pools=True,
                                              return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                node_fqdns = []
                for node in share_nodes:
                    node_fqdns.append(node.fqdn)

                share_id = share.share_id
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['encrypted'] = share.encrypted
                shares[share_id]['tokens'] = [token_path]
                shares[share_id]['persist'] = persist_mount

            # Send notification to idled.
            notify(username=username, event_type="share_unmount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_config_parameter("send_share_notifications")

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['add:role'])
    @object_lock()
    def add_role(
        self,
        role_name: str=None,
        role_uuid: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Check if role add will add new share permissions. """
        _role_uuid = role_uuid
        if role_name:
            _role_uuid = self.get_role_uuid(role_name, callback=callback)
        elif not role_uuid:
            msg = "Need <role_name> or <role_uuid>."
            raise OTPmeException(msg)

        if persist_mount is None:
            persist_mount = True

        role_shares = self.get_shares(recursive=True,
                                    skip_disabled=False,
                                    return_type="instance")
        if role_shares:
            role_to_add = backend.get_object(uuid=_role_uuid)
            role_to_add_shares = role_to_add.get_shares(recursive=True,
                                                        skip_disabled=False,
                                                        return_type="instance")
            role_to_add_tokens = role_to_add.get_tokens(skip_disabled=False,
                                                        include_roles=True,
                                                        return_type="rel_path")

            notifys = []
            user_shares = {}
            new_shares = set(role_shares) - set(role_to_add_shares)
            for share in new_shares:
                share_tokens = share.get_tokens(skip_disabled=False,
                                                include_roles=True,
                                                return_type="rel_path")
                notify_tokens = set(list(set(role_to_add_tokens) - set(share_tokens)))
                # Get share nodes.
                share_nodes = share.get_nodes(include_pools=True,
                                            return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                node_fqdns = []
                for node in share_nodes:
                    node_fqdns.append(node.fqdn)
                share_hosts = []
                if share.limit_by_hosts:
                    share_hosts = share.get_hosts(include_groups=True,
                                                include_roles=True,
                                                return_type="name")
                shares = {}
                share_id = share.share_id
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['limit_hosts'] = share.limit_by_hosts
                shares[share_id]['hosts'] = share_hosts
                shares[share_id]['encrypted'] = share.encrypted

                # Collect notifications.
                already_processed = []
                for token_path in notify_tokens:
                    username = token_path.split("/")[0]
                    if username == ADMIN_USER:
                        continue
                    if token_path in already_processed:
                        continue
                    try:
                        x_shares = user_shares[username]
                    except KeyError:
                        x_shares = {}
                    try:
                        tokens = x_shares[share_id]['tokens']
                    except KeyError:
                        tokens = []
                    tokens.append(token_path)
                    share_data = stuff.copy_object(shares)
                    x_shares.update(share_data)
                    x_shares[share_id]['tokens'] = tokens
                    x_shares[share_id]['persist'] = persist_mount
                    user_shares[username] = x_shares
                    already_processed.append(token_path)

            for username in user_shares:
                shares = user_shares[username]
                notifys.append((username, "share_mount", shares))

            def post_method():
                for x in notifys:
                    notify(username=x[0], event_type=x[1], data=x[2])

            if share_notifications is None:
                share_notifications = self.get_config_parameter("send_share_notifications")

            if share_notifications:
                callback.post_methods.append(post_method)

        result = super().add_role(*args, role_name=role_name,
                                role_uuid=role_uuid,
                                callback=callback, **kwargs)
        return result

    @check_acls(['remove:role'])
    @object_lock()
    def remove_role(
        self,
        role_name: str=None,
        role_uuid: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Check if role removal will revoke share permissions. """
        _role_uuid = role_uuid
        if role_name:
            if stuff.is_uuid(role_name):
                _role_uuid = role_name
            else:
                _role_uuid = self.get_role_uuid(role_name, callback=callback)
        elif not role_uuid:
            msg = "Need <role_name> or <role_uuid>."
            raise OTPmeException(msg)

        # Snapshot pre-removal state so we can diff which shares the role
        # loses access to once the parent link is gone.
        role_to_remove = backend.get_object(uuid=_role_uuid)
        shares_before = set(role_to_remove.get_shares(recursive=True,
                                                      skip_disabled=False,
                                                      return_type="instance"))
        if shares_before:
            role_to_remove_tokens = role_to_remove.get_tokens(skip_disabled=False,
                                                              include_roles=True,
                                                              return_type="rel_path")

        result = super().remove_role(*args, role_name=role_name or _role_uuid,
                                        callback=callback, **kwargs)

        if persist_mount is None:
            persist_mount = True

        def post_method():
            shares_after = set(role_to_remove.get_shares(recursive=True,
                                                         skip_disabled=False,
                                                         return_type="instance"))
            lost_shares = shares_before - shares_after

            user_shares = {}
            for share in lost_shares:
                # Tokens that still reach this share via other paths keep
                # access -- only notify those that genuinely lost it.
                share_tokens_after = share.get_tokens(skip_disabled=False,
                                                      include_roles=True,
                                                      return_type="rel_path")
                notify_tokens = set(role_to_remove_tokens) - set(share_tokens_after)
                if not notify_tokens:
                    continue
                share_nodes = share.get_nodes(include_pools=True,
                                              return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                if not share_nodes:
                    continue
                node_fqdns = []
                for node in share_nodes:
                    node_fqdns.append(node.fqdn)
                share_id = share.share_id
                shares = {}
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['encrypted'] = share.encrypted
                already_processed = []
                for token_path in notify_tokens:
                    username = token_path.split("/")[0]
                    if username == ADMIN_USER:
                        continue
                    if token_path in already_processed:
                        continue
                    try:
                        x_shares = user_shares[username]
                    except KeyError:
                        x_shares = {}
                    try:
                        tokens = x_shares[share_id]['tokens']
                    except KeyError:
                        tokens = []
                    tokens.append(token_path)
                    share_data = stuff.copy_object(shares)
                    x_shares.update(share_data)
                    x_shares[share_id]['tokens'] = tokens
                    x_shares[share_id]['persist'] = persist_mount
                    user_shares[username] = x_shares
                    already_processed.append(token_path)
            for username in user_shares:
                shares = user_shares[username]
                notify(username=username, event_type="share_unmount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_config_parameter("send_share_notifications")

        if shares_before and share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['add:host'])
    @object_lock()
    def add_host(
        self,
        *args,
        host_name: str=None,
        host_uuid: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a host to this role. """
        affected_shares = backend.search(object_type="share",
                                         attribute="role",
                                         value=self.uuid,
                                         return_type="instance")
        affected_shares = [s for s in affected_shares if s.limit_by_hosts]

        # Try to add host via parent class.
        result = super().add_host(*args, host_name=host_name,
                                host_uuid=host_uuid,
                                callback=callback, **kwargs)

        if not result:
            return result

        if not host_name:
            host = backend.get_object(uuid=host_uuid)
            host_name = host.name

        for share in affected_shares:
            share._notify_share_metadata_change("share_add_host", callback, host=host_name,
                                                persist_mount=persist_mount,
                                                share_notifications=share_notifications)
        return result

    @check_acls(['remove:host'])
    @object_lock()
    def remove_host(
        self,
        *args,
        host_name: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a host to this group. """
        affected_shares = backend.search(object_type="share",
                                         attribute="role",
                                         value=self.uuid,
                                         return_type="instance")
        affected_shares = [s for s in affected_shares if s.limit_by_hosts]

        # Try to remove host via parent class.
        result = super().remove_host(*args, host_name=host_name,
                                    callback=callback, **kwargs)
        if not result:
            return result

        for share in affected_shares:
            share._notify_share_metadata_change("share_remove_host", callback, host=host_name,
                                                persist_mount=persist_mount,
                                                share_notifications=share_notifications)
        return result

    def get_hosts(
        self,
        return_type: str="name",
        _caller: str="API",
        recursive: bool=True,
        skip_disabled: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all hosts assigned to this role. """
        result = []

        if self.hosts:
            search_attr = {}
            if skip_disabled:
                search_attr['enabled'] = {}
                search_attr['enabled']['value'] = True
            return_attributes = ['site', return_type]
            search_result = backend.search(object_type="host",
                                        attribute="uuid",
                                        values=self.hosts,
                                        attributes=search_attr,
                                        return_attributes=return_attributes)
            for uuid in search_result:
                try:
                    host_name = search_result[uuid][return_type]
                except Exception:
                    continue
                result.append(host_name)

        if not recursive:
            result = list(set(result))
            result.sort()
            return result

        for role_uuid in self.roles:
            role = backend.get_object(uuid=role_uuid)
            if not role:
                continue
            if skip_disabled:
                if not role.enabled:
                    continue
            result += role.get_hosts(return_type=return_type)

        result = list(set(result))
        result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @check_acls(['enable:object'])
    @object_lock()
    def enable(
        self,
        *args,
        persist_mount: bool=None,
        share_notifications: bool=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Send share_mount notifications on enable.

        Tokens of this role couldn't reach the role's shares while the
        role was disabled. After enable the path opens. Pre-snapshot
        share.get_tokens(skip_disabled=True) per share so we notify
        only tokens that genuinely gain new access -- tokens already
        reaching the share via another enabled path were already
        mounted and don't need a redundant share_mount. """
        role_tokens = self.get_tokens(skip_disabled=False,
                                      include_roles=True,
                                      return_type="rel_path")
        role_shares = self.get_shares(recursive=True,
                                      skip_disabled=False,
                                      return_type="instance")
        share_tokens_before = {}
        for share in role_shares:
            share_tokens_before[share.uuid] = set(share.get_tokens(
                            skip_disabled=True,
                            include_roles=True,
                            return_type="rel_path"))

        result = super().enable(*args, callback=callback, **kwargs)
        if not result:
            return result

        if persist_mount is None:
            persist_mount = True

        def post_method():
            user_shares = {}
            for share in role_shares:
                share_tokens_after = set(share.get_tokens(
                                skip_disabled=True,
                                include_roles=True,
                                return_type="rel_path"))
                # Newly reaching tokens that belong to this role.
                gained = share_tokens_after - share_tokens_before[share.uuid]
                notify_tokens = gained & set(role_tokens)
                if not notify_tokens:
                    continue
                share_nodes = share.get_nodes(include_pools=True,
                                              return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                if not share_nodes:
                    continue
                node_fqdns = [node.fqdn for node in share_nodes]
                share_hosts = []
                if share.limit_by_hosts:
                    share_hosts = share.get_hosts(include_groups=True,
                                                include_roles=True,
                                                return_type="name")
                share_id = share.share_id
                shares = {}
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['limit_hosts'] = share.limit_by_hosts
                shares[share_id]['hosts'] = share_hosts
                shares[share_id]['encrypted'] = share.encrypted
                already_processed = []
                for token_path in notify_tokens:
                    username = token_path.split("/")[0]
                    if username == ADMIN_USER:
                        continue
                    if token_path in already_processed:
                        continue
                    try:
                        x_shares = user_shares[username]
                    except KeyError:
                        x_shares = {}
                    try:
                        tokens = x_shares[share_id]['tokens']
                    except KeyError:
                        tokens = []
                    tokens.append(token_path)
                    share_data = stuff.copy_object(shares)
                    x_shares.update(share_data)
                    x_shares[share_id]['tokens'] = tokens
                    x_shares[share_id]['persist'] = persist_mount
                    user_shares[username] = x_shares
                    already_processed.append(token_path)
            for username in user_shares:
                shares = user_shares[username]
                notify(username=username, event_type="share_mount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_config_parameter("send_share_notifications")

        if role_shares and role_tokens and share_notifications:
            callback.post_methods.append(post_method)
        return result

    @check_acls(['disable:object'])
    @object_lock()
    def disable(
        self,
        *args,
        persist_mount: bool=None,
        share_notifications: bool=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Send share_unmount notifications on disable.

        Pre-snapshot the tokens reachable via this role. After disable,
        a role_token that is no longer in share.get_tokens
        (skip_disabled=True) has genuinely lost access -- the role's
        path is gone and no other enabled path reaches it. """
        role_tokens = self.get_tokens(skip_disabled=False,
                                      include_roles=True,
                                      return_type="rel_path")
        role_shares = self.get_shares(recursive=True,
                                      skip_disabled=False,
                                      return_type="instance")

        result = super().disable(*args, callback=callback, **kwargs)
        if not result:
            return result

        if persist_mount is None:
            persist_mount = True

        def post_method():
            user_shares = {}
            for share in role_shares:
                share_tokens_after = set(share.get_tokens(
                                skip_disabled=True,
                                include_roles=True,
                                return_type="rel_path"))
                # role_tokens that disappeared from the share's reach.
                notify_tokens = set(role_tokens) - share_tokens_after
                if not notify_tokens:
                    continue
                share_nodes = share.get_nodes(include_pools=True,
                                              return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                if not share_nodes:
                    continue
                node_fqdns = [node.fqdn for node in share_nodes]
                share_hosts = []
                if share.limit_by_hosts:
                    share_hosts = share.get_hosts(include_groups=True,
                                                include_roles=True,
                                                return_type="name")
                share_id = share.share_id
                shares = {}
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['limit_hosts'] = share.limit_by_hosts
                shares[share_id]['hosts'] = share_hosts
                shares[share_id]['encrypted'] = share.encrypted
                already_processed = []
                for token_path in notify_tokens:
                    username = token_path.split("/")[0]
                    if username == ADMIN_USER:
                        continue
                    if token_path in already_processed:
                        continue
                    try:
                        x_shares = user_shares[username]
                    except KeyError:
                        x_shares = {}
                    try:
                        tokens = x_shares[share_id]['tokens']
                    except KeyError:
                        tokens = []
                    tokens.append(token_path)
                    share_data = stuff.copy_object(shares)
                    x_shares.update(share_data)
                    x_shares[share_id]['tokens'] = tokens
                    x_shares[share_id]['persist'] = persist_mount
                    user_shares[username] = x_shares
                    already_processed.append(token_path)
            for username in user_shares:
                shares = user_shares[username]
                notify(username=username, event_type="share_unmount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_config_parameter("send_share_notifications")

        if role_shares and role_tokens and share_notifications:
            callback.post_methods.append(post_method)
        return result

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog()
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename role. """
        base_roles = config.get_base_objects("role")
        if self.name in base_roles:
            return callback.error(_("Cannot rename base role."))
        # Build new OID.
        new_oid = oid.get(object_type="role",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    @object_changelog()
    def add(
        self,
        groups: Union[list,None]=None,
        roles: Union[list,None]=None,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a role. """
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
                    if not _group.verify_acl("add:groups"):
                        msg = _("Group: {group_name}: Permission denied")
                        msg = msg.format(group_name=group_name)
                        return callback.error(msg)
                # Acquire lock.
                #_group._cache(callback=callback)
                _groups.append(_group)

        _roles = []
        if roles is not None:
            for role_name in roles:
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
                    if not _role.verify_acl("add:role"):
                        msg = _("Role: {role_name}: Permission denied")
                        msg = msg.format(role_name=role_name)
                        return callback.error(msg)
                _roles.append(_role)

        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(verify_acls=verify_acls,
                                callback=callback, **kwargs)
        if result is False:
            return callback.error()

        # Add object using parent class.
        add_result = OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

        # Add role to given groups.
        for _group in _groups:
            _group.add_role(role_name=self.name,
                            verify_acls=verify_acls,
                            callback=callback)
        # Add role to given roles.
        for _role in _roles:
            _role.add_role(role_name=self.name,
                        verify_acls=verify_acls,
                        callback=callback)
        return add_result


    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog()
    def delete(
        self,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Delete role. """
        if not self.exists():
            return callback.error(_("Role does not exist."))

        base_roles = config.get_base_objects("role")
        if self.name in base_roles:
            return callback.error(_("Cannot delete base role."))

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {role_name}")
                    msg = msg.format(role_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if self.tokens:
            msg = _("The role has tokens assigned.")
            return callback.error(msg)

        if self.roles:
            msg = _("The role has roles assigned.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        exception_parts = []
        # List that will hold all tokens that uses this role.
        token_list = []
        # Get all tokens from this role.
        for t_uuid in self.tokens:
            token = backend.get_object(object_type="token", uuid=t_uuid)
            if token:
                token_list.append(token.rel_path)
            else:
                token_list.append(t_uuid)

        if token_list:
            msg = _("Role has member tokens: {token_list}")
            exception_parts.append(msg.format(token_list=', '.join(token_list)))

        # List that will hold all groups that uses this role.
        accessgroup_list = self.get_access_groups()

        if accessgroup_list:
            msg = _("Role is member of this access groups: {accessgroup_list}")
            exception_parts.append(msg.format(accessgroup_list=', '.join(accessgroup_list)))

        exception = chr(10).join(exception_parts) if exception_parts else None
        if not self.ask_delete_confirmation(force=force, exception=exception, callback=callback):
            return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

    @check_acls(['remove:orphans'])
    @object_lock()
    @audit_log()
    @object_changelog()
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
            if token_oid:
                continue
            token_list.append(i)

        role_list = []
        for i in self.roles:
            role_oid = backend.get_oid(object_type="role", uuid=i)
            if role_oid:
                continue
            role_list.append(i)

        host_list = []
        for i in self.hosts:
            host_oid = backend.get_oid(object_type="host", uuid=i)
            if not host_oid:
                host_list.append(i)

        device_list = []
        for i in self.devices:
            device_oid = backend.get_oid(object_type="device", uuid=i)
            if not device_oid:
                device_list.append(i)

        msg = ""
        if acl_list:
            msg_part = _("{msg}{object_type}|{object_name}: Found the following orphan ACLs: {acl_list}\n")
            msg = msg_part.format(msg=msg, object_type=self.type, object_name=self.name, acl_list=','.join(acl_list))

        if policy_list:
            msg_part = _("{msg}{object_type}|{object_name}: Found the following orphan policies: {policy_list}\n")
            msg = msg_part.format(msg=msg, object_type=self.type, object_name=self.name, policy_list=','.join(policy_list))

        if token_list:
            msg_part = _("{msg}{object_type}|{object_name}: Found the following orphan token UUIDs: {token_list}\n")
            msg = msg_part.format(msg=msg, object_type=self.type, object_name=self.name, token_list=','.join(token_list))

        if role_list:
            msg_part = _("{msg}{object_type}|{object_name}: Found the following orphan role UUIDs: {role_list}\n")
            msg = msg_part.format(msg=msg, object_type=self.type, object_name=self.name, role_list=','.join(role_list))

        if host_list:
            msg += _("{type}|{name}: Found the following orphan host UUIDs: {host_list}\n").format(
                type=self.type, name=self.name, host_list=','.join(host_list))
        if device_list:
            msg += _("{type}|{name}: Found the following orphan device UUIDs: {device_list}\n").format(
                type=self.type, name=self.name, device_list=','.join(device_list))

        if msg:
            msg = _("{msg}Remove?: ").format(msg=msg)
            if not self.ask_change_confirmation(msg, force=force, callback=callback):
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
                msg = _("Removing orphan token UUID: {token_uuid}")
                msg = msg.format(token_uuid=i)
                callback.send(msg)
            object_changed = True
            # Update index.
            self.del_index('token', i)
            try:
                self.tokens.remove(i)
            except KeyError:
                pass
            try:
                self.token_options.pop(i)
            except KeyError:
                pass
            try:
                self.token_login_interfaces.pop(i)
            except KeyError:
                pass

        for i in role_list:
            if verbose_level > 0:
                msg = _("Removing orphan role UUID: {role_uuid}")
                msg = msg.format(role_uuid=i)
                callback.send(msg)
            object_changed = True
            self.roles.remove(i)
            # Update index.
            self.del_index('role', i)

        for i in device_list:
            if verbose_level > 0:
                msg = _("Removing orphan device UUID: {uuid}")
                msg = msg.format(uuid=i)
                callback.send(msg)
            object_changed = True
            self.devices.remove(i)

        for i in host_list:
            if verbose_level > 0:
                msg = _("Removing orphan host UUID: {uuid}")
                msg = msg.format(uuid=i)
                callback.send(msg)
            object_changed = True
            self.hosts.remove(i)

        if not object_changed:
            msg = _("No orphan objects found for {object_type}: {object_name}")
            msg = msg.format(object_type=self.type, object_name=self.name)
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show role config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        token_list = []
        if self.tokens:
            if self.verify_acl("view:tokens"):
                return_attrs = ['rel_path']
                token_list = backend.search(object_type="token",
                                            join_object_type="role",
                                            join_search_attr="uuid",
                                            join_search_val=self.uuid,
                                            join_attribute="token",
                                            attribute="uuid",
                                            value="*",
                                            return_attributes=return_attrs)
            token_list.sort()

        role_list = []
        if self.roles:
            if self.verify_acl("view:roles"):
                return_attrs = ['site', 'name']
                roles_result = backend.search(object_type="role",
                                            join_object_type="role",
                                            join_search_attr="uuid",
                                            join_search_val=self.uuid,
                                            join_attribute="role",
                                            attribute="uuid",
                                            value="*",
                                            return_attributes=return_attrs)
                for x in roles_result:
                    role_site = roles_result[x]['site']
                    role_name = roles_result[x]['name']
                    if role_site != config.site:
                        role_name = f"{role_site}/{role_name}"
                    role_list.append(role_name)
            role_list.sort()

        if self.verify_acl("view:hosts") \
        or self.verify_acl("add:hosts") \
        or self.verify_acl("remove:hosts"):
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

        if self.verify_acl("view:roles"):
            lines.append(f'ROLES="{",".join(role_list)}"')
        else:
            lines.append('ROLES=""')


        if self.verify_acl("view:accessgroups"):
            lines.append(f'ACCESS_GROUPS="{",".join(self.get_access_groups())}"')
        else:
            lines.append('ACCESS_GROUPS=""')

        if self.verify_acl("view:groups"):
            lines.append(f'GROUPS="{",".join(self.get_groups())}"')
        else:
            lines.append('GROUPS=""')

        if self.verify_acl("view:tokens"):
            lines.append(f'TOKENS="{",".join(token_list)}"')
        else:
            lines.append('TOKENS=""')

        lines.append(f'HOSTS="{",".join(host_list)}"')
        lines.append(f'DEVICES="{",".join(devices_list)}"')

        token_options = {}
        for uuid in self.token_options:
            if uuid in x_list:
                token_path = x_list[uuid]['rel_path']
            else:
                token_path = uuid
            token_options[token_path] = self.token_options[uuid]
        lines.append(f'TOKEN_OPTIONS="{token_options}"')

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show role details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = _("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
