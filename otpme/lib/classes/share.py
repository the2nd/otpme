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
from otpme.lib import otpme_acl
from otpme.lib.idle import notify
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.realm import ADMIN_USER
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.cache import assigned_host_cache
from otpme.lib.daemon.scriptd import run_script
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.classes.otpme_object import name_len_setter
from otpme.lib.protocols.utils import register_commands
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

logger = config.logger

default_callback = config.get_callback()

DEFAULT_UNIT = "shares"
REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.site",
                "otpme.lib.classes.unit",
                "otpme.lib.classes.script",
                ]

ADD_SCRIPT_NAME = "add_share.sh"
MOUNT_SCRIPT_NAME = "mount_share.sh"

read_acls = []

write_acls =  [
                "limit_hosts",
                "unlimit_hosts",
            ]


read_value_acls = {
                    "view"      : [
                                    "tokens",
                                    "roles",
                                    "nodes",
                                    "hosts",
                                    "pools",
                                    "groups",
                                    "policy",
                                    "root_dir",
                                    "encrypted",
                                    "sotp_signing",
                                    "share_key",
                                    "block_size",
                                    "read_only",
                                    "force_group",
                                    "force_create_mode",
                                    "force_directory_mode",
                                    "home_share_permissions",
                                    "master_password_tokens",
                                    "master_password_hash_params",
                                    "root_mount_tokens",
                                    "no_mount_tokens",
                                    "add_script",
                                    "mount_script",
                                    "mount_script_enabled",
                                    "limit_hosts",
                                    "home_share",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                    "token",
                                    "role",
                                    "node",
                                    "host",
                                    "pool",
                                    "group",
                                    "share_key",
                                    "master_password_token",
                                    "root_mount_token",
                                    "no_mount_token",
                                ],
                    "delete"       : [
                                    "share_key",
                                ],
                    "remove"    : [
                                    "token",
                                    "role",
                                    "node",
                                    "host",
                                    "pool",
                                    "group",
                                    "master_password_token",
                                    "root_mount_token",
                                    "no_mount_token",
                                ],
                    "enable"    : [
                                    "read_only",
                                    "sotp_signing",
                                    "add_script",
                                    "mount_script",
                                ],
                    "disable"    : [
                                    "read_only",
                                    "sotp_signing",
                                    "add_script",
                                    "mount_script",
                                ],
                    "edit"    : [
                                    "sign_public_keys",
                                    "root_dir",
                                    "force_group",
                                    "force_create_mode",
                                    "force_directory_mode",
                                    "home_share_permissions",
                                    "add_script",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'home_share', 'home_share_uid', 'force_group', 'force_create_mode', 'force_directory_mode', 'encrypted', 'no_key_gen', 'block_size', 'restore_share', 'restore_token'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'home_share', 'home_share_uid', 'force_group', 'force_create_mode', 'force_directory_mode', 'encrypted', 'no_key_gen', 'block_size', 'restore_share', 'restore_token'],
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
    'touch'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'touch',
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
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("share"),
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
                                        'max_nodes',
                                        'max_hosts',
                                        'max_pools',
                                        'max_roles',
                                        'max_tokens',
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
    'root_dir'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_root_dir',
                    'args'              : ['root_dir'],
                    'job_type'          : 'process',
                    },
                },
            },
    'force_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'force_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'force_create_mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'force_create_mode',
                    'args'              : ['create_mode'],
                    'job_type'          : 'process',
                    },
                },
            },
    'home_share_permissions'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_home_share_permissions',
                    'args'              : ['permissions'],
                    'job_type'          : 'process',
                    },
                },
            },
    'force_directory_mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'force_directory_mode',
                    'args'              : ['create_mode'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_ro'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_ro',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_ro'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_ro',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_sotp_signing'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sotp_signing',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_sotp_signing'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sotp_signing',
                    'job_type'          : 'process',
                    },
                },
            },
    'update_sign_public_keys'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'update_sign_public_keys',
                    'oargs'             : ['username'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_share_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_share_key',
                    'args'              : ['username', 'share_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_share_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_share_key',
                    'args'              : ['username'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_share_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_share_key',
                    'args'              : ['username'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.list_getter("share"),
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
                    'method'            : cli.list_getter("share"),
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
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
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
    'limit_hosts'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'limit_hosts',
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'unlimit_hosts'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'unlimit_hosts',
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'thread',
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
    'add_master_password_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_master_password_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_master_password_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_master_password_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_root_mount_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_root_mount_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_root_mount_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_root_mount_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_no_mount_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_no_mount_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_no_mount_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_no_mount_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['keep_share_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_pool'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_pool',
                    'args'              : ['pool_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_pool'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_pool',
                    'args'              : ['pool_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_host'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_host',
                    'args'              : ['host_name'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_host'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_host',
                    'args'              : ['host_name'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_node'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_node',
                    'args'              : ['node_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_node'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_node',
                    'args'              : ['node_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['keep_share_key', 'share_notifications', 'persist_mount'],
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
    'add_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_group',
                    'args'              : ['group_name'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_group',
                    'args'              : ['group_name'],
                    'oargs'             : ['share_notifications', 'persist_mount'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_hosts'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_hosts',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_nodes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_nodes',
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
                    'job_type'          : 'process',
                    },
                },
            },
    'list_roles'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_roles',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_policies'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_policies',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'list_pools'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_pools',
                    'oargs'             : ['return_type', 'skip_disabled'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'list_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_groups',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
                    'job_type'          : 'thread',
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
    'mount_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_mount_script',
                    'oargs'             : ['mount_script', 'script_options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_mount_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_mount_script',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_mount_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_mount_script',
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
    'show_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : ['parameter'],
                    'job_type'          : 'thread',
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
    config_params = config.get_config_parameters("share")
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
    acls += config.get_default_acls("share")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("share")
    return acls

def register():
    register_oid()
    config.register_config_parameter(name="max_share_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_config()
    register_backend()
    register_scripts()
    register_object_unit()
    register_sync_settings()
    register_config_parameters()
    register_commands("share", commands)
    # Register index attributes.
    config.register_index_attribute("share")
    config.register_index_attribute("pool")
    config.register_index_attribute("root_dir")
    config.register_index_attribute("root_mount_token")
    config.register_index_attribute("no_mount_token")
    config.register_recursive_default_acl("site", "+share")
    config.register_default_acl("unit", "+share")
    config.register_recursive_default_acl("unit", "+share")
    config.register_auth_on_action_hook("share", "add_host")
    config.register_auth_on_action_hook("share", "remove_host")
    config.register_auth_on_action_hook("share", "add_group")
    config.register_auth_on_action_hook("share", "remove_group")
    config.register_auth_on_action_hook("share", "limit_hosts")
    config.register_auth_on_action_hook("share", "unlimit_hosts")
    config.register_auth_on_action_hook("share", "enable_mount_script")
    config.register_auth_on_action_hook("share", "disable_mount_script")
    config.register_auth_on_action_hook("share", "change_mount_script")
    config.register_auth_on_action_hook("share", "show_config_parameters")

def register_hooks():
    config.register_auth_on_action_hook("share", "set_config_parameter")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT)
    config.register_default_unit("share", DEFAULT_UNIT)

def register_scripts():
    """ Registger scripts. """
    config.register_base_object("script", ADD_SCRIPT_NAME)
    config.register_base_object("script", MOUNT_SCRIPT_NAME)

def register_config_parameters():
    """ Registger config parameters. """
    # Object types our config parameters are valid for.
    object_types = [
                        'site',
                        'unit',
                    ]
    def script_setter(script_path, **kwargs):
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
    def script_getter(script_uuid, **kwargs):
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
    # Default add script to add to new shares.
    ADD_SCRIPT_PATH = f"{scripts_unit}/{ADD_SCRIPT_NAME}"
    config.register_config_parameter(name="default_share_add_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=ADD_SCRIPT_PATH,
                                    object_types=object_types)
    # Default mount script to add to new shares.
    MOUNT_SCRIPT_PATH = f"{scripts_unit}/{MOUNT_SCRIPT_NAME}"
    config.register_config_parameter(name="default_share_mount_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=MOUNT_SCRIPT_PATH,
                                    object_types=object_types)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    share_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    share_path_re = f'{unit_path_re}[/]{share_name_re}'
    share_oid_re = f'share|{share_path_re}'
    oid.register_oid_schema(object_type="share",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=share_name_re,
                            path_regex=share_path_re,
                            oid_regex=share_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="share",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="share")

def register_backend():
    """ Register object for the file backend. """
    share_dir_extension = "share"
    def path_getter(share_oid, share_uuid):
        return backend.config_path_getter(share_oid, share_dir_extension)
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
        return backend.rebuild_object_index("share", objects, after)
    # Register object to config.
    config.register_object_type(object_type="share",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["node"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Share
    backend.register_object_type(object_type="share",
                                dir_name_extension=share_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_config():
    # Object types our config parameters are valid for.
    object_types = [
                    'site',
                    'unit',
                    'user',
                    'token',
                    ]
    def share_root_setter(share_root, **kwargs):
        if not os.path.isdir(share_root):
            msg = _("Directory does not exists: {share_root}")
            msg = msg.format(share_root=share_root)
            raise ValueError(msg)
        return share_root
    # Default password hash algo.
    # This is the containment boundary every share root_dir is checked
    # against, so it must not be settable by whoever may edit a share.
    config.register_config_parameter(name="share_root",
                                    ctype=str,
                                    setter=share_root_setter,
                                    default_value="/otpme-mounts/",
                                    admin_only=True,
                                    object_types=object_types)

@match_class_typing
class Share(OTPmeObject):
    """ Class that implements OTPme share object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "share"
        # Share root dir
        self.root_dir = None
        self.home_share = False
        self.home_share_uid = False
        self.encrypted = False
        # Require the client to sign the SOTP it authenticates with.
        self.sotp_signing = False
        self.block_size = 4096

        # Call parent class init.
        super().__init__(object_id=object_id, **kwargs)

        self.read_only = False
        self.create_mode = "0o000"
        self.directory_mode = "0o000"
        # Mode the per user directories of a home share are created with.
        # The default keeps the users out of each others home dirs.
        self.home_share_permissions = "0o700"
        self.force_group_uuid = None

        self.limit_by_hosts = False
        self.restore_share = None
        self.track_last_used = True

        self.add_script = None
        self.mount_script = None
        self.mount_script_enabled = False

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Roles should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "ROOT_DIR",
                            "READ_ONLY",
                            "ENCRYPTED",
                            "TOKENS",
                            "ROLES",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "ROOT_DIR",
                            "READ_ONLY",
                            "ENCRYPTED",
                            "SOTP_SIGNING",
                            "SIGN_PUBLIC_KEYS",
                            "TOKENS",
                            "ROLES",
                            ]
                        },
                    }

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is lowercase.
        self.name = name.lower()

    def set_variables(self):
        """ Set instance variables. """
        return True

    @property
    def share_id(self):
        share_id = f"{self.site}/{self.name}"
        return share_id

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'ROOT_DIR'                  : {
                                                        'var_name'  : 'root_dir',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'HOME_SHARE'                : {
                                                        'var_name'  : 'home_share',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'HOME_SHARE_UID'            : {
                                                        'var_name'  : 'home_share_uid',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'ENCRYPTED'                 : {
                                                        'var_name'  : 'encrypted',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'SOTP_SIGNING'              : {
                                                        'var_name'  : 'sotp_signing',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'BLOCK_SIZE'                : {
                                                        'var_name'  : 'block_size',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },
                        'READ_ONLY'                : {
                                                        'var_name'  : 'read_only',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'FORCE_GROUP'               : {
                                                        'var_name'  : 'force_group_uuid',
                                                        'type'      : 'uuid',
                                                        'force_type': True,
                                                        'required'  : False,
                                                    },
                        'CREATE_MODE'               : {
                                                        'var_name'  : 'create_mode',
                                                        'type'      : str,
                                                        'force_type': True,
                                                        'required'  : False,
                                                    },
                        'DIRECTORY_MODE'            : {
                                                        'var_name'  : 'directory_mode',
                                                        'type'      : str,
                                                        'force_type': True,
                                                        'required'  : False,
                                                    },
                        'HOME_SHARE_PERMISSIONS'    : {
                                                        'var_name'  : 'home_share_permissions',
                                                        'type'      : str,
                                                        'force_type': True,
                                                        'required'  : False,
                                                    },
                        'MASTER_PASSWORD_TOKENS'    : {
                                                        'var_name'  : 'master_password_tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'MASTER_PASSWORD_HASH_PARAMS': {
                                                        'var_name'  : 'master_password_hash_params',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
                        'ROOT_MOUNT_TOKENS'         : {
                                                        'var_name'  : 'root_mount_tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'NO_MOUNT_TOKENS'           : {
                                                        'var_name'  : 'no_mount_tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'SHARE_KEYS'                : {
                                                        'var_name'  : 'share_keys',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
                        'SIGN_PUBLIC_KEYS'          : {
                                                        'var_name'  : 'sign_public_keys',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
                        'POOLS'                     : {
                                                        'var_name'  : 'pools',
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

                        'NODES'                     : {
                                                        'var_name'  : 'nodes',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'HOSTS'                     : {
                                                        'var_name'  : 'hosts',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'GROUPS'                    : {
                                                        'var_name'  : 'groups',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'ADD_SCRIPT'               : {
                                                        'var_name'  : 'add_script',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'ADD_SCRIPT_OPTIONS'       : {
                                                        'var_name'  : 'add_script_options',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'MOUNT_SCRIPT'              : {
                                                        'var_name'  : 'mount_script',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },

                        'MOUNT_SCRIPT_OPTIONS'      : {
                                                        'var_name'  : 'mount_script_options',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'MOUNT_SCRIPT_ENABLED'      : {
                                                        'var_name'  : 'mount_script_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'RESTORE_SHARE'             : {
                                                        'var_name'  : 'restore_share',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'LIMIT_HOSTS'               : {
                                                        'var_name'  : 'limit_by_hosts',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        }

        return object_config

    @property
    def share_root(self):
        share_root = config.share_root
        if not share_root:
            share_root = self.get_config_parameter('share_root')
        share_root = os.path.realpath(share_root)
        return share_root

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    @object_changelog("add")
    def add(
        self,
        home_share: bool=False,
        home_share_uid: bool=False,
        force_group: str=None,
        force_create_mode: str=None,
        force_directory_mode: str=None,
        encrypted: bool=False,
        key_len: int=32,
        block_size: int=4096,
        no_key_gen: bool=False,
        restore_share: str=None,
        restore_token: str=None,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if home_share_uid and not home_share:
            home_share = True
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        backup_enabled = self.get_config_parameter("backup_enabled")
        if backup_enabled:
            self.set_config_param(parameter='backup_enabled',
                                value=True,
                                callback=callback)
        if restore_share:
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=restore_share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                msg = _("Unknown share: {restore_share}")
                msg = msg.format(restore_share=restore_share)
                return callback.error(msg)
            share = result[0]
            if restore_token:
                result = backend.search(object_type="token",
                                        attribute="rel_path",
                                        value=restore_token,
                                        return_type="uuid")
                if not result:
                    msg = _("Unknown token.")
                    return callback.error(msg)
                token_uuid = result[0]
                if token_uuid not in share.tokens:
                    msg = _("Token not assigned to share.")
                    return callback.error(msg)
                share_key = None
                if share.encrypted:
                    token_user = restore_token.split("/")[0]
                    share_key = share.get_share_key(username=token_user)
                    if not share_key:
                        msg = _("No share key available for user: {user}")
                        msg = msg.format(user=token_user)
                        return callback.error(msg)
                if not self.add_token(token_path=restore_token,
                                        share_key=share_key,
                                        persist_mount=False,
                                        callback=callback):
                    msg = _("Failed to add token: {token}")
                    msg = msg.format(token=restore_token)
                    return callback.error(msg)
            self.restore_share = share.uuid
            self.home_share = share.home_share
            self.home_share_uid = share.home_share_uid
            self.home_share_permissions = share.home_share_permissions
            self.encrypted = share.encrypted
            if share.force_group_uuid:
                self.force_group(group_uuid=share.force_group_uuid,
                                    verify_acls=False)
            # Add object using parent class.
            add_result = super().add(verify_acls=verify_acls,
                                            verbose_level=verbose_level,
                                            callback=callback, **kwargs)
            return self._write(callback=callback)

        if force_group:
            self.force_group(group_name=force_group,
                            verify_acls=False)
        if force_create_mode:
            if not self.force_create_mode(create_mode=force_create_mode,
                                        callback=callback,
                                        verify_acls=False):
                return callback.error()
        if force_directory_mode:
            if not self.force_directory_mode(create_mode=force_directory_mode,
                                            callback=callback,
                                            verify_acls=False):
                return callback.error()
        # Default add script.
        default_add_script = self.get_config_parameter("default_share_add_script")
        if default_add_script:
            if verbose_level > 0:
                msg = _("Setting default add script: {default_add_script}")
                msg = msg.format(default_add_script=default_add_script)
                callback.send(msg)
            self.change_add_script(default_add_script,
                                    verify_acls=False,
                                    callback=callback)
        # Default mount script.
        default_mount_script = self.get_config_parameter("default_share_mount_script")
        if default_mount_script:
            if verbose_level > 0:
                msg = _("Setting default mount script: {default_mount_script}")
                msg = msg.format(default_mount_script=default_mount_script)
                callback.send(msg)
            self.change_mount_script(default_mount_script,
                                    verify_acls=False,
                                    callback=callback)
        # Get root dir.
        root_dir = os.path.join(self.share_root, self.name)
        # Run share add script.
        try:
            self.run_share_script(self.add_script, root_dir)
        except Exception as e:
            msg = _("Failed to run share add script: {add_script}: {e}")
            msg = msg.format(add_script=self.add_script, e=e)
            return callback.error(msg)
        # Check if root dir exists. The share is being created, there is
        # no old root dir to ask about.
        if not self.set_root_dir(root_dir, force=True, callback=callback):
            return callback.error()
        self.home_share = home_share
        self.home_share_uid = home_share_uid
        self.encrypted = encrypted
        self.add_index('encrypted', self.encrypted)
        self.add_index('sotp_signing', self.sotp_signing)
        if self.encrypted:
            self.block_size = block_size
            self.add_index('block_size', self.block_size)
        # Add object using parent class.
        add_result = super().add(verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback, **kwargs)
        if self.encrypted and add_result and not no_key_gen and not self.home_share:
            msg = _("Generating AES key for encrypted share...")
            callback.send(msg)
            if not config.auth_user:
                msg = _("Unable to add share without auth user.")
                return callback.error(msg)
            key_mode = config.auth_user.key_mode
            share_key_response = callback.gen_share_key(key_len=key_len, key_mode=key_mode)
            if not share_key_response:
                msg = _("Received empty share key response.")
                return callback.error(msg)
            try:
                share_key = share_key_response['share_key']
            except KeyError:
                msg = _("Share key response misses share key.")
                return callback.error(msg)
            try:
                self.master_password_hash_params = share_key_response['hash_params']
            except KeyError:
                msg = _("Share key response misses master password hash parameters.")
                return callback.error(msg)
            if not self.add_token(token_path=config.auth_token.rel_path,
                            share_key=share_key,
                            callback=callback):
                return callback.error()
        # Add index attributes.
        self.update_index('create_mode', self.create_mode)
        self.update_index('directory_mode', self.directory_mode)
        return self._write(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog("rename from {self.name} to {new_name}")
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename share. """
        # Build new OID.
        new_oid = oid.get(object_type="share",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    @check_acls(['edit:root_dir'])
    @object_lock()
    @audit_log()
    @object_changelog("set root directory to {root_dir}")
    def set_root_dir(
        self,
        root_dir,
        force: bool=False,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if self.root_dir == root_dir:
            msg = _("Root dir already set to: {root_dir}")
            msg = msg.format(root_dir=self.root_dir)
            return callback.error(msg)
        # Make sure root dir is in share root.
        common_path = os.path.commonpath([self.share_root, root_dir])
        if common_path != self.share_root:
            msg = _("Root dir not in share root: {share_root}: {root_dir}")
            msg = msg.format(share_root=self.share_root, root_dir=root_dir)
            return callback.error(msg)
        if not os.path.exists(root_dir):
            msg = _("No such file or directory: {root_dir}")
            msg = msg.format(root_dir=root_dir)
            return callback.error(msg)
        msg = _("Change root dir of share '{share_name}' from '{old_dir}' to '{new_dir}'? The data below the old one is not served anymore.: ")
        msg = msg.format(share_name=self.name,
                        old_dir=self.root_dir,
                        new_dir=root_dir)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()
        self.root_dir = root_dir
        self.update_index('root_dir', self.root_dir)
        return self._cache(callback=callback)

    @check_acls(['edit:force_group'])
    @object_lock()
    @audit_log()
    @object_changelog("force group {group_name}")
    def force_group(
        self,
        group_name: str=None,
        group_uuid: str=None,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if not group_name and not group_uuid:
            self.del_index('force_group_uuid', self.force_group_uuid)
            self.force_group_uuid = None
            return self._cache(callback=callback)
        if group_name:
            result = backend.search(object_type="group",
                                    attribute="name",
                                    value=group_name,
                                    return_type="instance")
            if not result:
                msg = _("Unknown group: {group_name}")
                msg = msg.format(group_name=group_name)
                return callback.error(msg)
            group = result[0]
        else:
            group = backend.get_object(object_type="group", uuid=group_uuid)
            if not group:
                msg = _("Unknown group: {group_uuid}")
                msg = msg.format(group_uuid=group_uuid)
                return callback.error(msg)
        if self.force_group_uuid == group.uuid:
            msg = _("Force group already set to: {group}")
            msg = msg.format(group=group)
            return callback.error(msg)
        self.force_group_uuid = group.uuid
        self.update_index('force_group_uuid', self.force_group_uuid)
        return self._cache(callback=callback)

    @check_acls(['edit:force_create_mode'])
    @object_lock()
    @audit_log()
    @object_changelog("force create mode {create_mode}")
    def force_create_mode(
        self,
        create_mode,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if self.create_mode == create_mode:
            msg = _("Create mode already set to: {create_mode}")
            msg = msg.format(create_mode=self.create_mode)
            return callback.error(msg)
        if not create_mode.startswith("0o"):
            msg = _("Invalid mode. Use python format, e.g. 0o700")
            return callback.error(msg)
        self.create_mode = create_mode
        self.update_index('create_mode', create_mode)
        return self._cache(callback=callback)

    @check_acls(['edit:force_directory_mode'])
    @object_lock()
    @audit_log()
    @object_changelog("force directory mode {create_mode}")
    def force_directory_mode(
        self,
        create_mode,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if self.directory_mode == create_mode:
            msg = _("Create mode already set to: {directory_mode}")
            msg = msg.format(directory_mode=self.directory_mode)
            return callback.error(msg)
        if not create_mode.startswith("0o"):
            msg = _("Invalid mode. Use python format, e.g. 0o700")
            return callback.error(msg)
        self.directory_mode = create_mode
        self.update_index('directory_mode', create_mode)
        return self._cache(callback=callback)

    @check_acls(['edit:home_share_permissions'])
    @object_lock()
    @audit_log()
    @object_changelog("home share permissions {permissions}")
    def set_home_share_permissions(
        self,
        permissions,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Set the mode the home share subdirs are created with.

        The default 0o700 keeps the users out of each others home dirs.
        Loosen it to let e.g. a forced group reach them through the file
        system (a root mount token reaches them through the share, see
        add_root_mount_token()).
        """
        if not self.home_share:
            msg = _("Share is not a home share.")
            return callback.error(msg)
        if self.home_share_permissions == permissions:
            msg = _("Home share permissions already set to: {permissions}")
            msg = msg.format(permissions=self.home_share_permissions)
            return callback.error(msg)
        if not permissions.startswith("0o"):
            msg = _("Invalid mode. Use python format, e.g. 0o700")
            return callback.error(msg)
        try:
            mode = int(permissions, 0)
        except ValueError:
            msg = _("Invalid mode. Use python format, e.g. 0o700")
            return callback.error(msg)
        if mode < 0 or mode > 0o7777:
            msg = _("Mode out of range: {permissions}")
            msg = msg.format(permissions=permissions)
            return callback.error(msg)
        self.home_share_permissions = permissions
        return self._cache(callback=callback)

    @check_acls(['enable:read_only'])
    @object_lock()
    @audit_log()
    @object_changelog("enable read-only")
    def enable_ro(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable ACL inheritance for the object """
        if not self.verify_acl("enable:read_oid_schema"):
            msg = _("Permission denied: {self}")
            msg = msg.format(self=self)
            return callback.error(msg, exception=PermissionDenied)

        if self.read_only:
            return callback.error(_("Share readonly already enabled."))

        msg = _("Make share readonly?: ")
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_ro",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        self.read_only = True

        self.update_index('read_only', self.read_only)

        return self._cache(callback=callback)

    @check_acls(['enable:read_only'])
    @object_lock()
    @audit_log()
    @object_changelog("disable read-only")
    def disable_ro(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable ACL inheritance for the object """
        if not self.verify_acl("disable:read_only"):
            msg = _("Permission denied: {self}")
            msg = msg.format(self=self)
            return callback.error(msg, exception=PermissionDenied)

        if not self.read_only:
            return callback.error(_("Share readonly already disabled."))

        msg = _("Make share read-write?: ")
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_ro",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        self.read_only = False

        self.update_index('read_only', self.read_only)

        return self._cache(callback=callback)

    def get_share_token_users(self):
        """ All users that have a token assigned to the share.

        Includes no mount tokens, just like get_share_tokens(), so a
        users sign public key is handled like their share key.
        """
        share_tokens = self.get_share_tokens()
        if not share_tokens:
            return []
        user_uuids = backend.search(object_type="token",
                                    attribute="uuid",
                                    values=share_tokens,
                                    return_attributes=['owner_uuid'])
        if not user_uuids:
            return []
        user_uuids = sorted(list(set(user_uuids)))
        return backend.search(object_type="user",
                            attribute="uuid",
                            values=user_uuids,
                            return_type="instance")

    def get_sign_public_key(self, user_uuid: str):
        """ Get users sign public key stored in this share.

        The key has to come from the share and not from the user
        object: the users site may be a different one and we do not
        want it to be able to swap the key that guards our data.
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
        """ Store users sign public key in the share. """
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
        token_path: str,
        callback: JobCallback=default_callback,
        ):
        """ Remove users sign public key if their last token was removed.

        Mirrors the share key handling: the key stays as long as any
        token of the user is still assigned to the share.

        No set_changelog() here: on an encrypted share the share key
        branch has already set the detail of the running entry and the
        detail is a single (overwritable) text.
        """
        username = token_path.split("/")[0]
        user = backend.get_object(object_type="user",
                                name=username,
                                realm=config.realm)
        if not user:
            return True
        if user.uuid not in self.sign_public_keys:
            return True
        share_tokens = self.get_share_tokens()
        for token_uuid in user.get_tokens():
            if token_uuid not in share_tokens:
                continue
            msg = _("Not removing sign public key because of other assigned token.")
            callback.send(msg)
            return True
        self.sign_public_keys.pop(user.uuid)
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
        """ Require clients to sign the SOTP they authenticate with. """
        if self.sotp_signing:
            return callback.error(_("SOTP signing already enabled."))

        # A role would bring in tokens without us noticing, so their
        # users sign public keys would be missing.
        if self.roles:
            msg = _("SOTP signing does not support roles. Please remove all roles from the share first.")
            return callback.error(msg)

        # Get sign public keys of all users with a token assigned.
        share_users = self.get_share_token_users()
        missing_keys = []
        for user in share_users:
            if user.sign_public_key:
                continue
            missing_keys.append(user.name)
        if missing_keys:
            msg = _("Users without sign public key: {user_names}")
            msg = msg.format(user_names=",".join(sorted(missing_keys)))
            return callback.error(msg)

        msg = _("Enable SOTP signing for share '{share_name}'? Clients without a sign key cannot access it anymore.: ")
        msg = msg.format(share_name=self.name)
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

        for user in share_users:
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

        msg = _("Disable SOTP signing for share '{share_name}'?: ")
        msg = msg.format(share_name=self.name)
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

        self.update_index('sotp_signing', self.sotp_signing)

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
        the share, so their access breaks until someone with write
        access to the share takes over the new key. That is on purpose:
        updating the copy automatically (e.g. from a hook on the user)
        would hand the users site exactly the control the copy is meant
        to take away from it.
        """
        if not self.sotp_signing:
            msg = _("SOTP signing not enabled.")
            return callback.error(msg)

        all_share_users = self.get_share_token_users()
        share_users = all_share_users
        if username is not None:
            share_users = []
            for user in all_share_users:
                if user.name != username:
                    continue
                share_users.append(user)
            if not share_users:
                msg = _("User does not have a token assigned to this share: {user_name}")
                msg = msg.format(user_name=username)
                return callback.error(msg)

        # Users whose key differs from the one we have.
        update_users = []
        missing_keys = []
        for user in share_users:
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

        # Keys without a token on the share. Adding and removing tokens
        # keeps them in sync, so this is only for leftovers (e.g. from a
        # token that was deleted instead of removed).
        orphan_uuids = []
        if username is None:
            share_user_uuids = []
            for user in all_share_users:
                share_user_uuids.append(user.uuid)
            for user_uuid in self.sign_public_keys:
                if user_uuid in share_user_uuids:
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
            msg = _("Update sign public keys of share '{share_name}'? Users: {user_names}: ")
            msg = msg.format(share_name=self.name, user_names=",".join(sorted(update_names)))
        else:
            msg = _("Update sign public keys of share '{share_name}'?: ")
            msg = msg.format(share_name=self.name)
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
    def is_master_password_token(
        self,
        token_uuid: str,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add token that is allowed to mount share with master password. """
        if not self.encrypted:
            msg = _("Share not encrypted.")
            return callback.error(msg)
        if token_uuid in self.master_password_tokens:
            return True
        return False

    @check_acls(['add:master_password_token'])
    @object_lock()
    @audit_log()
    @object_changelog("add master password token {token_path}")
    def add_master_password_token(
        self,
        token_path: str,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add token that is allowed to mount share with master password. """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        if not self.encrypted:
            msg = _("Share not encrypted.")
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid in self.master_password_tokens:
            msg = _("Token already assigned to share: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        self.master_password_tokens.append(token_uuid)

        return self._write(callback=callback)

    @check_acls(['remove:master_password_token'])
    @object_lock()
    @audit_log()
    @object_changelog("remove master password token {token_path}")
    def remove_master_password_token(
        self,
        token_path: str,
        force: bool=False,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove token that is allowed to mount share with master password. """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        if not self.encrypted:
            msg = _("Share not encrypted.")
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                site=config.site,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid not in self.master_password_tokens:
            msg = _("Token not assigned to share: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        if len(self.master_password_tokens) == 1:
            msg = _("'{token_path}' is the last master password token of share '{share_name}'. Without one the share cannot be mounted with the master password anymore.: ")
        else:
            msg = _("Remove master password token '{token_path}' from share '{share_name}'?: ")
        msg = msg.format(token_path=token_path, share_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        self.master_password_tokens.remove(token_uuid)

        return self._write(callback=callback)

    def is_root_mount_token(
        self,
        token_uuid: str,
        **kwargs,
        ):
        """ Check if the token mounts the share root instead of a home dir. """
        if token_uuid in self.root_mount_tokens:
            return True
        return False

    def _notify_share_token(self, event_type, token_path,
        persist_mount: bool=None,
        share_notifications: bool=None,
        callback: JobCallback=default_callback):
        """ Send a share_mount/share_unmount event for a single token.

        Same payload add_token()/remove_token() build: the client needs
        the nodes to connect to and the tokens the event is meant for.
        """
        username = token_path.split("/")[0]
        if username == ADMIN_USER:
            return
        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            share_nodes = self.get_nodes(include_pools=True,
                                        return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)

            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing
            shares[share_id]['tokens'] = [token_path]
            shares[share_id]['persist'] = persist_mount

            # Send notification to idled.
            notify(username=username, event_type=event_type, data=shares)

        if share_notifications is None:
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

    @check_acls(['add:root_mount_token'])
    @object_lock()
    @audit_log()
    @object_changelog("add root mount token {token_path}")
    def add_root_mount_token(
        self,
        token_path: str,
        persist_mount: bool=None,
        share_notifications: bool=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add token that mounts the share root instead of a home dir.

        A home share hands out "<share_root>/<home dir>" to its users.
        A root mount token gets no home dir, so it mounts the share root
        and reaches the home dirs of all users.
        """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        if not self.home_share:
            msg = _("Share is not a home share. Its tokens already mount the share root.")
            return callback.error(msg)

        if self.encrypted:
            msg = _("Share is encrypted. Every home dir has its own encryption, so a root mount could not read them.")
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid in self.root_mount_tokens:
            msg = _("Token already assigned to share: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        self.root_mount_tokens.append(token_uuid)

        # Update index.
        self.add_index('root_mount_token', token_uuid)

        result = self._write(callback=callback)
        if not result:
            return result

        if not self.enabled:
            return result

        # The token gets a different share root from now on, so let it
        # mount again.
        self._notify_share_token("share_mount", token_path,
                                persist_mount=persist_mount,
                                share_notifications=share_notifications,
                                callback=callback)
        return result

    @check_acls(['remove:root_mount_token'])
    @object_lock()
    @audit_log()
    @object_changelog("remove root mount token {token_path}")
    def remove_root_mount_token(
        self,
        token_path: str,
        persist_mount: bool=None,
        share_notifications: bool=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove token that mounts the share root instead of a home dir. """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid not in self.root_mount_tokens:
            msg = _("Token not assigned to share: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        self.root_mount_tokens.remove(token_uuid)
        # Update index.
        self.del_index('root_mount_token', token_uuid)

        result = self._write(callback=callback)
        if not result:
            return result

        # The share root the token has mounted is not its own anymore.
        self._notify_share_token("share_unmount", token_path,
                                persist_mount=persist_mount,
                                share_notifications=share_notifications,
                                callback=callback)
        return result

    def filter_mount_tokens(self, token_paths):
        """ Drop the tokens that do not get the share mounted.

        A no mount token may mount the share, it just does not get it
        mounted by itself, so it gets no share_mount event (see
        add_no_mount_token()). It stays in the unmount events: it may
        have mounted the share by hand.
        """
        if not self.no_mount_tokens:
            return token_paths
        no_mount_paths = backend.search(object_type="token",
                                        attribute="uuid",
                                        values=self.no_mount_tokens,
                                        return_type="rel_path")
        return [x for x in token_paths if x not in no_mount_paths]

    def is_no_mount_token(
        self,
        token_uuid: str,
        **kwargs,
        ):
        """ Check if the token does not get the share mounted by itself. """
        if token_uuid in self.no_mount_tokens:
            return True
        return False

    def get_share_tokens(self):
        """ All tokens assigned to the share, mounting or not.

        A users share key has to stay as long as any of their tokens is
        still on the share, no matter whether it may mount it.
        """
        return list(self.tokens) + list(self.no_mount_tokens)

    @check_acls(['add:no_mount_token'])
    @object_lock()
    @audit_log(ignore_args=['share_key'])
    @object_changelog("add no mount token {token_path}")
    def add_no_mount_token(
        self,
        token_path: str,
        share_key: str=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add token that does not get the share mounted automatically.

        Everything add_token() does, including handing the user a share
        key, except that the share is not mounted for this token at
        login and it gets no share_mount event. Mounting it by hand
        with otpme-mount keeps working (see filter_mount_tokens()).
        """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid in self.no_mount_tokens:
            msg = _("Token already assigned to share: {token_path}")
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

        if not config.auth_user or not config.auth_user.is_admin():
            if self.force_group_uuid is not None:
                group = backend.get_object(uuid=self.force_group_uuid)
                group_users = group.get_token_users(include_roles=True,
                                                skip_disabled=True,
                                                return_type="name")
                if user.name not in group_users:
                    msg = _("Force group enabled and user not in group: {group_name}")
                    msg = msg.format(group_name=group.name)
                    return callback.error(msg)

        if self.encrypted and not self.home_share:
            if self.restore_share:
                result = backend.search(object_type="share",
                                        attribute="uuid",
                                        value=self.restore_share,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
                if not result:
                    msg = _("Unknown share: {restore_share}")
                    msg = msg.format(restore_share=self.restore_share)
                    return callback.error(msg)
                share = result[0]
                share_key = share.get_share_key(username=token_user)
                if not share_key:
                    msg = _("No share key available for user: {user}")
                    msg = msg.format(user=token_user)
                    return callback.error(msg)
            else:
                existing_key = self.get_share_key(username=user.name)
                if not existing_key and not share_key:
                    auth_user = config.auth_user
                    auth_user_share_key = self.get_share_key(username=auth_user.name)
                    if not auth_user_share_key:
                        msg = _("You dont have a share key for share: {share_name}")
                        msg = msg.format(share_name=self.name)
                        return callback.error(msg)
                    msg = _("Sending request to re-encrypt share key for user: {user_name}")
                    msg = msg.format(user_name=user.name)
                    callback.send(msg)
                    key_mode = auth_user.key_mode
                    share_key = callback.reencrypt_share_key(share_user=user.name,
                                                            share_key=auth_user_share_key,
                                                            key_mode=key_mode)
                    if not share_key:
                        msg = _("Failed to receive share key from client.")
                        return callback.error(msg)
            if share_key:
                self.add_share_key(username=user.name,
                                    share_key=share_key,
                                    callback=callback,
                                    verify_acls=False)

        if self.sotp_signing:
            if not self.add_sign_public_key(user, callback=callback):
                return callback.error()

        self.no_mount_tokens.append(token_uuid)

        # Update index.
        self.add_index('no_mount_token', token_uuid)

        return self._write(callback=callback)

    @check_acls(['remove:no_mount_token'])
    @object_lock()
    @audit_log()
    @object_changelog("remove no mount token {token_path}")
    def remove_no_mount_token(
        self,
        token_path: str,
        keep_share_key: bool=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove token that does not get the share mounted automatically.

        Drops the users share key with it, like remove_token() does.
        """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid not in self.no_mount_tokens:
            msg = _("Token not assigned to share: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        self.no_mount_tokens.remove(token_uuid)
        # Update index.
        self.del_index('no_mount_token', token_uuid)

        if self.encrypted:
            token_user = token_path.split("/")[0]
            token_user = backend.get_object(object_type="user",
                                            name=token_user,
                                            realm=config.realm)
            share_tokens = self.get_share_tokens()
            user_tokens = token_user.get_tokens()
            other_token_assigned = False
            for x_uuid in user_tokens:
                if x_uuid not in share_tokens:
                    continue
                other_token_assigned = backend.get_object(uuid=x_uuid)
                break
            if other_token_assigned:
                msg = _("Not removing share key because of other assigned token: {token}")
                msg = msg.format(token=other_token_assigned)
                callback.send(msg)
                self.set_changelog("kept share key (other token still assigned)")
            else:
                if keep_share_key is None:
                    if self.home_share:
                        keep_share_key = True
                        msg = _("Not removing share key of home share.")
                        callback.send(msg)
                    else:
                        keep_share_key = False
                if not keep_share_key:
                    # Removing the token is the confirmed action, the
                    # share key goes with it.
                    self.del_share_key(username=token_user.name,
                                        force=True,
                                        callback=callback,
                                        verify_acls=False)
                    self.set_changelog("removed share key")
                elif self.home_share:
                    self.set_changelog("kept share key (home share)")
                else:
                    self.set_changelog("kept share key")

        if self.sotp_signing:
            self.del_sign_public_key(token_path, callback=callback)

        return self._write(callback=callback)

    @object_lock()
    @audit_log(ignore_args=['share_key'])
    @object_changelog("add token {token_path}")
    def add_token(
        self,
        token_path: str,
        share_key: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add token to share. """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid in self.tokens:
            msg = _("Token already assigned to share: {token_path}")
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

        if not config.auth_user or not config.auth_user.is_admin():
            if self.force_group_uuid is not None:
                group = backend.get_object(uuid=self.force_group_uuid)
                group_users = group.get_token_users(include_roles=True,
                                                skip_disabled=True,
                                                return_type="name")
                if user.name not in group_users:
                    msg = _("Force group enabled and user not in group: {group_name}")
                    msg = msg.format(group_name=group.name)
                    return callback.error(msg)

        if self.encrypted and not self.home_share:
            if self.restore_share:
                result = backend.search(object_type="share",
                                        attribute="uuid",
                                        value=self.restore_share,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
                if not result:
                    msg = _("Unknown share: {restore_share}")
                    msg = msg.format(restore_share=self.restore_share)
                    return callback.error(msg)
                share = result[0]
                share_key = share.get_share_key(username=token_user)
                if not share_key:
                    msg = _("No share key available for user: {user}")
                    msg = msg.format(user=token_user)
                    return callback.error(msg)
            else:
                existing_key = self.get_share_key(username=user.name)
                if not existing_key and not share_key:
                    auth_user = config.auth_user
                    auth_user_share_key = self.get_share_key(username=auth_user.name)
                    if not auth_user_share_key:
                        msg = _("You dont have a share key for share: {share_name}")
                        msg = msg.format(share_name=self.name)
                        return callback.error(msg)
                    msg = _("Sending request to re-encrypt share key for user: {user_name}")
                    msg = msg.format(user_name=user.name)
                    callback.send(msg)
                    key_mode = auth_user.key_mode
                    share_key = callback.reencrypt_share_key(share_user=user.name,
                                                            share_key=auth_user_share_key,
                                                            key_mode=key_mode)
                    if not share_key:
                        msg = _("Failed to receive share key from client.")
                        return callback.error(msg)
            if share_key:
                self.add_share_key(username=user.name,
                                    share_key=share_key,
                                    callback=callback,
                                    verify_acls=False)

        if self.sotp_signing:
            if not self.add_sign_public_key(user, callback=callback):
                return callback.error()

        # Add token by parent class.
        result = super().add_token(token_path=token_path,
                                callback=callback, **kwargs)

        if not result:
            return result

        if not self.enabled:
            return result

        username = token_path.split("/")[0]
        if username == ADMIN_USER:
            return result

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            share_nodes = self.get_nodes(include_pools=True,
                                          return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)

            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing
            shares[share_id]['tokens'] = [token_path]
            shares[share_id]['persist'] = persist_mount

            # Send notification to idled.
            notify(username=username, event_type="share_mount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['remove:token'])
    @object_lock()
    @audit_log()
    @object_changelog("remove token {token_path}")
    def remove_token(
        self,
        token_path: str,
        keep_share_key: bool=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove token from share. """
        if not "/" in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token_path,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid not in self.tokens:
            msg = _("Token not assigned to share: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)

        # Remove token by parent class.
        result = super().remove_token(token_path=token_path,
                                    callback=callback, **kwargs)

        if not result:
            return result

        if self.encrypted:
            token_user = token_path.split("/")[0]
            token_user = backend.get_object(object_type="user",
                                            name=token_user,
                                            realm=config.realm)
            share_tokens = self.get_share_tokens()
            user_tokens = token_user.get_tokens()
            other_token_assigned = False
            for x_uuid in user_tokens:
                if x_uuid not in share_tokens:
                    continue
                other_token_assigned = backend.get_object(uuid=x_uuid)
                break
            if other_token_assigned:
                msg = _("Not removing share key because of other assigned token: {token}")
                msg = msg.format(token=other_token_assigned)
                callback.send(msg)
                self.set_changelog("kept share key (other token still assigned)")
            else:
                if keep_share_key is None:
                    if self.home_share:
                        keep_share_key = True
                        msg = _("Not removing share key of home share.")
                        callback.send(msg)
                    else:
                        keep_share_key = False
                if not keep_share_key:
                    # Removing the token is the confirmed action, the
                    # share key goes with it.
                    self.del_share_key(username=token_user.name,
                                        force=True,
                                        callback=callback,
                                        verify_acls=False)
                    self.set_changelog("removed share key")
                elif self.home_share:
                    self.set_changelog("kept share key (home share)")
                else:
                    self.set_changelog("kept share key")

        # The parent class cached the object for writing, so the key we
        # remove here goes to the backend with it.
        if self.sotp_signing:
            self.del_sign_public_key(token_path, callback=callback)

        username = token_path.split("/")[0]
        if username == ADMIN_USER:
            return result

        # No check for a disabled share here: this sends share_unmount,
        # and taking a mount away stays right even for a share that is
        # switched off.
        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            share_tokens = self.get_tokens(skip_disabled=False,
                                          include_roles=True,
                                          return_type="rel_path")
            # If token is still valid for the share skip notification.
            if token_path in share_tokens:
                return
            share_nodes = self.get_nodes(include_pools=True,
                                          return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)

            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing
            shares[share_id]['tokens'] = [token_path]
            shares[share_id]['persist'] = persist_mount

            # Send notification to idled.
            notify(username=username, event_type="share_unmount", data=shares)

        if share_notifications is None:
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['add:role'])
    @object_lock()
    @audit_log()
    @object_changelog("add role {role_name}")
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
        """ Check if share is encrypted. """
        if self.encrypted:
            msg = _("Encrypted shares do not support roles.")
            return callback.error(msg)

        # A role would bring in tokens without us noticing, so their
        # users sign public keys would be missing.
        if self.sotp_signing:
            msg = _("Shares with SOTP signing do not support roles.")
            return callback.error(msg)

        # Add role by parent class.
        result =  super().add_role(*args, role_name=role_name,
                                    role_uuid=role_uuid,
                                    callback=callback, **kwargs)

        if not result:
            return result

        if not self.enabled:
            return result

        if role_name:
            role_uuid = self.get_role_uuid(role_name, callback=callback)
        elif not role_uuid:
            msg = "Need <role_name> or <role_uuid>."
            raise OTPmeException(msg)

        # Get role.
        role = backend.get_object(uuid=role_uuid)

        role_tokens = role.get_tokens(return_type="rel_path",
                                        include_roles=True)
        role_tokens = self.filter_mount_tokens(role_tokens)
        if not role_tokens:
            return result

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            # Get share nodes.
            share_nodes = self.get_nodes(include_pools=True,
                                        return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)
            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing

            # Collect notifications.
            user_shares = {}
            already_processed = []
            for token_path in role_tokens:
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
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['remove:role'])
    @object_lock()
    @audit_log()
    @object_changelog("remove role {role_name}")
    def remove_role(
        self,
        role_name: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Check if share is encrypted. """
        if self.encrypted:
            msg = _("Encrypted shares do not support roles.")
            return callback.error(msg)

        if self.sotp_signing:
            msg = _("Shares with SOTP signing do not support roles.")
            return callback.error(msg)

        # Add role by parent class.
        result =  super().remove_role(*args, role_name=role_name,
                                    callback=callback, **kwargs)

        if not result:
            return result

        # Get role.
        role_uuid = self.get_role_uuid(role_name, callback=callback)
        role = backend.get_object(uuid=role_uuid)

        role_tokens = role.get_tokens(return_type="rel_path",
                                        include_roles=True)
        if not role_tokens:
            return result

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            # Get share tokens.
            share_tokens = self.get_tokens(return_type="rel_path",
                                        include_roles=True)
            # Get share nodes.
            share_nodes = self.get_nodes(include_pools=True,
                                        return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)
            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing

            # Collect notifications.
            user_shares = {}
            already_processed = []
            for token_path in role_tokens:
                if token_path in already_processed:
                    continue
                username = token_path.split("/")[0]
                if username == ADMIN_USER:
                    continue
                if token_path in share_tokens:
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
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['add:share_key'])
    @object_lock()
    @audit_log(ignore_args=['share_key'])
    @object_changelog("add share key for user {username}")
    def add_share_key(
        self,
        username: str,
        share_key: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        result = backend.search(object_type="user",
                                attribute="name",
                                value=username,
                                return_type="uuid")
        if not result:
            msg = _("Unknown user: {username}")
            msg = msg.format(username=username)
            return callback.error(msg)
        user_uuid = result[0]

        if user_uuid in self.share_keys:
            msg = _("Share key already exists: {username}")
            msg = msg.format(username=username)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_share_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {error}")
                msg = msg.format(error=e)
                return callback.error(msg)

        self.share_keys[user_uuid] = share_key

        return self._write(callback=callback)

    @check_acls(['view:share_key'])
    @object_lock()
    def get_share_key(
        self,
        username: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        result = backend.search(object_type="user",
                                attribute="name",
                                value=username,
                                return_type="uuid")
        if not result:
            msg = _("Unknown user: {username}")
            msg = msg.format(username=username)
            return callback.error(msg)
        user_uuid = result[0]

        if user_uuid not in self.share_keys:
            msg = _("Share key does not exist: {username}")
            msg = msg.format(username=username)
            return callback.error(msg)

        if run_policies:
            config.ignore_policy_tags.append("interactive")
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("get_share_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                config.raise_exception()
                msg = _("Error running policies: {error}")
                msg = msg.format(error=e)
                return callback.error(msg)
            config.ignore_policy_tags.remove("interactive")

        share_key = self.share_keys[user_uuid]

        return callback.ok(share_key)

    @check_acls(['delete:share_key'])
    @object_lock()
    @audit_log()
    @object_changelog("remove share key of user {username}")
    def del_share_key(
        self,
        username: str,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        result = backend.search(object_type="user",
                                attribute="name",
                                value=username,
                                return_type="uuid")
        if not result:
            msg = _("Unknown user: {username}")
            msg = msg.format(username=username)
            return callback.error(msg)
        user_uuid = result[0]

        if user_uuid not in self.share_keys:
            msg = _("Share key does not exist: {username}")
            msg = msg.format(username=username)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_share_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {error}")
                msg = msg.format(error=e)
                return callback.error(msg)

        msg = _("Remove share key of user '{username}' from share '{share_name}'? The user cannot decrypt the shares data anymore.: ")
        msg = msg.format(username=username, share_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        self.share_keys.pop(user_uuid)

        return self._write(callback=callback)

    @check_acls(['add:ppol'])
    @object_lock()
    @audit_log()
    @object_changelog("add pool {pool_name}")
    def add_pool(
        self,
        pool_name: str,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a pool to objects pool list. """
        if verify_acls:
            if not self.verify_acl("add:pool"):
                msg = _("Permission denied: {self}")
                msg = msg.format(self=self)
                return callback.error(msg, exception=PermissionDenied)

        pool = backend.get_object(object_type="pool",
                                    realm=config.realm,
                                    site=config.site,
                                    name=pool_name)
        if not pool:
            msg = _("Unknown pool: {pool_name}")
            msg = msg.format(pool_name=pool_name)
            return callback.error(msg)

        if pool.uuid in self.pools:
            exception = AlreadyExists
            msg = _("Node is already assigned to {object_type} '{object_name}'.")
            msg = msg.format(object_type=self.type, object_name=self.name)
            return callback.error(msg, exception=exception)

        if run_policies:
            try:
                self.run_policies("modify",
                                force=force,
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_pool",
                                force=force,
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        msg = _("Adding pool {pool_name} to {object_type} {object_name}.")
        msg = msg.format(pool_name=pool.name, object_type=self.type, object_name=self.name)
        callback.send(msg)
        self.pools.append(pool.uuid)
        # Update index.
        self.add_index('pool', pool.uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:ppol'])
    @object_lock()
    @audit_log()
    @object_changelog("remove pool {pool_name}")
    def remove_pool(
        self,
        pool_name: str,
        force: bool=False,
        verify_acls: bool=True,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Removes a pool from objects pools list. """
        if verify_acls:
            if not self.verify_acl("remove:pool"):
                msg = _("Permission denied: {self}")
                msg = msg.format(self=self)
                return callback.error(msg, exception=PermissionDenied)

        pool = backend.get_object(object_type="pool",
                                    realm=config.realm,
                                    site=config.site,
                                    name=pool_name)
        if not pool:
            msg = _("Unknown pool: {pool_name}")
            msg = msg.format(pool_name=pool_name)
            return callback.error(msg)

        if pool.uuid not in self.pools:
            msg = _("Node is not assigned to {object_type} '{object_name}'.")
            msg = msg.format(object_type=self.type, object_name=self.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_pool",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove pool from object.
        self.pools.remove(pool.uuid)
        # Update index.
        self.del_index('pool', pool.uuid)
        return self._cache(callback=callback)

    @check_acls(['add:group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("add group {group_name}")
    def add_group(
        self,
        group_name: str=None,
        group_uuid: str=None,
        persist_mount: bool=None,
        share_notifications: bool=None,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a group (hosts) to this share.  """
        if not group_uuid:
            grp = backend.get_object(object_type="group",
                                    realm=config.realm,
                                    site=self.site,
                                    name=group_name)
            if not grp:
                msg = _("Group does not exist: {group_name}")
                msg = msg.format(group_name=group_name)
                return callback.error(msg)
            group_uuid = grp.uuid

        if group_uuid in self.groups:
            msg = _("Group already added to share.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        msg = _("Adding group to share: {name}")
        msg = msg.format(name=self.name)
        callback.send(msg)

        self.groups.append(group_uuid)
        self.add_index("group", group_uuid)

        result = self._cache(callback=callback)

        if not result:
            return result

        if not self.enabled:
            return result

        if not self.limit_by_hosts:
            return result

        # Get group.
        group = backend.get_object(uuid=group_uuid)

        # Get group hosts.
        group_hosts = group.get_hosts(skip_disabled=True, return_type="name")

        if not group_hosts:
            return result

        share_tokens = self.get_tokens(skip_disabled=False,
                                        include_roles=True,
                                        return_type="rel_path")
        # Get share nodes.
        share_nodes = self.get_nodes(include_pools=True,
                                    return_type="instance")
        if not share_nodes:
            share_nodes = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=self.realm,
                                        site=self.site,
                                        return_type="instance")
        node_fqdns = []
        for node in share_nodes:
            node_fqdns.append(node.fqdn)

        shares = {}
        share_id = self.share_id
        shares[share_id] = {}
        shares[share_id]['name'] = self.name
        shares[share_id]['site'] = self.site
        shares[share_id]['nodes'] = node_fqdns
        shares[share_id]['hosts'] = group_hosts
        shares[share_id]['encrypted'] = self.encrypted
        shares[share_id]['sotp_signing'] = self.sotp_signing

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        # Collect notifications.
        user_shares = {}
        already_processed = []
        for token_path in share_tokens:
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

        notifys = []
        for username in user_shares:
            shares = user_shares[username]
            notifys.append((username, "share_add_host", shares))

        def post_method():
            for x in notifys:
                notify(username=x[0], event_type=x[1], data=x[2])

        if share_notifications is None:
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    @check_acls(['remove:group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("remove group {group_name}")
    def remove_group(
        self,
        group_name: str,
        persist_mount: bool=None,
        share_notifications: bool=None,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove a group (hosts) from this share. """
        group = backend.get_object(object_type="group",
                                realm=config.realm,
                                site=self.site,
                                name=group_name)
        if not group:
            msg = _("Group does not exist: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        if group.uuid not in self.groups:
            msg = _("Group not assigned share.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.groups.remove(group.uuid)
        self.del_index("group", group.uuid)

        result = self._cache(callback=callback)

        if not result:
            return result

        if not self.limit_by_hosts:
            return result

        # Get group hosts.
        group_hosts = group.get_hosts(skip_disabled=True, return_type="uuid")

        if not group_hosts:
            return result

        share_tokens = self.get_tokens(skip_disabled=False,
                                        include_roles=True,
                                        return_type="rel_path")
        # Get share nodes.
        share_nodes = self.get_nodes(include_pools=True,
                                    return_type="instance")
        if not share_nodes:
            share_nodes = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=self.realm,
                                        site=self.site,
                                        return_type="instance")
        node_fqdns = []
        for node in share_nodes:
            node_fqdns.append(node.fqdn)

        shares = {}
        share_id = self.share_id
        shares[share_id] = {}
        shares[share_id]['name'] = self.name
        shares[share_id]['site'] = self.site
        shares[share_id]['nodes'] = node_fqdns
        shares[share_id]['hosts'] = group_hosts
        shares[share_id]['encrypted'] = self.encrypted
        shares[share_id]['sotp_signing'] = self.sotp_signing

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        # Collect notifications.
        user_shares = {}
        already_processed = []
        for token_path in share_tokens:
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

        notifys = []
        for username in user_shares:
            shares = user_shares[username]
            notifys.append((username, "share_remove_host", shares))

        def post_method():
            for x in notifys:
                notify(username=x[0], event_type=x[1], data=x[2])

        if share_notifications is None:
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

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
                ('groups', 'group', None),
                ('hosts', 'host', None),
                ('nodes', 'node', None),
                ('pools', 'pool', None),
                ('master_password_tokens', 'token', None),
                ('root_mount_tokens', 'token', None),
                ('no_mount_tokens', 'token', None),
                ('share_keys', 'user', None, 'dict_keys'),
                ]
        return super().remove_orphans(force=force,
                                    run_policies=run_policies,
                                    verbose_level=verbose_level,
                                    recursive=recursive,
                                    extra_ref_lists=extra_ref_lists,
                                    callback=callback,
                                    _caller=_caller,
                                    **kwargs)


    @cli.check_rapi_opts()
    @check_acls(acls=['view:groups'])
    def list_groups(self, **kwargs):
        """ Returns the shares group. """
        return self.get_groups(**kwargs)

    def get_groups(
        self,
        return_type: str="name",
        _caller: str="API",
        skip_disabled: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Get share's groups. """
        result = []
        if not self.groups:
            return callback.ok(result)

        search_attr = {}
        if skip_disabled:
            search_attr['enabled'] = {}
            search_attr['enabled']['value'] = True
        return_attributes = ['site', return_type]
        search_result = backend.search(object_type="group",
                                    attribute="uuid",
                                    values=self.groups,
                                    attributes=search_attr,
                                    return_attributes=return_attributes)
        for uuid in search_result:
            try:
                x_result = search_result[uuid][return_type]
            except Exception:
                continue
            if return_type == "name":
                x_site = search_result[uuid]['site']
                if x_site != config.site:
                    x_result = f"{x_site}/{x_result}"
            result.append(x_result)

        result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

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
        """ Adds a host to this share. """
        # Try to add host via parent class.
        result = super().add_host(*args, host_name=host_name,
                                host_uuid=host_uuid,
                                callback=callback, **kwargs)
        if not result:
            return result

        if not self.limit_by_hosts:
            return result

        if host_uuid:
            host = backend.get_object(uuid=host_uuid)
        else:
            host = backend.get_object(object_type="host",
                                    realm=config.realm,
                                    site=self.site,
                                    name=host_name)

        self._notify_share_metadata_change("share_add_host", callback, host=host.name,
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
        # Try to add host via parent class.
        result = super().remove_host(*args, host_name=host_name,
                                    callback=callback, **kwargs)
        if not result:
            return result

        if not self.limit_by_hosts:
            return result

        host = backend.get_object(object_type="host",
                                realm=config.realm,
                                site=self.site,
                                name=host_name)

        self._notify_share_metadata_change("share_remove_host", callback, host=host.name,
                                            persist_mount=persist_mount,
                                            share_notifications=share_notifications)
        return result

    @cli.check_rapi_opts()
    @check_acls(acls=['view:hosts'])
    def list_hosts(
        self,
        **kwargs,
        ):
        """ Return list with hosts valid for this share. """
        return self.get_hosts(**kwargs)

    @cli.check_rapi_opts()
    @check_acls(acls=['view:nodes'])
    def list_nodes(
        self,
        **kwargs,
        ):
        """ Return list with nodes valid for this share. """
        return self.get_nodes(**kwargs)

    def get_nodes(
        self,
        return_type: str="name",
        skip_disabled: bool=True,
        include_pools: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Get nodes valid for this share. """
        # If no nodes or pools assigned to share return all nodes of shares site.
        if not self.nodes and not self.pools:
            result = backend.search(object_type="node",
                                    attribute="uuid",
                                    value="*",
                                    realm=self.realm,
                                    site=self.site,
                                    return_type=return_type)
            if _caller == "RAPI":
                result = ",".join(result)
            if _caller == "CLIENT":
                result = "\n".join(result)
            return callback.ok(result)

        result = super().get_nodes(return_type=return_type,
                                    skip_disabled=skip_disabled,
                                    include_pools=include_pools,
                                    callback=callback,
                                    _caller=_caller)

        return callback.ok(result)

    @cli.check_rapi_opts()
    @check_acls(acls=['view:pools'])
    def list_pools(
        self,
        **kwargs,
        ):
        """ Return list with all pools assigned to this share. """
        return self.get_pools(**kwargs)

    def get_pools(
        self,
        return_type: str="name",
        skip_disabled: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Get all pools assigned to this node. """
        exception = None
        if return_type not in [ 'name', 'instance', 'uuid', 'oid', 'read_oid', 'full_oid' ]:
            exception = _("Unknown return type: {return_type}")
            exception = exception.format(return_type=return_type)
        if _caller != "API" and (return_type == "instance" or return_type == "oid"):
            exception = _("Unknown return type: {return_type}")
            exception = exception.format(return_type=return_type)
        if exception:
            return callback.error(exception)
        result = []
        # Pools assigned to this object.
        if not self.pools:
            if _caller == "RAPI":
                result = ",".join(result)
            if _caller == "CLIENT":
                result = "\n".join(result)
            return result
        # Search attributes.
        search_attr = {}
        if skip_disabled:
            search_attr['enabled'] = {}
            search_attr['enabled']['value'] = True
        _return_type = return_type
        result = backend.search(attribute="uuid",
                                values=self.pools,
                                attributes=search_attr,
                                object_type="pool",
                                return_type=_return_type)
        # Remove duplicates.
        if isinstance(result, list):
            result = sorted(list(set(result)))

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    @check_acls(['limit_hosts'])
    @object_lock()
    @audit_log()
    @object_changelog("limit hosts")
    def limit_hosts(
        self,
        persist_mount: bool=None,
        share_notifications: bool=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Limit share access to assigned hosts.

        Toggling this on doesn't change WHO has access (role / token /
        group assignments stay) -- it adds a per-host restriction.
        Notify every user reachable through the share with a
        share_mount carrying the new limit_hosts=True + hosts allow-
        list so each agent re-evaluates locally and unmounts on
        non-listed hosts. """
        if self.limit_by_hosts:
            return callback.error(_("Share access already limited."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("limit_hosts",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        self.limit_by_hosts = True
        self.update_index('limit_by_hosts', self.limit_by_hosts)
        result = self._cache(callback=callback)
        self._notify_share_metadata_change("share_remove_host", callback,
                                            persist_mount=persist_mount,
                                            share_notifications=share_notifications)
        return result

    @check_acls(['unlimit_hosts'])
    @object_lock()
    @audit_log()
    @object_changelog("unlimit hosts")
    def unlimit_hosts(
        self,
        persist_mount: bool=None,
        share_notifications: bool=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Unlimit share access.

        Symmetric to limit_hosts: WHO has access is unchanged, the
        per-host restriction is lifted. Agents on previously blocked
        hosts can now mount; notify everyone reachable so they
        re-evaluate. """
        if not self.limit_by_hosts:
            return callback.error(_("Share access already unlimited."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("unlimit_hosts",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        self.limit_by_hosts = False
        self.update_index('limit_by_hosts', self.limit_by_hosts)
        result = self._cache(callback=callback)
        self._notify_share_metadata_change("share_mount", callback,
                                            persist_mount=persist_mount,
                                            share_notifications=share_notifications)
        return result

    # The events that can grant access. A disabled share must not send
    # them: nobody is to mount it. The revoking ones stay allowed even
    # then, they can only ever take a mount away.
    GRANTING_EVENTS = ("share_mount", "share_add_host")

    def _notify_share_metadata_change(self, event_type, callback,
                                      host: str=None,
                                      persist_mount: bool=None,
                                      share_notifications: bool=None):
        """ Send a share_mount / share_unmount event to every user
        reachable through the share so each agent re-evaluates against
        the share's current metadata. Caller picks the event type
        based on the direction of the change: ``share_unmount`` when
        the operation can revoke access (limit_hosts) and
        ``share_mount`` when it can grant access (unlimit_hosts). """
        if not self.enabled:
            if event_type in self.GRANTING_EVENTS:
                return
        share_tokens = self.get_tokens(skip_disabled=True,
                                       include_roles=True,
                                       return_type="rel_path")
        if self.root_mount_tokens:
            result = backend.search(object_type="token",
                                    attribute="uuid",
                                    values=self.root_mount_tokens,
                                    return_type="rel_path")
            if result:
                share_tokens += result
        if event_type == "share_mount":
            share_tokens = self.filter_mount_tokens(share_tokens)
        if not share_tokens:
            return
        share_nodes = self.get_nodes(include_pools=True,
                                     return_type="instance")
        if not share_nodes:
            share_nodes = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=self.realm,
                                        site=self.site,
                                        return_type="instance")
        if not share_nodes:
            return
        node_fqdns = [node.fqdn for node in share_nodes]

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            nonlocal host
            share_hosts = self.get_hosts(include_groups=True,
                                        include_roles=True,
                                        return_type="name")
            if event_type == "share_remove_host":
                if host and host in share_hosts:
                    host = None

            share_id = self.share_id
            share_name = self.name
            share_site = self.site
            share_encrypted = self.encrypted
            share_sotp_signing = self.sotp_signing
            share_limit_by_hosts = self.limit_by_hosts

            user_shares = {}
            already_processed = []
            for token_path in share_tokens:
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
                x_shares[share_id] = {
                    'name': share_name,
                    'site': share_site,
                    'nodes': list(node_fqdns),
                    'limit_hosts': share_limit_by_hosts,
                    'hosts': list(share_hosts),
                    'encrypted': share_encrypted,
                    'sotp_signing': share_sotp_signing,
                    'tokens': tokens,
                    'persist': persist_mount,
                }
                if host:
                    x_shares[share_id]['host'] = host
                user_shares[username] = x_shares
                already_processed.append(token_path)
            for username in user_shares:
                shares = user_shares[username]
                notify(username=username, event_type=event_type, data=shares)

        if share_notifications is None:
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

    @assigned_host_cache.cache_method()
    def is_assigned_host(
        self,
        host_uuid: str,
        include_roles: bool=False,
        include_groups: bool=False,
        ):
        if host_uuid in self.hosts:
            return self.uuid
        if include_groups:
            for x_uuid in self.groups:
                group = backend.get_object(object_type="group", uuid=x_uuid)
                if not group:
                    continue
                if not group.enabled:
                    continue
                if host_uuid in group.hosts:
                    return True
        if include_roles:
            for x_uuid in self.roles:
                role = backend.get_object(object_type="role", uuid=x_uuid)
                if not role:
                    continue
                if not role.enabled:
                    continue
                if role.is_assigned_host(host_uuid):
                    return True
        return False

    def get_hosts(
        self,
        return_type: str="name",
        skip_disabled: bool=True,
        include_roles: bool=False,
        include_groups: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Return list with all hosts assigned to this share. """
        result = super().get_hosts(return_type=return_type,
                                    _caller="API",
                                    callback=callback)

        if include_groups:
            for x_uuid in self.groups:
                group = backend.get_object(object_type="group", uuid=x_uuid)
                if not group:
                    continue
                if skip_disabled:
                    if not group.enabled:
                        continue
                if not group.hosts:
                    continue
                result += backend.search(object_type="host",
                                        attribute="uuid",
                                        values=group.hosts,
                                        return_type=return_type)
        if include_roles:
            for x_uuid in self.roles:
                role = backend.get_object(object_type="role", uuid=x_uuid)
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

    @check_acls(['edit:add_script'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("change add script {add_script}")
    def change_add_script(
        self,
        add_script: Union[str,None]=None,
        script_options: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change share add script. """
        if script_options:
            script_options = script_options.split(" ")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_add_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return self.change_script(script_var='add_script',
                        script_options_var='add_script_options',
                        script_options=script_options,
                        script=add_script, callback=callback,
                        **kwargs)

    @check_acls(['enable:mount_script'])
    @object_lock()
    @audit_log()
    @object_changelog("enable mount script")
    def enable_mount_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable user mount script. """
        if not self.mount_script:
            msg = "Mount script not configured."
            return callback.error(msg)

        x = backend.get_object(object_type="script",
                            uuid=self.mount_script)
        if not x:
            msg = _("Script does not exist: {mount_script}")
            msg = msg.format(mount_script=self.mount_script)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_mount_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        # Check if mount_script is already enabled.
        if self.mount_script_enabled:
            msg = _("Mount script already enabled for this share.")
            return callback.error(msg)

        self.mount_script_enabled = True
        self.update_index('mount_script_enabled', self.mount_script_enabled)

        return self._cache(callback=callback)

    @check_acls(['disable:mount_script'])
    @object_lock()
    @audit_log()
    @object_changelog("disable mount script")
    def disable_mount_script(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable user mount script. """
        # Check if mount_script is already disabled.
        if not self.mount_script_enabled:
            msg = _("Mount script already disabled for this share.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_mount_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        self.mount_script_enabled = False
        self.update_index('mount_script_enabled', self.mount_script_enabled)

        return self._cache(callback=callback)

    @check_acls(['edit:mount_script'])
    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("change mount script {mount_script}")
    def change_mount_script(
        self,
        mount_script: Union[str,None]=None,
        script_options: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change share add script. """
        if script_options:
            script_options = script_options.split(" ")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_mount_script",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        return self.change_script(script_var='mount_script',
                        script_options_var='mount_script_options',
                        script_options=script_options,
                        script=mount_script, callback=callback,
                        **kwargs)

    def run_mount_script(self):
        self.run_share_script(self.mount_script, self.root_dir)

    def run_share_script(self, share_script, root_dir):
        """ Run share script. """
        share_script_parms = {
                'options'       : None,
                'share_name'    : self.name,
                'share_root'    : root_dir
                }

        if self.force_group_uuid:
            group = backend.get_object(uuid=self.force_group_uuid)
            if group:
                share_script_parms['force_group'] = group.name
        if self.create_mode != 0o000:
            share_script_parms['force_create_mode'] = str(self.create_mode).replace("o", "")
        if self.directory_mode != 0o000:
            share_script_parms['force_directory_mode'] = str(self.directory_mode).replace("o", "")

        share_script_oid = backend.get_oid(object_type="script", uuid=share_script)
        log_msg = _("Starting share script: {share_script_oid}", log=True)[1]
        log_msg = log_msg.format(share_script_oid=share_script_oid)
        logger.debug(log_msg)

        # Run share script.
        try:
            share_script_result = run_script(script_type="share_script",
                                        script_uuid=share_script,
                                        script_parms=share_script_parms,
                                        user=config.user,
                                        group=config.group)
        except Exception as e:
            log_msg = _("Error running share script: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.warning(log_msg)
            raise

        if not share_script_result:
            msg = _("Failed to run share script.")
            raise OTPmeException(msg)

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
        """ Disable share and send idled notifications. """
        # Try to enable by parent class.
        result = super().enable(*args, callback=callback, **kwargs)
        if not result:
            return result

        share_tokens = self.get_tokens(return_type="rel_path",
                                    include_roles=True)
        share_tokens = self.filter_mount_tokens(share_tokens)
        if not share_tokens:
            return result

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            # Get share nodes.
            share_nodes = self.get_nodes(include_pools=True,
                                        return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)
            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing

            # Collect notifications.
            user_shares = {}
            already_processed = []
            for token_path in share_tokens:
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
            share_notifications = self.get_share_notifications()

        if share_notifications:
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
        """ Check if token add will add new share permissions. """
        # Try to by parent class.
        result = super().disable(*args, callback=callback, **kwargs)
        if not result:
            return result

        share_tokens = self.get_tokens(return_type="rel_path",
                                    include_roles=True)
        if self.no_mount_tokens:
            share_tokens += backend.search(object_type="token",
                                        attribute="uuid",
                                        values=self.no_mount_tokens,
                                        return_type="rel_path")
        if not share_tokens:
            return result

        if persist_mount is None:
            persist_mount = not bool(self.restore_share)

        def post_method():
            # Get share nodes.
            share_nodes = self.get_nodes(include_pools=True,
                                        return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=self.realm,
                                            site=self.site,
                                            return_type="instance")
            node_fqdns = []
            for node in share_nodes:
                node_fqdns.append(node.fqdn)
            share_hosts = []
            if self.limit_by_hosts:
                share_hosts = self.get_hosts(include_groups=True,
                                            include_roles=True,
                                            return_type="name")
            shares = {}
            share_id = self.share_id
            shares[share_id] = {}
            shares[share_id]['name'] = self.name
            shares[share_id]['site'] = self.site
            shares[share_id]['nodes'] = node_fqdns
            shares[share_id]['limit_hosts'] = self.limit_by_hosts
            shares[share_id]['hosts'] = share_hosts
            shares[share_id]['encrypted'] = self.encrypted
            shares[share_id]['sotp_signing'] = self.sotp_signing

            # Collect notifications.
            user_shares = {}
            already_processed = []
            for token_path in share_tokens:
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
            share_notifications = self.get_share_notifications()

        if share_notifications:
            callback.post_methods.append(post_method)

        return result

    def _get_share_unmount_data(self, persist_mount: bool=None):
        """ Build the share_unmount notification data per user.

        Everything is resolved right away instead of in the post method
        the notification is sent from: the caller deletes the share, and
        after that its tokens, nodes and hosts cannot be resolved
        anymore.
        """
        share_tokens = self.get_tokens(return_type="rel_path",
                                    include_roles=True)
        if not share_tokens:
            return {}
        share_nodes = self.get_nodes(include_pools=True,
                                    return_type="instance")
        if not share_nodes:
            share_nodes = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=self.realm,
                                        site=self.site,
                                        return_type="instance")
        node_fqdns = [node.fqdn for node in share_nodes]
        share_hosts = []
        if self.limit_by_hosts:
            share_hosts = self.get_hosts(include_groups=True,
                                        include_roles=True,
                                        return_type="name")
        if persist_mount is None:
            persist_mount = not bool(self.restore_share)
        share_id = self.share_id
        user_shares = {}
        already_processed = []
        for token_path in share_tokens:
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
            x_shares[share_id] = {
                'name': self.name,
                'site': self.site,
                'nodes': list(node_fqdns),
                'limit_hosts': self.limit_by_hosts,
                'hosts': list(share_hosts),
                'encrypted': self.encrypted,
                'tokens': tokens,
                'persist': persist_mount,
            }
            user_shares[username] = x_shares
            already_processed.append(token_path)
        return user_shares

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog("delete")
    def delete(
        self,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        persist_mount: bool=None,
        share_notifications: bool=None,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete share. """
        if not self.exists():
            msg = _("Share does not exist.")
            return callback.error(msg)

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {share_name}")
                    msg = msg.format(share_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception:
                return callback.error()

        exception_parts = []
        if self.encrypted:
            # The per user share keys live on the share object and are
            # gone with it. The data on disk stays encrypted, so without
            # the master password there is no way back.
            msg = _("Share '{share_name}' is encrypted. The share keys are deleted with it, so its data can only be decrypted by someone in possession of the master password.")
            exception_parts.append(msg.format(share_name=self.name))
        if self.tokens:
            msg = _("Share '{share_name}' has assigned tokens: {token_list}")
            token_list = backend.search(object_type="token",
                                        attribute="uuid",
                                        values=self.tokens,
                                        return_type="rel_path")
            exception_parts.append(msg.format(share_name=self.name,
                                            token_list=", ".join(token_list)))
        if self.roles:
            msg = _("Share '{share_name}' has assigned roles: {role_list}")
            role_list = backend.search(object_type="role",
                                        attribute="uuid",
                                        values=self.roles,
                                        return_type="name")
            exception_parts.append(msg.format(share_name=self.name,
                                            role_list=", ".join(role_list)))
        exception = chr(10).join(exception_parts) if exception_parts else None
        if not self.ask_delete_confirmation(force=force,
                                            exception=exception,
                                            callback=callback):
            return callback.abort()

        # Tell the clients to unmount. The data is collected before the
        # delete because afterwards there is nothing left to resolve it
        # from, the notification itself is sent by the post method.
        if share_notifications is None:
            share_notifications = self.get_share_notifications()
        if share_notifications:
            user_shares = self._get_share_unmount_data(persist_mount=persist_mount)
            if user_shares:
                def post_method():
                    for username in user_shares:
                        notify(username=username,
                                event_type="share_unmount",
                                data=user_shares[username])
                callback.post_methods.append(post_method)

        # Delete object using parent class.
        return super().delete(verbose_level=verbose_level,
                            force=force,
                            callback=callback,
                            **kwargs)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show share config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        token_list = []
        if self.tokens:
            if self.verify_acl("view:tokens"):
                return_attrs = ['rel_path']
                token_list = backend.search(object_type="token",
                                            join_object_type="share",
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
                                            join_object_type="share",
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

        if self.verify_acl("view:nodes") \
        or self.verify_acl("add:node") \
        or self.verify_acl("remove:node"):
            node_list = []
            for i in self.nodes:
                node_oid = backend.get_oid(uuid=i,
                                        object_type="node",
                                        instance=True)
                # Add UUIDs of orphan nodes.
                if not node_oid:
                    node_list.append(i)
                    continue
                node_name = node_oid.name
                node_list.append(node_name)
            node_list.sort()
        else:
            node_list = ""

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

        pool_list = []
        if self.pools:
            if self.verify_acl("view:pools"):
                pool_list = backend.search(object_type="pool",
                                        attribute="uuid",
                                        values=self.pools,
                                        return_type="name")
            pool_list.sort()

        master_password_tokens_list = []
        if self.master_password_tokens:
            if self.verify_acl("view:master_password_tokens"):
                master_password_tokens_list = backend.search(object_type="token",
                                                            attribute="uuid",
                                                            values=self.master_password_tokens,
                                                            return_type="rel_path")
            master_password_tokens_list.sort()

        root_mount_tokens_list = []
        if self.root_mount_tokens:
            if self.verify_acl("view:root_mount_tokens"):
                root_mount_tokens_list = backend.search(object_type="token",
                                                        attribute="uuid",
                                                        values=self.root_mount_tokens,
                                                        return_type="rel_path")
            root_mount_tokens_list.sort()

        no_mount_tokens_list = []
        if self.no_mount_tokens:
            if self.verify_acl("view:no_mount_tokens"):
                no_mount_tokens_list = backend.search(object_type="token",
                                                    attribute="uuid",
                                                    values=self.no_mount_tokens,
                                                    return_type="rel_path")
            no_mount_tokens_list.sort()

        if self.verify_acl("view:groups") \
        or self.verify_acl("add:group") \
        or self.verify_acl("remove:group"):
            group_list = []
            for i in self.groups:
                group_oid = backend.get_oid(i, instance=True)
                # Add UUIDs of orphan groups.
                if not group_oid:
                    group_list.append(i)
                    continue
                if not otpme_acl.access_granted(object_id=group_oid,
                                                acl="view_public:object"):
                    continue
                group_list.append(group_oid.name)
            group_list.sort()
        else:
            group_list = [""]

        lines = []

        lines.append(f'ROLES="{",".join(role_list)}"')
        lines.append(f'TOKENS="{",".join(token_list)}"')
        lines.append(f'NODES="{",".join(node_list)}"')
        lines.append(f'NODES="{",".join(host_list)}"')
        lines.append(f'POOLS="{",".join(pool_list)}"')
        lines.append(f'GROUPS="{",".join(group_list)}"')

        if self.verify_acl("view:home_share"):
            lines.append(f'HOME_SHARE="{self.home_share}"')
        else:
            lines.append('HOME_SHARE=""')

        if self.verify_acl("view:home_share"):
            lines.append(f'HOME_SHARE_UID="{self.home_share_uid}"')
        else:
            lines.append('HOME_SHARE_UID=""')

        if self.verify_acl("view:force_group"):
            group = None
            if self.force_group_uuid:
                group = backend.get_object(uuid=self.force_group_uuid)
                if not group:
                    group = "Unknown"
            lines.append(f'FORCE_GROUP="{group}"')
        else:
            lines.append('FORCE_GROUP=""')

        if self.verify_acl("view:force_create_mode"):
            lines.append(f'CREATE_MODE="{self.create_mode}"')
        else:
            lines.append('CREATE_MODE=""')

        if self.verify_acl("view:force_directory_mode"):
            lines.append(f'DIRECTORY_MODE="{self.directory_mode}"')
        else:
            lines.append('DIRECTORY_MODE=""')

        if self.verify_acl("view:home_share_permissions"):
            lines.append(f'HOME_SHARE_PERMISSIONS="{self.home_share_permissions}"')
        else:
            lines.append('HOME_SHARE_PERMISSIONS=""')

        if self.verify_acl("view:root_dir") \
        or self.verify_acl("edit:root_dir"):
            lines.append(f'ROOT_DIR="{self.root_dir}"')
        else:
            lines.append('ROOT_DIR=""')

        if self.verify_acl("view:master_password_tokens"):
            lines.append(f'MASTER_PASSWORD_TOKENS="{",".join(master_password_tokens_list)}"')
        else:
            lines.append('MASTER_PASSWORD_TOKENS=""')

        if self.verify_acl("view:master_password_hash_params"):
            lines.append(f'MASTER_PASSWORD_HASH_PARAMS="{self.master_password_hash_params}"')
        else:
            lines.append('MASTER_PASSWORD_HASH_PARAMS=""')

        if self.verify_acl("view:root_mount_tokens"):
            lines.append(f'ROOT_MOUNT_TOKENS="{",".join(root_mount_tokens_list)}"')
        else:
            lines.append('ROOT_MOUNT_TOKENS=""')

        if self.verify_acl("view:no_mount_tokens"):
            lines.append(f'NO_MOUNT_TOKENS="{",".join(no_mount_tokens_list)}"')
        else:
            lines.append('NO_MOUNT_TOKENS=""')

        if self.verify_acl("view:add_script"):
            add_script = None
            if self.add_script:
                add_script = backend.get_object(uuid=self.add_script)
            lines.append(f'ADD_SCRIPT="{add_script}"')
        else:
            lines.append('ADD_SCRIPT=""')

        if self.verify_acl("view:mount_script"):
            mount_script = None
            if self.mount_script:
                mount_script = backend.get_object(uuid=self.mount_script)
            lines.append(f'MOUNT_SCRIPT="{mount_script}"')
        else:
            lines.append('MOUNT_SCRIPT=""')

        if self.verify_acl("view:mount_script"):
            lines.append(f'MOUNT_SCRIPT_OPTIONS="{self.mount_script_options}"')
        else:
            lines.append('MOUNT_SCRIPT_OPTIONS=""')

        if self.verify_acl("enable:mount_script") \
        or self.verify_acl("enable:mount_script"):
            lines.append(f'MOUNT_SCRIPT_ENABLED="{self.mount_script_enabled}"')
        else:
            lines.append('MOUNT_SCRIPT_ENABLED=""')

        if self.verify_acl("view:limit_hosts") \
        or self.verify_acl("limit_hosts") \
        or self.verify_acl("unlimit_hosts"):
            lines.append(f'LIMIT_HOSTS="{self.limit_by_hosts}"')
        else:
            lines.append('LIMIT_HOSTS=""')

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show share details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
