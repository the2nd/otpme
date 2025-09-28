# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.audit import audit_log
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeObject
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
REGISTER_AFTER = ["otpme.lib.classes.site"]
SHARES_DIR = os.path.join(config.data_dir, "data", "shares")

read_acls = []
write_acls = []

read_value_acls = {
                    "view"      : [
                                    "token",
                                    "role",
                                    "node",
                                    "pool",
                                    "policy",
                                    "root_dir",
                                    "encrypted",
                                    "share_key",
                                    "block_size",
                                    "read_only",
                                    "force_group",
                                    "force_create_mode",
                                    "force_directory_mode",
                                    "master_password_token",
                                    "master_password_hash_params",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                    "token",
                                    "role",
                                    "node",
                                    "pool",
                                    "share_key",
                                    "master_password_token",
                                ],
                    "delete"       : [
                                    "share_key",
                                ],
                    "remove"    : [
                                    "token",
                                    "role",
                                    "node",
                                    "pool",
                                    "master_password_token",
                                ],
                    "enable"    : [
                                    "read_only",
                                ],
                    "disable"    : [
                                    "read_only",
                                ],
                    "edit"    : [
                                    "root_dir",
                                    "force_group",
                                    "force_create_mode",
                                    "force_directory_mode",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['root_dir'],
                    'oargs'             : ['unit', 'encrypted', 'no_key_gen', 'block_size'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'args'              : ['root_dir'],
                    'oargs'             : ['unit', 'encrypted', 'no_key_gen', 'block_size'],
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
                                        'max_pools',
                                        'max_roles',
                                        'max_tokens',
                                        'max_policies',
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
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
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
    'list_nodes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_nodes',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_users'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_token_users',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    'job_type'          : 'thread',
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

def register():
    register_oid()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("share", commands)
    # Register index attributes.
    config.register_index_attribute("share")
    config.register_index_attribute("root_dir")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT)
    config.register_default_unit("share", DEFAULT_UNIT)

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
        self.encrypted = False
        self.block_size = 4096
        # Call parent class init.
        super(Share, self).__init__(object_id=object_id, **kwargs)
        # List and dict attributes must be set after calling super because
        # self.incremental_update is only available after calling super.
        self.nodes = []
        self.pools = []
        self.share_keys = {}
        self.read_only = False
        self.create_mode = "0o000"
        self.directory_mode = "0o000"
        self.force_group_uuid = None
        self.master_password_tokens = []
        self.master_password_hash_params = {}

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

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'ROOT_DIR'                  : {
                                                        'var_name'  : 'root_dir',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'ENCRYPTED'                 : {
                                                        'var_name'  : 'encrypted',
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
                        'SHARE_KEYS'                : {
                                                        'var_name'  : 'share_keys',
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
                        'NODES'                     : {
                                                        'var_name'  : 'nodes',
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

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    def add(
        self,
        root_dir: str,
        encrypted: bool=False,
        key_len: int=32,
        block_size: int=4096,
        no_key_gen: bool=False,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        # Check if root dir exists.
        if not self.set_root_dir(root_dir, callback=callback):
            return callback.error()
        self.encrypted = encrypted
        self.add_index('encrypted', self.encrypted)
        if self.encrypted:
            self.block_size = block_size
            self.add_index('block_size', self.block_size)
        # Add object using parent class.
        add_result = super(Share, self).add(verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback, **kwargs)
        if self.encrypted and add_result and not no_key_gen:
            msg = _("Generating AES key for encrypted share...")
            callback.send(msg)
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
            self.add_token(token_path=config.auth_token.rel_path,
                            share_key=share_key)
        return self._write(callback=callback)

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
        """ Rename group. """
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
    def set_root_dir(
        self,
        root_dir,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if self.root_dir == root_dir:
            msg = _("Root dir already set to: {root_dir}")
            msg = msg.format(root_dir=self.root_dir)
            return callback.error(msg)
        if not os.path.exists(root_dir):
            msg = _("No such file or directory: {root_dir}")
            msg = msg.format(root_dir=root_dir)
            return callback.error(msg)
        self.root_dir = root_dir
        self.update_index('root_dir', self.root_dir)
        return self._cache(callback=callback)

    @check_acls(['edit:force_group'])
    @object_lock()
    @audit_log()
    def force_group(
        self,
        group_name,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if not group_name:
            self.del_index('force_group_uuid', self.force_group_uuid)
            self.force_group_uuid = None
            return self._cache(callback=callback)
        result = backend.search(object_type="group",
                                attribute="name",
                                value=group_name,
                                return_type="instance")
        if not result:
            msg = _("Unknown group: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)
        group = result[0]
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
        self.create_mode = create_mode
        self.update_index('create_mode', create_mode)
        return self._cache(callback=callback)

    @check_acls(['edit:force_directory_mode'])
    @object_lock()
    @audit_log()
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
        self.directory_mode = create_mode
        self.update_index('directory_mode', create_mode)
        return self._cache(callback=callback)

    @check_acls(['enable:read_only'])
    @object_lock()
    @audit_log()
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

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Make share readonly?: ")
                if answer.lower() != "y":
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

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Make share read-write?: ")
                if answer.lower() != "y":
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

    @object_lock()
    def is_master_password_token(
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
                                site=config.site,
                                return_type="uuid")
        if not result:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_uuid = result[0]
        if token_uuid in self.master_password_tokens:
            return True
        return False

    @check_acls(['add:master_password_token'])
    @object_lock()
    @audit_log()
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
    def remove_master_password_token(
        self,
        token_path: str,
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

        self.master_password_tokens.remove(token_uuid)

        return self._write(callback=callback)

    @object_lock()
    @audit_log(ignore_args=['share_key'])
    def add_token(
        self,
        token_path: str,
        share_key: str=None,
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

        if self.force_group_uuid is not None:
            group = backend.get_object(uuid=self.force_group_uuid)
            group_users = group.get_token_users(include_roles=True,
                                            skip_disabled=True,
                                            return_type="name")
            if user.name not in group_users:
                msg = _("Force group enabled and user not in group: {group_name}")
                msg = msg.format(group_name=group.name)
                return callback.error(msg)

        if self.encrypted:
            existing_key = self.get_share_key(username=user.name)
            if not existing_key and not share_key:
                msg = _("Sending request to re-encrypt share key for user: {user_name}")
                msg = msg.format(user_name=user.name)
                callback.send(msg)
                auth_user = backend.get_object(uuid=config.auth_user.uuid)
                key_mode = auth_user.key_mode
                auth_user_share_key = self.get_share_key(username=auth_user.name)
                if not auth_user_share_key:
                    msg = _("You dont have a share key for share: {share_name}")
                    msg = msg.format(share_name=self.name)
                    return callback.error(msg)
                share_key = callback.reencrypt_share_key(share_user=user.name,
                                                        share_key=auth_user_share_key,
                                                        key_mode=key_mode)
                if not share_key:
                    msg = _("Failed to receive share key from client.")
                    return callback.error(msg)
            if share_key:
                if not self.add_share_key(username=user.name,
                                    share_key=share_key,
                                    callback=callback,
                                    verify_acls=False):
                    msg = _("Failed to add share key for user: {user}")
                    msg = msg.format(user=user)
                    return callback.error(msg)

        return super(Share, self).add_token(token_path=token_path,
                                        callback=callback, **kwargs)

    @object_lock()
    @audit_log()
    def remove_token(
        self,
        token_path: str,
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

        if self.encrypted:
            token_user = token_path.split("/")[0]
            self.del_share_key(username=token_user,
                                callback=callback,
                                verify_acls=False)

        return super(Share, self).remove_token(token_path=token_path,
                                            callback=callback, **kwargs)

    @object_lock()
    @audit_log()
    def add_role(
        self,
        *args,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Check if share is encrypted. """
        if self.encrypted:
            msg = _("Encrypted shares do not support roles.")
            return callback.error(msg)
        return super(Share, self).add_role(*args, callback=callback, **kwargs)

    @check_acls(['add:share_key'])
    @object_lock()
    @audit_log(ignore_args=['share_key'])
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
    def del_share_key(
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

        self.share_keys.pop(user_uuid)

        return self._write(callback=callback)

    @check_acls(['add:ppol'])
    @object_lock()
    @audit_log()
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

    @cli.check_rapi_opts()
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

        result = super(Share, self).get_nodes(return_type=return_type,
                                            skip_disabled=skip_disabled,
                                            include_pools=include_pools,
                                            callback=callback,
                                            _caller=_caller)

        return callback.ok(result)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show role config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        token_list = []
        if self.tokens:
            if self.verify_acl("view:token"):
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
            if self.verify_acl("view:role"):
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

        node_list = []
        if self.nodes:
            if self.verify_acl("view:node"):
                return_attrs = ['name']
                node_list = backend.search(object_type="node",
                                        join_object_type="share",
                                        join_search_attr="uuid",
                                        join_search_val=self.uuid,
                                        join_attribute="token",
                                        attribute="uuid",
                                        value="*",
                                        return_attributes=return_attrs)
            node_list.sort()

        pool_list = []
        if self.pools:
            if self.verify_acl("view:pool"):
                pool_list = backend.search(object_type="pool",
                                        attribute="uuid",
                                        values=self.pools,
                                        return_type="name")
            pool_list.sort()

        master_password_tokens_list = []
        if self.master_password_tokens:
            if self.verify_acl("view:master_password_token"):
                master_password_tokens_list = backend.search(object_type="token",
                                                            attribute="uuid",
                                                            values=self.master_password_tokens,
                                                            return_type="rel_path")
            master_password_tokens_list.sort()

        lines = []

        if self.verify_acl("view:role"):
            lines.append(f'ROLES="{",".join(role_list)}"')
        else:
            lines.append('ROLES=""')

        if self.verify_acl("view:token"):
            lines.append(f'TOKENS="{",".join(token_list)}"')
        else:
            lines.append('TOKENS=""')

        if self.verify_acl("view:node"):
            lines.append(f'NODES="{",".join(node_list)}"')
        else:
            lines.append('NODES=""')

        if self.verify_acl("view:pool"):
            lines.append(f'POOLS="{",".join(pool_list)}"')
        else:
            lines.append('POOLS=""')

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

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show role details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
