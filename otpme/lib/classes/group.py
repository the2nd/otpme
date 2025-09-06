# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import jwt
from otpme.lib import json
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.register import register_module
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
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

logger = config.logger

read_acls = []
write_acls = []

read_value_acls = {
                    "view"      : [
                                "role",
                                "token",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                "user",
                                "token",
                                "role",
                                "default_group_user",
                                ],
                    "edit"       : [
                                "config",
                                ],
                    "remove"    : [
                                "user",
                                "token",
                                "role",
                                "default_group_user",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'ldif_attributes'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'ldif_attributes'],
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
                    'method'            : cli.show_getter("group"),
                    'args'              : ['realm'],
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'max_policies',
                                        'max_roles',
                                        'max_tokens',
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
                    'method'            : cli.list_getter("group"),
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
                    'method'            : cli.list_getter("group"),
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
    'add_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'oargs'             : ['token_options', 'sign', 'tags'],
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
                    'method'            : 'get_sync_users',
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
    'list_default_group_users'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_default_group_users',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name'},
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_roles'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_roles',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'recursive'],
                    'dargs'             : {'return_type':'name'},
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

DEFAULT_UNIT = "groups"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                ]

def register():
    register_dn()
    register_oid()
    register_hooks()
    register_backend()
    register_object_unit()
    register_ldap_object()
    register_sync_settings()
    register_commands("group", commands)
    register_module("otpme.lib.classes.token")

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("group", "cn")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("group", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    #read_oid_schema = [ 'realm', 'site', 'name' ]
    read_oid_schema = [ 'realm', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    group_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    group_path_re = '%s[/]%s' % (unit_path_re, group_name_re)
    group_oid_re = 'group|%s' % group_path_re
    oid.register_oid_schema(object_type="group",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=group_name_re,
                            path_regex=group_path_re,
                            oid_regex=group_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="group",
                                getter=rel_path_getter)
def register_hooks():
    config.register_auth_on_action_hook("group", "add_role")
    config.register_auth_on_action_hook("group", "remove_role")
    config.register_auth_on_action_hook("group", "add_token")
    config.register_auth_on_action_hook("group", "remove_token")

def register_backend():
    """ Register object for the file backend. """
    group_dir_extension = "group"
    def path_getter(group_oid, group_uuid):
        return backend.config_path_getter(group_oid, group_dir_extension)
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                ]
        return backend.rebuild_object_index("group", objects, after)
    # Register object to config.
    config.register_object_type(object_type="group",
                            tree_object=True,
                            add_after=["dictionary"],
                            sync_before=["token", "user"],
                            uniq_name=True,
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'name'])
    # Register index attributes.
    config.register_index_attribute('user')
    # Register object to backend.
    class_getter = lambda: Group
    backend.register_object_type(object_type="group",
                                dir_name_extension=group_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="group")
    config.register_object_sync(host_type="host", object_type="group")

def register_ldap_object():
    """ Register LDAP object settings. """
    config.register_ldap_object(object_type="group",
                                default_scope="one",
                                scopes=['one'])

@match_class_typing
class Group(OTPmeObject):
    """ Creates access group object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        name: Union[str,None]=None,
        realm: Union[str,None]=None,
        unit: Union[str,None]=None,
        site: Union[str,None]=None,
        path: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class)
        self.type = "group"

        # Call parent class init.
        super(Group, self).__init__(object_id=object_id,
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

        self.token_options = {}
        self.token_login_interfaces = {}
        # Groups should inherit ACLs by default.
        self.acl_inheritance_enabled = True

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "ROLES",
                            "TOKENS",
                            "SYNC_USERS",
                            "DEFAULT_GROUP_USERS",
                            "HOSTS",
                            "NODES",
                            "gidNumber",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "ROLES",
                            "TOKENS",
                            "SYNC_USERS",
                            "DEFAULT_GROUP_USERS",
                            "HOSTS",
                            "NODES",
                            "gidNumber",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict """
        object_config = {
                        'SYNC_USERS'                     : {
                                                        'var_name'  : 'sync_users',
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

                        'DEFAULT_GROUP_USERS'       : {
                                                        'var_name'  : 'default_group_users',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

            }

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = str(name).lower()

    @check_acls(['add:default_group_user'])
    @object_lock()
    @backend.transaction
    def add_default_group_user(
        self,
        user_uuid: str,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds user as its default group. """
        if user_uuid in self.default_group_users:
            msg = (_("User already added to group '%s'.") % self.name)
            return callback.error(msg)
        # Add user to group.
        self.default_group_users.append(user_uuid)
        # Update index.
        self.add_index('user', user_uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:default_group_user'])
    @object_lock()
    @backend.transaction
    def remove_default_group_user(
        self,
        user_uuid: str,
        ignore_missing: bool=False,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Removes a user from groups members list. """
        if user_uuid not in self.default_group_users:
            if ignore_missing:
                return
            msg = (_("User not in group '%s'.")
                    % self.name)
            return callback.error(msg)
        # Remove user from group.
        self.default_group_users.remove(user_uuid)
        # Update index.
        self.del_index('user', user_uuid)
        return self._cache(callback=callback)

    @object_lock()
    def list_default_group_users(
        self,
        return_type: str="name",
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ List default group users. """
        exception = None
        if not return_type in [ 'uuid', 'oid', 'name', 'read_oid', 'full_oid']:
            exception = "Unknown return type: %s" % return_type
        if exception:
            if _caller != "API":
                return callback.error(exception)
            else:
                raise Exception(exception)
        result = []
        user_uuids = self.default_group_users.copy()
        if user_uuids:
            # Search users (return attribute) via user UUID.
            search_attrs = {}
            result = backend.search(object_type="user",
                                    attribute="uuid",
                                    values=user_uuids,
                                    attributes=search_attrs,
                                    return_type=return_type)
            result.sort()
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    @object_lock(full_lock=True)
    @backend.transaction
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename group. """
        base_groups = config.get_base_objects("group")
        if self.name in base_groups:
            return callback.error("Cannot rename base group.")

        # Build new OID.
        new_oid = oid.get(object_type="group",
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
        ldif_attributes: Union[str,None]=None,
        default_attributes: dict={},
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a group. """
        # Check if group exist on any site.
        result = backend.search(object_type="group",
                                attribute="name",
                                value=self.name,
                                return_type="oid")
        if result:
            group_oid = result[0]
            msg = "Group already exists: %s" % group_oid
            return callback.error(msg)

        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()

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
                    except:
                        msg = "Invalid attribute: %s" % x
                        return callback.error(msg)
                    if attr not in ext_attrs:
                        continue
                    if ext not in default_attributes:
                        default_attributes[ext] = {}
                    if attr == "gidNumber":
                        value = int(value)
                    default_attributes[ext][attr] = value

        # Add object using parent class.
        add_result = OTPmeObject.add(self, default_attributes=default_attributes,
                            verbose_level=verbose_level, callback=callback, **kwargs)

        return add_result

    def move(self,
        *args,
        _caller: str="API",
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Move user to other unit. """
        internal_groups = config.get_internal_objects("group")
        if self.name in internal_groups:
            msg = "Moving internal group is not allowed."
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
                msg = "Error running policies: %s" % e
                return callback.error(msg)

        new_unit = kwargs['new_unit']
        if new_unit.startswith("/"):
            path_data = oid.resolve_path(new_unit, object_type="group")
            new_site = path_data['site']
            if new_site != self.site:
                return self.cross_site_move(*args, path=new_unit,
                                            callback=callback,
                                            **kwargs)

        move_result = super(Group, self).move(*args, callback=callback, **kwargs)
        return move_result

    def cross_site_move(
        self,
        path: str,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Do cross site move of group. """
        if config.use_api:
            msg = "Cannot do cross-site move in API mode."
            return callback.error(msg)

        path_data = oid.resolve_path(object_path=path,
                                    object_type="unit")
        dst_realm = path_data['realm']
        dst_site = path_data['site']

        object_ids = [(self.oid.full_oid, self.uuid)]
        group_policies = self.get_policies(ignore_hooks=True,
                                        return_type="name")
        for policy_name in group_policies:
            self.remove_policy(policy_name=policy_name,
                                verify_acls=False)
        self.update_object_config()
        object_config = self.object_config.copy()
        objects = {
                    self.oid.full_oid   : {
                                            'path'          : path,
                                            'object_config' : object_config,
                                            'policies'      : group_policies,
                                        },
                }

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
        """ Delete group. """
        if not self.exists():
            return callback.error("Group does not exist.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if self.is_special_object(return_true_false=True):
            msg = "Cannot delete special group: %s" % self.name
            return callback.error(msg)

        if self.default_group_users:
            msg = "The group has default group users assigned."
            return callback.error(msg)

        if self.tokens:
            msg = "The group has tokens assigned."
            return callback.error(msg)

        if self.roles:
            msg = "The group has roles assigned."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            exception = ""
            # List that will hold all roles of this group.
            role_list = []
            # Get all roles from this group.
            for r_uuid in self.roles:
                role = backend.get_object(object_type="role", uuid=r_uuid)
                role_list.append(role.name)

            if role_list:
                exception = (_("%sGroup '%s' has member roles: %s\n")
                            % (exception, self.name, ", ".join(role_list)))

            # List that will hold all tokens that of this group.
            token_list = []
            # Get all tokens from this group.
            for t_uuid in self.tokens:
                token = backend.get_object(object_type="token", uuid=t_uuid)
                token_list.append(token.rel_path)

            if token_list:
                exception = (_("%sGroup '%s' has member tokens: %s\n")
                            % (exception, self.name, ", ".join(token_list)))

            if self.confirmation_policy != "force":
                if self.confirmation_policy == "paranoid":
                    msg = ("%sPlease type '%s' to delete object: "
                        % (exception, self.name))
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
                else:
                    answer = callback.ask(_("%sDelete group?: ") % exception)
                    if answer.lower() != "y":
                        return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback,
                                    **kwargs)

    @check_acls(['remove:orphans'])
    @object_lock()
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

        default_group_users_list = []
        user_uuids = self.default_group_users
        for i in user_uuids:
            user_oid = backend.get_oid(object_type="user", uuid=i)
            if user_oid:
                continue
            default_group_users_list.append(i)

        if not force:
            msg = ""
            if acl_list:
                msg = (_("%s%s|%s: Found the following orphan ACLs: %s\n")
                        % (msg, self.type, self.name, ",".join(acl_list)))

            if policy_list:
                msg = ""
                if policy_list:
                    msg = (_("%s%s|%s: Found the following orphan policies: %s\n")
                            % (msg, self.type, self.name, ",".join(policy_list)))

            if token_list:
                msg = (_("%s%s|%s: Found the following orphan token UUIDs: %s\n")
                        % (msg, self.type, self.name, ",".join(token_list)))

            if role_list:
                msg = (_("%s%s|%s: Found the following orphan role UUIDs: %s\n")
                        % (msg, self.type, self.name, ",".join(role_list)))

            if default_group_users_list:
                msg = (_("%s%s|%s: Found the following orphan user UUIDs: %s\n")
                        % (msg, self.type, self.name, ",".join(default_group_users_list)))

            if msg:
                answer = callback.ask(_("%sRemove?: ") % msg)
                if answer.lower() != "y":
                    return callback.abort()

        object_changed = False
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
                callback.send(_("Removing orphan token UUID: %s") % i)
            object_changed = True
            if i in self.tokens:
                self.tokens.remove(i)
            if i in self.token_options:
                self.token_options.pop(i)

        for i in role_list:
            if verbose_level > 0:
                callback.send(_("Removing orphan role UUID: %s") % i)
            object_changed = True
            self.roles.remove(i)

        for i in default_group_users_list:
            if verbose_level > 0:
                callback.send(_("Removing orphan user UUID: %s") % i)
            object_changed = True
            if i in self.default_group_users:
                self.default_group_users.remove(i)

        if not object_changed:
            msg = (_("No orphan objects found for %s: %s")
                    % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show_config(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Show group config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        if self.verify_acl("view:token") \
        or self.verify_acl("add:token") \
        or self.verify_acl("remove:token"):
            token_list = []
            for i in self.tokens:
                token_oid = backend.get_oid(object_type="token",
                                            uuid=i, instance=True)
                # Add UUIDs of orphan tokens.
                if not token_oid:
                    token_list.append(i)
                    continue
                if not otpme_acl.access_granted(object_id=token_oid,
                                                acl="view_public:object"):
                    continue
                token_list.append(token_oid.rel_path)
            token_list.sort()
        else:
            token_list = [""]

        if self.verify_acl("view:roles"):
            role_list = []
            for i in self.roles:
                role_oid = backend.get_oid(object_type="role",
                                        uuid=i, instance=True)
                # Add UUIDs of orphan roles
                if not role_oid:
                    role_list.append(i)
                    continue
                if not otpme_acl.access_granted(object_id=role_oid,
                                                acl="view_public:object"):
                    continue
                role_path = "%s (%s)" % (role_oid.rel_path, role_oid.site)
                role_list.append(role_path)
            role_list.sort()
        else:
            role_list = [""]

        lines.append('ROLES="%s"' % ",".join(role_list))
        lines.append('TOKENS="%s"' % ",".join(token_list))
        token_options = {}
        for uuid in self.token_options:
            token = backend.get_object(object_type="token", uuid=uuid)
            if token:
                token_path = token.rel_path
            else:
                token_path = uuid
            token_options[token_path] = self.token_options[uuid]
        lines.append('TOKEN_OPTIONS="%s"' % token_options)

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show group details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
