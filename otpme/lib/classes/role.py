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
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.register import register_module
from otpme.lib.typing import match_class_typing
#from otpme.lib.cache import assigned_role_cache
#from otpme.lib.cache import assigned_token_cache
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

read_acls = []
write_acls = []

read_value_acls = {
                    "view"      : [
                                    "user",
                                    "token",
                                    "accessgroup",
                                    "group",
                                    "policy",
                                    "role",
                                    "dynamic_groups",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                    "user",
                                    "token",
                                    "role",
                                    "dynamic_group",
                                ],
                    "edit"       : [
                                    "config",
                                ],
                    "remove"    : [
                                    "user",
                                    "token",
                                    "role",
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
    'list_dynamic_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_dynamic_groups',
                    'job_type'          : 'thread',
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

DEFAULT_UNIT = "roles"

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
    register_commands("role", commands)
    register_module("otpme.lib.classes.token")

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
    role_path_re = '%s[/]%s' % (unit_path_re, role_name_re)
    role_oid_re = 'role|%s' % role_path_re
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
                            add_after=["token"],
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
                    role_name = "%s/%s" % (x_site, x_name)
                result.append(role_name)
            else:
                msg = (_("Unknown return type: %s") % return_type)
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
        super(Role, self).__init__(object_id=object_id,
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

    @object_lock(full_lock=True)
    @backend.transaction
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
            return callback.error("Cannot rename base role.")
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
                    msg = "Unknown group: %s" % group_name
                    return callback.error(msg)
                _group = result[0]
                if verify_acls:
                    if not _group.verify_acl("add:role"):
                        msg = "Group: %s: Permission denied" % group_name
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
                    msg = "Unknown role: %s" % role_name
                    return callback.error(msg)
                _role = result[0]
                if verify_acls:
                    if not _role.verify_acl("add:role"):
                        msg = "Role: %s: Permission denied" % role_name
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
            return callback.error("Role does not exist exists.")

        base_roles = config.get_base_objects("role")
        if self.name in base_roles:
            return callback.error("Cannot delete base role.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if self.tokens:
            msg = "The role has tokens assigned."
            return callback.error(msg)

        if self.roles:
            msg = "The role has roles assigned."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            exception = ""
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
                exception = (_("%sRole has member tokens: %s\n")
                            % (exception, ", ".join(token_list)))

            # List that will hold all groups that uses this role.
            accessgroup_list = self.get_access_groups()

            if accessgroup_list:
                exception = (_("%sRole is member of this access groups: %s\n")
                            % (exception, ", ".join(accessgroup_list)))

            if exception != "":
                if self.confirmation_policy != "force":
                    if self.confirmation_policy == "paranoid":
                        answer = callback.ask(_("%sPlease type '%s' to delete object: ")
                                            % (exception, self.name))
                        if answer != self.name:
                            return callback.abort()
                    else:
                        answer = callback.ask(_("%sDelete role '%s'?: ")
                                            % (exception, self.name))
                        if answer.lower() != "y":
                            return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    if self.confirmation_policy == "paranoid":
                        answer = callback.ask(_("Please type '%s' to delete object: ") % self.name)
                        if answer != self.name:
                            return callback.abort()
                    else:
                        answer = callback.ask(_("Delete role '%s'?: ") % self.name)
                        if answer.lower() != "y":
                            return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

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
            if not token_oid:
                token_list.append(i)

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

            if msg:
                answer = callback.ask("%sRemove?: " % msg)
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
                callback.send(_("Removing orphan token UUID: %s") % i)
            object_changed = True
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

        if not object_changed:
            msg = (_("No orphan objects found for %s: %s")
                    % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show role config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        token_list = []
        if self.tokens:
            if self.verify_acl("view:token"):
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
            if self.verify_acl("view:role"):
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
                        role_name = "%s/%s" % (role_site, role_name)
                    role_list.append(role_name)
            role_list.sort()

        lines = []

        if self.verify_acl("view:role"):
            lines.append('ROLES="%s"' % ",".join(role_list))
        else:
            lines.append('ROLES=""')


        if self.verify_acl("view:accessgroup"):
            lines.append('ACCESS_GROUPS="%s"' % ",".join(self.get_access_groups()))
        else:
            lines.append('ACCESS_GROUPS=""')

        if self.verify_acl("view:group"):
            lines.append('GROUPS="%s"' % ",".join(self.get_groups()))
        else:
            lines.append('GROUPS=""')

        if self.verify_acl("view:token"):
            lines.append('TOKENS="%s"' % ",".join(token_list))
        else:
            lines.append('TOKENS=""')

        token_options = {}
        for uuid in self.token_options:
            if uuid in x_list:
                token_path = x_list[uuid]['rel_path']
            else:
                token_path = uuid
            token_options[token_path] = self.token_options[uuid]
        lines.append('TOKEN_OPTIONS="%s"' % token_options)

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
