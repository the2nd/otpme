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
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
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

default_callback = config.get_callback()

read_acls =  []

write_acls =  []

read_value_acls =    {
                    "view"      : [
                                "roles",
                                "tokens",
                                "groups",
                                "scope_id",
                                "auto_member",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                "role",
                                "token",
                                "group",
                                ],
                    "remove"    : [
                                "role",
                                "token",
                                "group",
                                ],
                    "edit"      : [
                                "name",
                                "config",
                                "scope_id",
                                ],
                    "enable"      : [
                                "auto_member",
                                ],
                    "disable"      : [
                                "auto_member",
                                ],
                }

default_acls = []
recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['name', 'unit', 'scope_id'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
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
    'scope_id'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_scope_id',
                    'args'              : ['scope_id'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_auto_member'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_auto_member',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_auto_member'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_auto_member',
                    'job_type'          : 'thread',
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("scope"),
                    'args'              : ['realm'],
                    'oargs'              : [
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
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.list_getter("scope"),
                    'oargs'              : [
                                        'reverse',
                                        'show_all',
                                        'search_regex',
                                        'sort_by',
                                        ],
                    'job_type'          : None,
                    },
                'exists'    : {
                    'method'            : cli.list_getter("scope"),
                    'oargs'              : [
                                        'reverse',
                                        'show_all',
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
    'add_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'remove_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'thread',
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
    'add_client'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_client',
                    'args'              : ['client_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_client'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_client',
                    'args'              : ['client_name'],
                    'job_type'          : 'process',
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
    'list_clients'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_clients',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'skip_disabled':False},
                    'job_type'          : 'thread',
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
    'add_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    #'add_extension'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'add_extension',
    #                'args'              : ['extension'],
    #                'job_type'          : 'process',
    #                },
    #            },
    #        },
    #'remove_extension'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'remove_extension',
    #                'args'              : ['extension'],
    #                'job_type'          : 'process',
    #                },
    #            },
    #        },
    #'add_attribute'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'add_attribute',
    #                'args'              : ['attribute'],
    #                'oargs'             : ['value'],
    #                'job_type'          : 'process',
    #                },
    #            },
    #        },
    #'del_attribute'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'del_attribute',
    #                'args'              : ['attribute'],
    #                'oargs'             : ['value'],
    #                'job_type'          : 'process',
    #                },
    #            },
    #        },
    #'add_object_class'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'add_object_class',
    #                'args'              : ['object_class'],
    #                'job_type'          : 'process',
    #                },
    #            },
    #        },
    #'del_object_class'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'del_object_class',
    #                'args'              : ['object_class'],
    #                'job_type'          : 'process',
    #                },
    #            },
    #        },
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
    #'_show_config'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'show_config',
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    #'_list_valid_object_classes'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'list_valid_object_classes',
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    #'_list_valid_attributes'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'list_valid_attributes',
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    #'_show_attributes'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'show_attributes',
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    #'_show_object_classes'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'get_object_classes',
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    'show_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    #'_show_supported_acls'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'get_supported_acls',
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    #'_show_supported_default_acls'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'get_supported_acls',
    #                'args'              : { 'acl_types' : 'default_acls' },
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
    #'_show_supported_recursive_default_acls'   : {
    #        'OTPme-mgmt-1.0'    : {
    #            'exists'    : {
    #                'method'            : 'get_supported_acls',
    #                'args'              : { 'acl_types' : 'recursive_default_acls' },
    #                'job_type'          : 'thread',
    #                },
    #            },
    #        },
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
    config_params = config.get_config_parameters("scope")
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
    acls += config.get_default_acls("scope")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("scope")
    return acls

BASE_SCOPE_DEFAULTS = {
    # default: add scope to config paramter "oidc_default_scopes"
    # auto_member: add token/role to this scope on client.add_token/role().
    "openid":         {"auto_member": True,  'default': True},
    "profile":        {"auto_member": True,  'default': True},
    "email":          {"auto_member": True,  'default': True},
    "address":        {"auto_member": True,  'default': False},
    "phone":          {"auto_member": True,  'default': False},
    "offline_access": {"auto_member": True,  'default': False},
    "groups":         {"auto_member": False, 'default': False},
}

DEFAULT_UNIT = "scopes"
REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                ]

def register():
    register_oid()
    config.register_config_parameter(name="max_scope_name_len",
                                    ctype=int,
                                    default_value=128,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("scope", commands)
    config.register_recursive_default_acl("site", "+scope")
    config.register_default_acl("unit", "+scope")
    config.register_recursive_default_acl("unit", "+scope")
    config.register_index_attribute("scope_id")
    config.register_index_attribute("auto_member")
    for scope in BASE_SCOPE_DEFAULTS:
        config.register_base_object("scope", scope)

def register_hooks():
    config.register_auth_on_action_hook("scope", "add_role")
    config.register_auth_on_action_hook("scope", "remove_role")
    config.register_auth_on_action_hook("scope", "add_token")
    config.register_auth_on_action_hook("scope", "remove_token")
    config.register_auth_on_action_hook("scope", "add_client")
    config.register_auth_on_action_hook("scope", "remove_client")
    config.register_auth_on_action_hook("scope", "add_group")
    config.register_auth_on_action_hook("scope", "remove_group")
    config.register_auth_on_action_hook("scope", "set_config_parameter")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("scope", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    scope_name_re = '([0-9A-Za-z]([0-9A-Za-z_.-]*[0-9A-Za-z]){0,})'
    scope_path_re = f'{unit_path_re}[/]{scope_name_re}'
    scope_oid_re = f'scope|{scope_path_re}'
    oid.register_oid_schema(object_type="scope",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=scope_name_re,
                            path_regex=scope_path_re,
                            oid_regex=scope_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="scope",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    scope_dir_extension = "scope"
    def path_getter(scope_oid, scope_uuid):
        return backend.config_path_getter(scope_oid, scope_dir_extension)
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
                ]
        return backend.rebuild_object_index("scope", objects, after)
    # Register object to config.
    config.register_object_type(object_type="scope",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["host"],
                            sync_after=["user", "token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Scope
    backend.register_object_type(object_type="scope",
                                dir_name_extension=scope_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="scope")

@match_class_typing
class Scope(OTPmeObject):
    """ Creates scope object """
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
        # Set our type (used in parent class).
        self.type = "scope"

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

        self.scope_id = None
        self.auto_member = False

        # Scopes should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self._sync_fields = {
                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "CLIENTS",
                            "TOKENS",
                            "ROLES",
                            "GROUPS",
                            ]
                        },
                    }

    def _get_object_config(self, **kwargs):
        """ Get object config dict. """
        object_config = {
                        'SCOPE_ID'                  : {
                                                        'var_name'  : 'scope_id',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

                        'AUTO_MEMBER'                : {
                                                        'var_name'  : 'auto_member',
                                                        'type'      : bool,
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

                        'CLIENTS'                   : {
                                                        'var_name'  : 'clients',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'GROUPS'                    : {
                                                        'var_name'  : 'groups',
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
        # Make sure name is a string.
        self.name = str(name)

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
                ('tokens', 'token', ['token_options']),
                ('roles', 'role', None),
                ('clients', 'client', None),
                ]
        return super().remove_orphans(force=force,
                                    run_policies=run_policies,
                                    verbose_level=verbose_level,
                                    recursive=recursive,
                                    extra_ref_lists=extra_ref_lists,
                                    callback=callback,
                                    _caller=_caller,
                                    **kwargs)

    @object_lock(full_lock=True)
    @check_acls(['rename:object'])
    @audit_log()
    @object_changelog()
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename scope. """
        base_scopes = config.get_base_objects("scope")
        if self.name in base_scopes:
            return callback.error("Cannot rename base scope.")

        # Build new OID.
        new_oid = oid.get(object_type="scope",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        result = self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)
        return result

    @object_lock(full_lock=True)
    @run_pre_post_add_policies()
    def add(
        self,
        scope_id: str=None,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a scope. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        # Add object using parent class.
        add_result = super().add(verbose_level=verbose_level,
                                callback=callback, **kwargs)
        if not add_result:
            msg = _("Failed to add scope.")
            return callback.error(msg)
        if scope_id is None:
            scope_id = self.name
        self.change_scope_id(scope_id)
        defaults = BASE_SCOPE_DEFAULTS.get(self.name)
        if defaults:
            auto_member = defaults["auto_member"]
            if auto_member:
                self.enable_auto_member()
        return callback.ok()

    @object_lock(full_lock=True)
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
        """ Delete scope. """
        if not self.exists():
            return callback.error("Scope does not exist.")

        base_scopes = config.get_base_objects("scope")
        if self.name in base_scopes:
            return callback.error("Cannot delete base scope.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {scope_name}")
                    msg = msg.format(scope_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if not self.ask_delete_confirmation(force=force, callback=callback):
            return callback.abort()

        # Delete object using parent class.
        result = super().delete(verbose_level=verbose_level,
                                        force=force, callback=callback)
        return result

    @check_acls(['add:client'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog()
    def add_client(
        self,
        client_name: str=None,
        client_uuid: str=None,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a client to this scope. """
        if not client_uuid:
            host = backend.get_object(object_type="client",
                                    realm=config.realm,
                                    site=self.site,
                                    name=client_name)
            if not host:
                msg = _("Client does not exist: {client_name}")
                msg = msg.format(client_name=client_name)
                return callback.error(msg)
            client_uuid = host.uuid

        if client_uuid in self.clients:
            msg = _("Client already added to scope.")
            return callback.error(msg)

        # Make sure not other scope with the same ID has the client assigned.
        search_attrs = {
                    "scope_id"  : {'value':self.scope_id},
                    "client"    : {'value':client_uuid},
                    }
        other_scopes = backend.search(object_type="scope",
                                    attributes=search_attrs,
                                    return_type="instance")
        for o in other_scopes:
            if o.uuid == self.uuid:
                continue
            msg = _("Client already member of another scope with scope_id '{sid}': {name}")
            msg = msg.format(sid=self.scope_id, name=o.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_client",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        msg = _("Adding client to scope: {name}")
        msg = msg.format(name=self.name)
        callback.send(msg)

        # Append client UUID to clients.
        self.clients.append(client_uuid)
        # Update index.
        self.add_index("client", client_uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:client'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog()
    def remove_client(
        self,
        client_name: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Removes a client from this scope. """
        client = backend.get_object(object_type="client",
                                realm=config.realm,
                                site=self.site,
                                name=client_name)
        if not client:
            msg = _("Client does not exist: {client_name}")
            msg = msg.format(client_name=client_name)
            return callback.error(msg)

        if client.uuid not in self.clients:
            msg = _("Client not in scope.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_client",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Remove client UUID from group.
        self.clients.remove(client.uuid)
        # Update index.
        self.del_index("client", client.uuid)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['edit:scope_id'])
    @audit_log()
    @object_changelog()
    def change_scope_id(
        self,
        scope_id: str,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change scope ID. """
        self.scope_id = scope_id
        self.add_index("scope_id", scope_id)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['enable:auto_member'])
    @audit_log()
    @object_changelog()
    def enable_auto_member(
        self,
        run_policies: bool=True,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change scope ID. """
        if self.auto_member:
            msg = _("Auto member already enabled.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_auto_member",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.auto_member = True
        self.update_index("auto_member", self.auto_member)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['disable:auto_member'])
    @audit_log()
    @object_changelog()
    def disable_auto_member(
        self,
        run_policies: bool=True,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change scope ID. """
        if not self.auto_member:
            msg = _("Auto member already disabled.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_auto_member",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.auto_member = False
        self.update_index("auto_member", self.auto_member)
        return self._cache(callback=callback)

    @check_acls(['view:clients'])
    @cli.check_rapi_opts()
    def list_clients(
        self,
        **kwargs,
        ):
        """ Return list with all clients assigned to this object. """
        return self.get_clients(**kwargs)

    @check_acls(['add:group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog()
    def add_group(
        self,
        group_name: str=None,
        group_uuid: str=None,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a group to this scope's group whitelist.

        OIDC ``groups`` claim is computed as the intersection of the
        user's group memberships and this whitelist (per-client by
        having multiple Scope objects sharing the same ``scope_id``).
        """
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
            msg = _("Group already added to scope.")
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

        msg = _("Adding group to scope: {name}")
        msg = msg.format(name=self.name)
        callback.send(msg)

        self.groups.append(group_uuid)
        self.add_index("group", group_uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:group'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog()
    def remove_group(
        self,
        group_name: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove a group from this scope's group whitelist. """
        grp = backend.get_object(object_type="group",
                                realm=config.realm,
                                site=self.site,
                                name=group_name)
        if not grp:
            msg = _("Group does not exist: {group_name}")
            msg = msg.format(group_name=group_name)
            return callback.error(msg)

        if grp.uuid not in self.groups:
            msg = _("Group not in scope.")
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

        self.groups.remove(grp.uuid)
        self.del_index("group", grp.uuid)
        return self._cache(callback=callback)

    @cli.check_rapi_opts()
    @check_acls(acls=['view:groups'])
    def list_groups(self, **kwargs):
        """ CLI-facing wrapper. Returns the scope's group whitelist
        as names. ACL-gated (view:groups). """
        return self.get_groups(**kwargs)

    def get_groups(
        self,
        return_type: str="name",
        _caller: str="API",
        skip_disabled: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return the groups whitelisted on this scope.

        NOTE: opposite semantics from ``user.get_groups()`` /
        ``token.get_groups()`` -- those return the object's group
        memberships. On a Scope this returns the group members of
        the scope (consistent with ``Scope.get_clients()``).

        Worker method, no ACL decorator -- internal callers
        (e.g. _get_user_claims at /userinfo) must be able to read
        the whitelist regardless of the requesting principal.
        """
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

    def get_clients(
        self,
        return_type: str="name",
        _caller: str="API",
        skip_disabled: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return list with all clients assigned to this object. """
        result = []
        if not self.clients:
            return result

        search_attr = {}
        if skip_disabled:
            search_attr['enabled'] = {}
            search_attr['enabled']['value'] = True
        return_attributes = ['site', return_type]
        search_result = backend.search(object_type="client",
                                    attribute="uuid",
                                    values=self.clients,
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

    def show_config(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Show scope config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:scope_id"):
            lines.append(f'SCOPE_ID="{self.scope_id}"')
        else:
            lines.append('SCOPE_ID="-"')

        if self.verify_acl("view:tokens") \
        or self.verify_acl("add:token") \
        or self.verify_acl("remove:token"):
            token_list = []
            for i in self.tokens:
                token_oid = backend.get_oid(i, instance=True)
                # Add UUIDs of orphan tokens.
                if not token_oid:
                    token_list.append(i)
                    continue
                if not otpme_acl.access_granted(object_id=token_oid,
                                                acl="view_public:object"):
                    continue
                token_path = token_oid.rel_path
                token_list.append(token_path)
            token_list.sort()
        else:
            token_list = [""]

        if self.verify_acl("view:roles") \
        or self.verify_acl("add:role") \
        or self.verify_acl("remove:role"):
            role_list = []
            for i in self.roles:
                role_oid = backend.get_oid(i, instance=True)
                # Add UUIDs of orphan roles.
                if not role_oid:
                    role_list.append(i)
                    continue
                if not otpme_acl.access_granted(object_id=role_oid,
                                                acl="view_public:object"):
                    continue
                role_path = role_oid.rel_path
                role_list.append(role_path)
            role_list.sort()
        else:
            role_list = [""]

        if self.verify_acl("view:clients") \
        or self.verify_acl("add:client") \
        or self.verify_acl("remove:client"):
            client_list = []
            for i in self.clients:
                client_oid = backend.get_oid(i, instance=True)
                # Add UUIDs of orphan clients.
                if not client_oid:
                    client_list.append(i)
                    continue
                if not otpme_acl.access_granted(object_id=client_oid,
                                                acl="view_public:object"):
                    continue
                client_list.append(client_oid.name)
            client_list.sort()
        else:
            client_list = [""]

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

        lines.append(f'ROLES="{",".join(role_list)}"')
        lines.append(f'TOKENS="{",".join(token_list)}"')
        lines.append(f'CLIENTS="{",".join(client_list)}"')
        lines.append(f'GROUPS="{",".join(group_list)}"')

        return super().show_config(config_lines=lines, callback=callback, **kwargs)

    def show(self, **kwargs):
        """ Show role details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
