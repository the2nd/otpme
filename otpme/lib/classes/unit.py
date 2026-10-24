# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib
from typing import List
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
from otpme.lib import otpme_acl
from otpme.lib import worker_pool
from otpme.lib import multiprocessing
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.classes.otpme_object import name_len_setter
from otpme.lib.protocols.utils import register_commands
from otpme.lib.cache import unit_members_cache as members_cache
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

# The workers that walk the members of a unit, how many there are and
# from how many members on they are started at all, are in
# otpme.lib.worker_pool.

read_acls = []
write_acls = []

read_value_acls = {}
write_value_acls = {
                    "add"       : [
                                "unit",
                                "user",
                                "group",
                                "accessgroup",
                                "client",
                                "node",
                                "host",
                                "role",
                                "ca",
                                "script",
                                "policy",
                                "resolver",
                                "pass",
                                "vlan",
                                "device",
                                "pool",
                                "share",
                                "scope",
                                "dictionary",
                                ],
                    "set"       : [
                                "config",
                                ],
                    "delete"    : [
                                "unit",
                                "user",
                                "group",
                                "accessgroup",
                                "client",
                                "node",
                                "host",
                                "role",
                                "ca",
                                "script",
                                "policy",
                                "resolver",
                                "pass",
                                "vlan",
                                "device",
                                "pool",
                                "share",
                                "scope",
                                "dictionary",
                                ],
                    }

default_acls = [
                    "all",
                    "rename",
                    "edit",
                    "add",
                    "remove",
                    "delete",
                    "enable",
                    "disable",
                    "view_all",
                    "view_public",
                    "view",
                    "import",
                    "export",
                    "+unit",
                    ]

recursive_default_acls = [
                    "all",
                    "rename",
                    "edit",
                    "add",
                    "remove",
                    "delete",
                    "enable",
                    "disable",
                    "view_all",
                    "view_public",
                    "view",
                    "import",
                    "export",
                    "+unit",
                    ]
commands = {
    'add'   : {
            'default'    : {
                'missing'    : {
                    'method'            : 'add',
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
                    'method'            : cli.show_getter("unit"),
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
                    'job_type'          : 'thread',
                    },
                },
            },
    'list'   : {
            'default'    : {
                'missing'    : {
                    'method'            : cli.list_getter("unit"),
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
                    'method'            : cli.list_getter("unit"),
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
    'show_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : ['parameter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'del'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'delete',
                    'oargs'             : ['add_to_trash'],
                    'job_type'          : 'process',
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
                    'oargs'             : ['merge', 'keep_acls', 'keep_old_unit', 'object_types', 'skip_ca'],
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
    'modify_attribute'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'modify_attribute',
                    'args'              : ['attribute', 'old_value', 'new_value'],
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
                    'cache_update_interval' : 30,
                    'args'              : ['owner_type', 'owner_name', 'acls'],
                    'oargs'             : ['recursive_acls', 'apply_default_acls', 'object_types', 'procs'],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'cache_update_interval' : 30,
                    'args'              : ['acls'],
                    'oargs'              : ['recursive_acls', 'apply_default_acls', 'object_types', 'procs'],
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
    'list_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    'sign_password_members'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'sign_password_members',
                    'job_type'          : 'process',
                    },
                },
            },
    'unsign_password_members'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'unsign_password_members',
                    'oargs'             : ['signer'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_password_members'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_password_members',
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

def register_subtype_add_acl(acl):
    global write_value_acls
    add_acl_list = write_value_acls['add']
    add_acl_list.append(acl)
    write_value_acls['add'] = add_acl_list

def register_subtype_del_acl(acl):
    global write_value_acls
    del_acl_list = write_value_acls['delete']
    del_acl_list.append(acl)
    write_value_acls['delete'] = del_acl_list

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(split=False, **kwargs):
    from otpme.lib.extensions import utils
    result = _get_value_acls(read_value_acls, write_value_acls, split=split, **kwargs)
    config_params = config.get_config_parameters("unit")
    if split:
        read_acls = result[0]['view']
        add_acls = result[1]['add']
        edit_acls = result[1]['edit']
        set_acls = result[1]['set']
        del_acls = result[1]['delete']
    else:
        read_acls = result['view']
        add_acls = result['add']
        edit_acls = result['edit']
        set_acls = result['set']
        del_acls = result['delete']
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        set_acls.append(acl)
    # Get extension value ACLs.
    value_acls = utils.get_value_acls("unit")
    for a in value_acls:
        for acl in value_acls[a]:
            add_acls.append(acl)
            read_acls.append(acl)
            edit_acls.append(acl)
            del_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    _default_acls = _get_default_acls(default_acls, **kwargs)
    for acl in _default_acls:
        if not acl.startswith("+"):
            continue
        object_type = acl.split("+")[1]
        sub_types = config.get_sub_object_types(object_type)
        if not sub_types:
            continue
        for sub_type in sub_types:
            object_module_path = f"otpme.lib.{object_type}.{sub_type}.{sub_type}"
            object_module = importlib.import_module(object_module_path)
            for default_acl in object_module.get_default_acls():
                if default_acl in _default_acls:
                    continue
                _default_acls.append(default_acl)
    _default_acls += config.get_default_acls("unit")
    return _default_acls

def get_recursive_default_acls(**kwargs):
    _recursive_default_acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    for acl in _recursive_default_acls:
        if not acl.startswith("+"):
            continue
        object_type = acl.split("+")[1]
        sub_types = config.get_sub_object_types(object_type)
        if not sub_types:
            continue
        for sub_type in sub_types:
            object_module_path = f"otpme.lib.{object_type}.{sub_type}.{sub_type}"
            object_module = importlib.import_module(object_module_path)
            for default_acl in object_module.get_default_acls():
                if default_acl in _recursive_default_acls:
                    continue
                _recursive_default_acls.append(default_acl)
    _recursive_default_acls += config.get_recursive_default_acls("unit")
    return _recursive_default_acls

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

def register():
    register_dn()
    register_oid()
    config.register_config_parameter(name="max_unit_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_ldap_object()
    register_sync_settings()
    register_commands("unit", commands)
    config.register_default_acl("site", "+unit")
    config.register_recursive_default_acl("site", "+unit")

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("unit", "ou")

def register_hooks():
    config.register_auth_on_action_hook("unit", "pre_add_role")
    config.register_auth_on_action_hook("unit", "set_config_parameter")

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'rel_path' ]
    read_oid_schema = None
    # OID regex stuff.
    site_path_re = oid.object_regex['site']['path']
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    unit_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    unit_path_re = f'{site_path_re}([/]{unit_name_re}){{1,}}'
    # An OID is not a path, see accessgroup.py: no leading slash. We
    # have no read schema, so there is one form -- realm, site and the
    # rel_path, which is one or more unit names.
    #unit_oid_re = f'unit|{unit_path_re}'
    unit_oid_re = (f'unit[|]{realm_name_re}[/]{site_name_re}'
                f'([/]{unit_name_re}){{1,}}')
    oid.register_oid_schema(object_type="unit",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=unit_name_re,
                            path_regex=unit_path_re,
                            oid_regex=unit_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="unit",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    unit_dir_extension = "unit"
    def path_getter(unit_oid, unit_uuid):
        site_dir = backend.get_site_dir(unit_oid.realm, unit_oid.site)
        if unit_oid.unit:
            unit_fs_path = backend.get_unit_fs_path(unit_oid)
            config_dir = os.path.join(site_dir, unit_fs_path)
        else:
            config_dir = site_dir
        unit_dir_name = f"{unit_oid.name}.{unit_dir_extension}"
        config_dir = os.path.join(config_dir, unit_dir_name)
        config_paths = {}
        config_paths['config_dir'] = config_dir
        config_paths['rmtree_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                ]
        return backend.rebuild_object_index("unit", objects, after)
    # Register object to config.
    config.register_object_type(object_type="unit",
                            version=1,
                            tree_object=True,
                            uniq_name=False,
                            add_after=["site"],
                            sync_after=["site"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'rel_path'])
    # Register object to backend.
    class_getter = lambda: Unit
    backend.register_object_type(object_type="unit",
                                dir_name_extension=unit_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="unit")
    config.register_object_sync(host_type="host", object_type="unit")

def register_ldap_object():
    """ Register LDAP object settings. """
    config.register_ldap_object(object_type="unit", scopes=['one', 'base', 'sub'])

@match_class_typing
class Unit(OTPmeObject):
    """ Creates unit object. """
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
        self.type = "unit"

        if not path and not object_id and (not name and not site and not realm):
            msg = _("Need <object_id> or <path> or <realm>+<site>+[unit]+<name>!")
            raise OTPmeException(msg)

        if not path:
            if unit:
                if unit.startswith("/"):
                    path = f"{unit}/{name}"
            else:
                path = f"/{realm}/{site}/{name}"

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

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "EXTENSIONS",
                            # Only the LDIF is built from them, and a
                            # host has no LDIF, see _base_sync_fields.
                            #"EXTENSION_ATTRIBUTES",
                            "OBJECT_CLASSES",
                            "ou",
                            "CONFIG_PARAMS:backupd_max_conn",
                            "CONFIG_PARAMS:socket_backlog",
                            "CONFIG_PARAMS:max_decompressed_size",
                            ],
                        'sso_host'  : [
                                "CONFIG_PARAMS:httpd_workers",
                                "CONFIG_PARAMS:httpd_socket_uri",
                                "CONFIG_PARAMS:httpd_ssl_workers",
                                "CONFIG_PARAMS:httpd_ssl_socket_uri",
                                ],
                        },

                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "EXTENSION_ATTRIBUTES",
                            "OBJECT_CLASSES",
                            "ou",
                            "CONFIG_PARAMS:allow_temp_passwords",
                            # Part of the device_token_roles cascade
                            # (user overrides unit overrides site), so
                            # it travels with the other two.
                            "CONFIG_PARAMS:device_token_roles",
                            # Same cascade, same reason: a portal of
                            # another site asks these of our users.
                            "CONFIG_PARAMS:deploy_login_token_reauth",
                            "CONFIG_PARAMS:deploy_fido2_token_reauth",
                            "CONFIG_PARAMS:deploy_passkey_reauth",
                            "CONFIG_PARAMS:deploy_tiqr_token_reauth",
                            "CONFIG_PARAMS:deploy_totp_token_reauth",
                            "CONFIG_PARAMS:sso_allow_passkey_mgmt",
                            "CONFIG_PARAMS:sso_allow_tiqr_mgmt",
                            "CONFIG_PARAMS:sso_allow_totp_mgmt",
                            "CONFIG_PARAMS:sso_allow_login_token_redeploy",
                            "CONFIG_PARAMS:deploy_device_token_reauth",
                            "CONFIG_PARAMS:sso_profile_edit_reauth",
                            "CONFIG_PARAMS:sso_reauth_timeout",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {}
        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is lowercase.
        self.name = name.lower()

    @object_lock()
    def _handle_acl(
        self,
        action: str,
        acls: List,
        recursive_acls: bool=False,
        apply_default_acls: bool=False,
        object_types: Union[List,None]=None,
        verify_acls: bool=True,
        # Named, like everything else handle_acl() hands down, so it
        # cannot ride along in kwargs and be passed a second time by
        # name further down. That is what broke Site._handle_acl().
        force: bool=False,
        procs: Union[int,None]=None,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Method to call inherit_default_acl() for all member objects. """
        if object_types is None:
            object_types = []
        exception = None
        if action == "add":
            inherit_method = "inherit_default_acl"
        else:
            inherit_method = "disinherit_default_acl"

        if not recursive_acls and not apply_default_acls:
            return callback.ok()

        if verbose_level > 0:
            # Function to print "Reading objects..." message only if reading
            # objects takes more than 2 seconds.
            def print_msg():
                import time
                wait = 2
                while True:
                    if wait == 0:
                        if self._acl_msg:
                            msg = _("* Reading objects from unit {unit_path}...")
                            msg = msg.format(unit_path=self.rel_path)
                            callback.send(msg)
                        break
                    wait -= 1
                    time.sleep(1)
                return True
            # Start thread that will print the message if needed.
            self._acl_msg = True
            multiprocessing.start_thread("print_msg", print_msg)

        # Get members. By UUID, and loaded one at a time below: this
        # walks the whole tree, and a member list of objects would be
        # the tree in memory.
        members = self.get_members(return_type="uuid", object_types=object_types)

        # Disable printing of "Reading objects..."
        self._acl_msg = False

        # How many objects this unit holds, so every message can say
        # where in them it is. Per unit and not per tree: a sub unit is
        # walked as one of these and counts its own, and counting the
        # whole tree first would mean reading it twice.
        member_count = 0
        for object_type in members:
            member_count += len(members[object_type])
        member_pos = 0

        member_kwargs = {
                    'inherit_method'        : inherit_method,
                    'recursive_acls'        : recursive_acls,
                    'apply_default_acls'    : apply_default_acls,
                    'object_types'          : object_types,
                    'verify_acls'           : verify_acls,
                    'force'                 : force,
                    # A member that is a unit of its own walks its own
                    # members, and is told the same as we were.
                    'procs'                 : procs,
                    'verbose_level'         : verbose_level,
                    }
        member_kwargs.update(kwargs)

        # Many members are worth sharing out. The objects of a unit are
        # independent of each other -- each is read, changed and written
        # on its own -- so the only thing a worker needs is which one to
        # do, and the time goes into the index and the caches, which
        # take more than one process at a time.
        if member_count >= worker_pool.WORKER_MIN_ITEMS \
        and not worker_pool.in_worker:
            return self.handle_acl_members_in_workers(members,
                                            member_count=member_count,
                                            action=action,
                                            acls=acls,
                                            callback=callback,
                                            **member_kwargs)

        for object_type in members:
            try:
                object_uuids = members[object_type]
            except Exception:
                continue
            for x_uuid in object_uuids:
                member_pos += 1
                member_progress = {
                                'pos'   : member_pos,
                                'total' : member_count,
                                }
                if not self.handle_acl_member(action, acls,
                                    object_type=object_type,
                                    member_uuid=x_uuid,
                                    member_progress=member_progress,
                                    callback=callback,
                                    **member_kwargs):
                    exception = True
        if exception:
            return callback.error()

        return callback.ok()

    def handle_acl_members_in_workers(self, members, member_count, action,
        acls, callback=default_callback, **member_kwargs):
        """ Walk the members of this unit with a pool of workers.

        The pool is the one in otpme.lib.worker_pool, see there for how
        it is built and why.

        What travels the queue is the type and the UUID of a member,
        which is small. Everything a worker needs besides -- the ACLs of
        this walk, what to do with them, who is asking -- it inherits
        when it is forked; none of that changes while the walk runs.

        The lines of a member say where in the walk it is ("3/100"), so
        they are said in the order the members went out.
        """
        def handle_member(item, worker_callback):
            # True or False: anything that is not a yes is a failure
            # here, and the pool takes only False for one.
            status = self.handle_acl_member(action, acls,
                                object_type=item['type'],
                                member_uuid=item['uuid'],
                                member_progress={
                                            'pos'   : item['pos'],
                                            'total' : member_count,
                                            },
                                callback=worker_callback,
                                **member_kwargs)
            return bool(status)

        def get_items():
            pos = 0
            for object_type in members:
                try:
                    object_uuids = members[object_type]
                except Exception:
                    continue
                for x_uuid in object_uuids:
                    pos += 1
                    yield {
                            'type'  : object_type,
                            'uuid'  : x_uuid,
                            'pos'   : pos,
                            }

        # Out of the kwargs of the members and not a named argument of
        # our own: they carry it down to a member that is a unit, and
        # naming it here as well would be the same argument twice.
        pool = worker_pool.WorkerPool(name="acl",
                                    handler=handle_member,
                                    callback=callback,
                                    procs=member_kwargs.get("procs"),
                                    ordered=True)
        pool.start()
        try:
            status = pool.run(get_items())
        finally:
            pool.stop()

        if not status:
            return callback.error()

        return callback.ok()

    def handle_acl_member(self, action, acls, object_type, member_uuid,
        member_progress, inherit_method, recursive_acls=False,
        apply_default_acls=False, object_types=None, verify_acls=True,
        force=False, verbose_level=0, callback=default_callback, **kwargs):
        """ Put the ACLs of this walk on one member of this unit.

        Its own method and not the body of the loop above, because it is
        everything that happens to one object and nothing else: it takes
        the UUID of a member, reads it, changes it and writes it, and
        says whether that worked. Whoever calls it decides how many are
        done at a time.
        """
        exception = False
        if object_types is None:
            object_types = []
        # Not into the cache: we touch every object once, so what it
        # would keep is of no use to anybody and the walk would leave an
        # instance of the whole tree there.
        o = backend.get_object(object_type=object_type,
                            uuid=member_uuid,
                            add_to_cache=False)
        if not o:
            return True
        # Make sure we inherit ACLs recursive through all units.
        if recursive_acls:
            # Get the ACL apply IDs, all of them, so this member is read
            # and written once and not once per ACL.
            #
            # As raw ACLs and not as IDs with one owner beside them: the
            # ACLs of a list can belong to different owners --
            # inherit_acls() hands us the ACLs of a parent object -- and
            # a raw ACL carries its own.
            member_acls = []
            for x_acl in acls:
                apply_id = o.get_acl_apply_ids(acl=x_acl)[0]
                if not apply_id:
                    continue
                member_acl = f"{x_acl.owner_type}:{x_acl.owner_uuid}:{apply_id}"
                member_acls.append(member_acl)

            if member_acls:
                # The owner is not looked up here, because it was not
                # looked up before either: this path used to hand over
                # the owner UUID, which skips the check a raw ACL would
                # run into.
                member_kwargs = dict(kwargs)
                member_kwargs['ignore_unknown_owner'] = True
                add_status = o.handle_acl(action=action,
                                    raw_acls=member_acls,
                                    object_types=object_types,
                                    recursive_acls=recursive_acls,
                                    apply_default_acls=apply_default_acls,
                                    _acl_progress=member_progress,
                                    verify_acls=verify_acls,
                                    # Named now that _handle_acl() names
                                    # it and it no longer rides along in
                                    # kwargs. It used to reach a member
                                    # that way and still should.
                                    force=force,
                                    verbose_level=verbose_level,
                                    callback=callback,
                                    **member_kwargs)
                if not add_status:
                    exception = True

        if apply_default_acls:
            inherit_acl = True
            if object_types and o.type not in object_types:
                inherit_acl = False
            if inherit_acl:
                o_inherit_method = getattr(o, inherit_method)
                for x_acl in acls:
                    # force, because somebody asked for this.
                    # acl_inheritance_enabled says whether an object
                    # follows its unit by itself, and it is off for most
                    # types -- which made an explicit "-a" do nothing at
                    # all, without saying so. Adding an object does the
                    # same thing for the same reason, see
                    # OTPmeObject.add().
                    add_status = o_inherit_method(acl=x_acl,
                                    force=True,
                                    procs=kwargs.get("procs"),
                                    object_types=object_types,
                                    _acl_progress=member_progress,
                                    _acl_owners=kwargs.get("_acl_owners"),
                                    verify_acls=verify_acls,
                                    verbose_level=verbose_level,
                                    callback=callback)
                    if not add_status:
                        exception = True

        # Done with this member: written here, because we loaded it and
        # nothing else holds it. Its own handle_acl() writes it where it
        # can tell that it is part of a walk, but the default ACLs above
        # reach it through inherit_default_acl(), which cannot.
        if not o.write_acl_changes(callback=callback):
            exception = True

        return not exception

    @members_cache.cache_method()
    def get_members(
        self,
        object_types: Union[List,None]=None,
        return_type: str="full_oid",
        recursive: bool=False,
        **kwargs,
        ):
        """ Get all unit member objects. """
        _members = {}
        if not object_types:
            object_types = config.tree_object_types

        # The index answers every return type but "instance" by itself,
        # so a caller that only wants names or UUIDs costs no objects at
        # all. Where we need the objects we ask for UUIDs: an OID is
        # built per row (see the file backend), and a member list of
        # OIDs pays that for everything at once, while loading pays it
        # one object at a time -- which is how _handle_acl() walks a
        # unit that has many members.
        search_return_type = return_type
        if return_type == "instance" or recursive:
            search_return_type = "uuid"

        for object_type in object_types:
            search_result = backend.search(realm=self.realm,
                                        site=self.site,
                                        attribute="unit",
                                        value=self.uuid,
                                        object_type=object_type,
                                        return_type=search_return_type)
            if not search_result:
                continue
            _members[object_type] = search_result

        if not recursive and search_return_type == return_type:
            return _members

        # From here on we need the objects themselves: to hand them out,
        # or to ask them for their own members below.
        members = {}
        for t in _members:
            objects = []
            for x_uuid in _members[t]:
                o = backend.get_object(object_type=t, uuid=x_uuid)
                if not o:
                    continue
                objects.append(o)
            members[t] = objects

        if not recursive:
            return members

        # Get recursive members.
        x_members = dict(members)
        while True:
            try:
                child_units = x_members['unit']
            except Exception:
                child_units = []

            if not child_units:
                break

            for o in child_units:
                x_members = o.get_members(object_types=object_types,
                                            return_type="instance",
                                            recursive=False)
                if not x_members:
                    continue

                for t in x_members:
                    for xo in x_members[t]:
                        if t not in members:
                            members[t] = []
                        members[t].append(xo)

        recursive_members = {}
        for t in members:
            objects = []
            for o in members[t]:
                if return_type == "instance":
                    objects.append(o)
                elif return_type == "oid":
                    objects.append(o.oid)
                elif return_type == "full_oid":
                    objects.append(o.oid.full_oid)
                elif return_type == "uuid":
                    # The object is here, so its UUID is too. Asking the
                    # backend for it is one lookup per member.
                    objects.append(o.uuid)
                elif return_type == "name":
                    o_name = o.name
                    objects.append(o_name)
                elif return_type == "path":
                    o_path = o.path
                    objects.append(o_path)
            recursive_members[t] = objects

        return recursive_members

    def rename(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename unit. """
        msg = "Please use move to rename a unit."
        return callback.error(msg)

    @check_acls(acls=['move'])
    # Besides we dont need a transaction for object moves it keeps object
    # locks longer than needed and slows down other jobs while moving.
    #@backend.transaction
    def move(
        self,
        new_unit: str,
        object_types: Union[List,None]=None,
        merge: bool=False,
        run_policies: bool=True,
        keep_old_unit: bool=False,
        force: bool=False,
        skip_ca: bool=False,
        keep_acls: Union[bool,None]=None,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change unit's unit (move).

        force skips the confirmation like everywhere else. A CA cannot be
        moved, so moving a unit that holds one is a different decision and
        has its own skip_ca.
        """
        if not keep_old_unit:
            base_units = config.get_base_objects("unit")
            if not self.unit and self.rel_path in base_units:
                return callback.error("Cannot move base unit.")

        # Remove tailing slash.
        if new_unit.endswith("/"):
            new_unit = new_unit[:-1]
        # Build absolute path.
        if not new_unit.startswith("/"):
            new_unit = f"/{self.realm}/{self.site}/{new_unit}"

        move_child_units = True
        if object_types:
            if keep_old_unit is not True:
                msg = _("You must use <keep_old_unit> when moving only specific objects.")
                return callback.error(msg)
            if "unit" not in object_types:
                move_child_units = False

        check_path = f"{self.path}/"
        if check_path in new_unit:
            move_child_units = False
            if not keep_old_unit:
                msg = _("Cannot move unit to sub unit of itself Please use <keep_old_unit>.")
                return callback.error(msg)

        # Get all unit members.
        unit_members = self.get_members(return_type="instance", recursive=False)
        # Check for CA.
        for t in unit_members:
            try:
                t_members = unit_members[t]
            except Exception:
                continue
            for x in t_members:
                if x.type != "ca":
                    continue
                if skip_ca:
                    keep_old_unit = True
                    break
                msg = _("Unit has CA as a child: {ca_name}")
                msg = msg.format(ca_name=x)
                callback.error(msg)
                msg = "Use <skip_ca> to move objects other than CAs and keep unit."
                raise OTPmeException(msg)

        msg = _("Move unit '{unit_path}' to '{new_unit}'? All its members are moved with it.: ")
        msg = msg.format(unit_path=self.rel_path, new_unit=new_unit)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        msg = _("Moving unit {old_path} > {new_path}...")
        msg = msg.format(old_path=self.path, new_path=new_unit)
        callback.send(msg)

        # Get new unit.
        from otpme.lib.classes.unit import Unit
        try:
            _new_unit = Unit(path=new_unit)
        except Exception as e:
            msg = _("Invalid unit: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        _keep_acls = True
        if _new_unit.exists():
            _keep_acls = False
            if not merge:
                msg = _("Unit exists: {unit_path}")
                msg = msg.format(unit_path=_new_unit.path)
                return callback.error(msg)
        else:
            inherit_acls = False
            if keep_acls is False:
                inherit_acls = True
            _new_unit.add(inherit_acls=inherit_acls,
                        callback=callback,
                        verbose_level=verbose_level,
                        _caller=_caller)
            if keep_acls is not False:
                _new_unit.acls = self.acls
            _new_unit.policies = self.policies
            _new_unit.policy_options = self.policy_options
            _new_unit.description = self.description
            _new_unit._write(callback=callback)

        if keep_acls is None:
            keep_acls = _keep_acls

        # Get all child units.
        if move_child_units:
            child_units = self.get_members(object_types=["unit"],
                                            return_type="instance",
                                            recursive=False)
            # Move child units.
            if child_units:
                for child_unit in child_units['unit']:
                    new_child_unit_path = f"{_new_unit.path}/{child_unit.name}"
                    # The move of this unit is the confirmed action, its
                    # child units and members go with it.
                    child_unit.move(new_child_unit_path,
                                object_types=object_types,
                                keep_acls=keep_acls,
                                run_policies=run_policies,
                                verbose_level=verbose_level,
                                callback=callback,
                                force=True,
                                skip_ca=skip_ca,
                                _caller=_caller)

        # Move all unit members.
        lock_acquired = False
        while True:
            if not unit_members:
                # Re-check for memebers.
                unit_members = self.get_members(return_type="instance",
                                                recursive=False)
                if not unit_members:
                    # No need to lock for unit that will not be deleted.
                    if keep_old_unit:
                        break
                    if lock_acquired:
                        break
                    # Acquire lock to prevent new objects to be added
                    # to this unit.
                    self.acquire_lock(lock_caller="move")
                    lock_acquired = True
            for t in config.object_add_order:
                # Units where moved before in this method.
                if t == "unit":
                    continue
                if object_types:
                    if t not in object_types:
                        continue
                try:
                    x_members = sorted(unit_members[t])
                except KeyError:
                    continue
                for x in x_members:
                    # Ignore objects without unit (e.g. tokens).
                    if not x.unit_uuid:
                        continue
                    x.move(new_unit=new_unit,
                        keep_acls=keep_acls,
                        run_policies=run_policies,
                        callback=callback,
                        verbose_level=verbose_level,
                        force=True,
                        _caller=_caller)
            # Reset unit members to initiate re-check.
            unit_members = None

        if keep_old_unit:
            return callback.ok()

        return self.delete(add_to_trash=False, force=True, callback=callback)

    @object_lock(full_lock=True)
    @run_pre_post_add_policies()
    @audit_log()
    @object_changelog("add")
    def add(self, verify_acls=True, inherit_acls=True, force=False,
        verbose_level=0, callback=default_callback, **kwargs):
        """ Add a unit.

        We take force as a parameter to prevent it from ending up in kwargs.
        The methods we call while adding the unit get force=True explicitly
        and would else get it twice.
        """
        # Run parent class stuff e.g. verify ACLs.
        # When adding a sub unit we need a exact matching ACL because we
        # dont want a global "add" ACL to allow adding of sub units.
        result = self._prepare_add(verify_acls=verify_acls,
                                    add_acl="add:unit",
                                    need_exact_acl=True,
                                    callback=callback,
                                    **kwargs)
        if result is False:
            return callback.error()

        try:
            parent_object = self.get_parent_object()
        except Exception as e:
            msg = _("Unable to get parent object: {oid}: {error}")
            msg = msg.format(oid=self.oid, error=e)
            return callback.error(msg)

        # Add ACLs to new unit. We only add ACLs for the current login user.
        for acl in parent_object.acls:
            # Cannot inherit user ACLs without auth token.
            if not config.auth_token:
                break
            # Decode ACL.
            try:
                _acl = otpme_acl.decode(acl)
            except Exception as e:
                msg, log_msg = _("Error decoding ACL: {acl}: {error}", log=True)
                msg = msg.format(acl=acl, error=e)
                log_msg = log_msg.format(acl=acl, error=e)
                logger.critical(log_msg)
                return callback.error(msg)
            # Skip recursive ACLs which already should be added
            # by _prepare_add().
            if _acl.recursive:
                continue

            # Get token roles.
            token_roles = config.auth_token.get_roles(return_type="uuid")

            # Check if ACL matches the current login user.
            acl_match = False
            if config.auth_token.uuid == _acl.owner_uuid:
                acl_match = True

            for r in token_roles:
                if r == _acl.owner_uuid:
                    acl_match = True

            if not acl_match:
                continue

            # Add ACL.
            try:
                self.add_acl(acls=[_acl.id],
                            owner_uuid=_acl.owner_uuid,
                            force=True,
                            verify_acls=False,
                            verbose_level=verbose_level,
                            callback=callback,
                            **kwargs)
            except Exception as e:
                msg, log_msg = _("Error adding ACL: {error}", log=True)
                msg = msg.format(error=e)
                log_msg = log_msg.format(error=e)
                logger.critical(log_msg)
                return callback.error(msg)

        # Units should inherit ACLs by default.
        self.acl_inheritance_enabled = True
        # Add object using parent class.
        return OTPmeObject.add(self, inherit_acls=inherit_acls,
                                verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @audit_log()
    @object_changelog("delete")
    def delete(
        self,
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete unit. """
        if self.unit_uuid:
            parent_object = backend.get_object(object_type="unit",
                                            uuid=self.unit_uuid)
            if not parent_object:
                msg = _("Parent unit does not exist: {unit_uuid}")
                msg = msg.format(unit_uuid=self.unit_uuid)
                return callback.error(msg)
        else:
            parent_object = backend.get_object(object_type="site",
                                            uuid=config.site_uuid)
            if not parent_object:
                msg = _("Uuhhh site does not exist: {site_uuid}")
                msg = msg.format(site_uuid=config.site_uuid)
                return callback.error(msg)

        if not parent_object.verify_acl("delete:unit"):
            if not self.verify_acl("delete:object"):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)

        if not backend.object_exists(object_id=self.oid):
            return callback.error("Unit does not exist.")

        base_units = config.get_base_objects("unit")
        if not self.unit and self.rel_path in base_units:
            return callback.error("Cannot delete base unit.")

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        exception = ""

        # Get member object names.
        if not force:
            members = self.get_members(return_type="name")
            for object_type in members:
                try:
                    object_names = members[object_type]
                except Exception:
                    continue
                x = _("Unit '{unit_name}' contains {obj_type}s: {obj_names}")
                x = x.format(unit_name=self.name, obj_type=object_type, obj_names=', '.join(object_names))
                if exception:
                    exception = f"{exception}\n{x}"
                else:
                    exception = x

        exception_str = exception if exception != "" else None
        if not self.ask_delete_confirmation(force=force, exception=exception_str, callback=callback):
            return callback.abort()

        # Remove member objects.
        members = self.get_members(return_type="instance")
        for object_type in members:
            for o in members[object_type]:
                try:
                    o.delete(force=True, callback=callback, **kwargs)
                except Exception as e:
                    msg = _("Unable to delete {obj_type} '{obj_name}': {error}")
                    msg = msg.format(obj_type=o.type, obj_name=o.name, error=e)
                    return callback.error(msg)

        # Delete object using parent class.
        del_result = OTPmeObject.delete(self,
                        verbose_level=verbose_level,
                        force=force,
                        callback=callback,
                        **kwargs)

        return del_result

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
        extra_ref_lists = []
        return super().remove_orphans(force=force,
                                    run_policies=run_policies,
                                    verbose_level=verbose_level,
                                    recursive=recursive,
                                    extra_ref_lists=extra_ref_lists,
                                    recursive_func=self._remove_orphans_recursive,
                                    callback=callback,
                                    _caller=_caller,
                                    **kwargs)

    def _remove_orphans_recursive(self, force=False, verbose_level=0,
        recursive=False, callback=default_callback, **kwargs):
        """ Recurse into the unit's member objects. """
        object_changed = False
        members = self.get_members(return_type="uuid")
        for object_type in members:
            for x_uuid in members[object_type]:
                o = backend.get_object(object_type=object_type, uuid=x_uuid)
                if not o:
                    continue
                if verbose_level > 1:
                    callback.send(_("Processing {oid}").format(oid=o.oid))
                if o.remove_orphans(force=force, verbose_level=verbose_level,
                                    recursive=recursive, callback=callback):
                    object_changed = True
        return object_changed

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show unit config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)


    def show(self, callback: JobCallback=default_callback, **kwargs):
        """ Show unit members. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        lines.append(f"{self.path}:\n")

        count = 0
        # Get member object names
        members = self.get_members(return_type="oid")
        for object_type in members:
            object_ids = members[object_type]
            if len(object_ids) > 0:
                if count > 0:
                    lines.append("\n")
                o_type = f"{object_type[:1].upper()}{object_type[1:]}"
                lines.append(f"     {o_type}s:")
                for o in object_ids:
                    if not otpme_acl.access_granted(object_id=o,
                                                    acl="view_public:object"):
                        continue
                    lines.append(f"\t{o.name}")
                count += 1

        output = "\n".join(lines)

        return callback.ok(output)
