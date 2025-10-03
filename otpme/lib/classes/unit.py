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
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import multiprocessing
from otpme.lib.audit import audit_log
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeObject
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
                                ],
                    "edit"      : [
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
                                ],
                    }

# FIXME: make this list a register method???
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
                    "+user",
                    "+group",
                    "+accessgroup",
                    "+client",
                    "+node",
                    "+host",
                    "+role",
                    "+ca",
                    "+script",
                    "+token",
                    "+policy",
                    "+resolver",
                    "+dictionary",
                    ]

recursive_default_acls = default_acls

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
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
                    'method'            : cli.show_getter("unit"),
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
                    'job_type'          : 'thread',
                    },
                },
            },
    'list'   : {
            'OTPme-mgmt-1.0'    : {
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
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : [],
                    'job_type'          : 'thread',
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
                    'oargs'             : ['merge', 'keep_acls', 'keep_old_unit', 'object_types'],
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
                    'args'              : ['attribute', 'old_value', 'new_value'],
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
                    'args'              : ['owner_type', 'owner_name', 'acl'],
                    'oargs'             : ['recursive_acls', 'apply_default_acls', 'object_types'],
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
                    'oargs'              : ['recursive_acls', 'apply_default_acls', 'object_types',],
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

def get_value_acls(**kwargs):
    return _get_value_acls(read_value_acls, write_value_acls, **kwargs)

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
    return _recursive_default_acls

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

def register():
    register_dn()
    register_oid()
    register_hooks()
    register_backend()
    register_ldap_object()
    register_sync_settings()
    register_commands("unit", commands)

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("unit", "ou")

def register_hooks():
    config.register_auth_on_action_hook("unit", "pre_add_role")

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'rel_path' ]
    read_oid_schema = None
    # OID regex stuff.
    site_path_re = oid.object_regex['site']['path']
    unit_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    unit_path_re = f'{site_path_re}([/]{unit_name_re}){{1,}}'
    unit_oid_re = f'unit|{unit_path_re}'
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
        super(Unit, self).__init__(object_id=object_id,
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
                            "EXTENSION_ATTRIBUTES",
                            "OBJECT_CLASSES",
                            "ou",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "EXTENSION_ATTRIBUTES",
                            "OBJECT_CLASSES",
                            "ou",
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
        acl: object,
        recursive_acls: bool=False,
        apply_default_acls: bool=False,
        object_types: Union[List,None]=[],
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Method to call inherit_default_acl() for all member objects. """
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

        # Get members.
        members = self.get_members(return_type="instance")

        # Disable printing of "Reading objects..."
        self._acl_msg = False

        for object_type in members:
            try:
                objects = members[object_type]
            except:
                continue
            for o in objects:
                # Make sure we inherit ACLs recursive through all units.
                if recursive_acls:
                    # Get ACL apply IDs.
                    apply_id, recursive_apply_id = o.get_acl_apply_ids(acl=acl)

                    if apply_id:
                        add_status = o.handle_acl(action=action,
                                            acl=apply_id,
                                            owner_uuid=acl.owner_uuid,
                                            object_types=object_types,
                                            recursive_acls=recursive_acls,
                                            apply_default_acls=apply_default_acls,
                                            verify_acls=verify_acls,
                                            verbose_level=verbose_level,
                                            callback=callback,
                                            **kwargs)
                        if not add_status:
                            exception = True

                if apply_default_acls:
                    inherit_acl = True
                    if object_types and o.type not in object_types:
                        inherit_acl = False
                    if inherit_acl:
                        o_inherit_method = getattr(o, inherit_method)
                        add_status = o_inherit_method(acl=acl,
                                        object_types=object_types,
                                        verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback)
                        if not add_status:
                            exception = True
        if exception:
            return callback.error()
        else:
            return callback.ok()

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

        for object_type in object_types:
            object_oids = backend.search(realm=self.realm,
                                        site=self.site,
                                        attribute="unit",
                                        value=self.uuid,
                                        object_type=object_type,
                                        return_type="oid")
            if not object_oids:
                continue
            _members[object_type] = object_oids

        members = {}
        for t in _members:
            objects = []
            for o_id in _members[t]:
                if return_type == "instance" or recursive:
                    o = backend.get_object(object_type=t, object_id=o_id)
                    if o:
                        objects.append(o)
                elif return_type == "oid":
                    objects.append(o_id)
                elif return_type == "full_oid":
                    objects.append(o_id.full_oid)
                elif return_type == "uuid":
                    o_uuid = backend.get_uuid(o_id)
                    objects.append(o_uuid)
                elif return_type == "name":
                    o_name = o_id.name
                    objects.append(o_name)
                elif return_type == "path":
                    o_path = o_id.path
                    objects.append(o_path)

            members[t] = objects

        if not recursive:
            return members

        # Get recursive members.
        x_members = dict(members)
        while True:
            try:
                child_units = x_members['unit']
            except:
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
                    o_uuid = backend.get_uuid(o.oid)
                    objects.append(o_uuid)
                elif return_type == "name":
                    o_name = o.name
                    objects.append(o_name)
                elif return_type == "path":
                    o_path = o_id.path
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
        keep_acls: Union[bool,None]=None,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change unit's unit (move). """
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
            except:
                continue
            for x in t_members:
                if x.type != "ca":
                    continue
                if force:
                    keep_old_unit = True
                    break
                msg = _("Unit has CA as a child: {ca_name}")
                msg = msg.format(ca_name=x)
                callback.error(msg)
                msg = "Use <force> to move objects other than CAs and keep unit."
                raise OTPmeException(msg)

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
                    child_unit.move(new_child_unit_path,
                                object_types=object_types,
                                keep_acls=keep_acls,
                                run_policies=run_policies,
                                verbose_level=verbose_level,
                                callback=callback,
                                force=force,
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
                        force=force,
                        _caller=_caller)
            # Reset unit members to initiate re-check.
            unit_members = None

        # Invalidate cache.
        members_cache.invalidate()
        if keep_old_unit:
            return callback.ok()

        return self.delete(add_to_trash=False, force=True, callback=callback)

    @object_lock(full_lock=True)
    @run_pre_post_add_policies()
    @audit_log()
    def add(self, verify_acls=True, inherit_acls=True,
        verbose_level=0, callback=default_callback, **kwargs):
        """ Add a unit. """
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
                self.add_acl(acl=_acl.id,
                            owner_uuid=_acl.owner_uuid,
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
            return callback.error("Unit does not exist exists.")

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
                except:
                    continue
                x = _("Unit '{unit_name}' contains {obj_type}s: {obj_names}")
                x = x.format(unit_name=self.name, obj_type=object_type, obj_names=', '.join(object_names))
                if exception:
                    exception = f"{exception}\n{x}"
                else:
                    exception = x

        if not force:
            if exception != "":
                if self.confirmation_policy != "force":
                    if self.confirmation_policy != "paranoid":
                        msg = _("{exception}\nPlease type '{unit_name}' to delete object: ")
                        msg = msg.format(exception=exception, unit_name=self.name)
                        answer = callback.ask(msg)
                        if answer != self.name:
                            return callback.abort()
                    else:
                        msg = _("{exception}\nDelete unit?: ")
                        msg = msg.format(exception=exception)
                        answer = callback.ask(msg)
                        if answer.lower() != "y":
                            return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    if self.confirmation_policy != "paranoid":
                        msg = _("Please type '{unit_name}' to delete object: ")
                        msg = msg.format(unit_name=self.name)
                        answer = callback.ask(msg)
                        if answer != self.name:
                            return callback.abort()
                    else:
                        msg = _("Delete unit '{unit_name}'?: ")
                        msg = msg.format(unit_name=self.name)
                        answer = callback.ask(msg)
                        if answer.lower() != "y":
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

        # Invalidate cache.
        members_cache.invalidate()
        return del_result

    @check_acls(['remove:orphans'])
    @object_lock()
    @audit_log()
    def remove_orphans(
        self,
        recursive: bool=False,
        run_policies: bool=True,
        force: bool=False,
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

        remove_orphans = True
        object_changed = False
        if not force:
            msg = ""
            if acl_list:
                msg = _("{obj_type}{obj_name}: Found the following orphan ACLs: {acl_list}\n")
                msg = msg.format(obj_type=self.type, obj_name=self.name, acl_list=','.join(acl_list))
            if msg:
                answer = callback.ask(f"{msg}Remove?: ")
                if answer.lower() != "y":
                    remove_orphans = False

        if remove_orphans:
            if self.remove_orphan_acls(force=True,
                                verbose_level=verbose_level,
                                callback=callback, **kwargs):
                object_changed = True

        if recursive:
            # Get member object names.
            members = self.get_members(return_type="uuid")
            for object_type in members:
                uuids = members[object_type]
                for i in uuids:
                    o = backend.get_object(object_type=object_type, uuid=i)
                    # Skip orphan objects.
                    if not o:
                        continue
                    if verbose_level > 1:
                        msg = _("Processing {oid}")
                        msg = msg.format(oid=o.oid)
                        callback.send(msg)
                    if o.remove_orphans(force=force,
                                        verbose_level=verbose_level,
                                        recursive=recursive,
                                        callback=callback,
                                        **kwargs):
                        object_changed = True
        if not object_changed:
            msg = None
            if verbose_level > 0:
                msg = _("No orphan objects found for {obj_type}: {obj_name}")
                msg = msg.format(obj_type=self.type, obj_name=self.name)
            return callback.ok(msg)

        return self._cache(callback=callback)

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
