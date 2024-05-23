# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import datetime
#import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import locking
from otpme.lib.humanize import units
from otpme.lib.classes.unit import Unit
from otpme.lib.classes.user import User
from otpme.lib.classes.group import Group
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
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

logger = config.logger

default_callback = config.get_callback()

read_acls =  [
                'get_objects',
            ]

write_acls =  [
                'run',
            ]

read_value_acls = {
                "view"  : [
                        "resolver_type",
                        "key_attribute",
                        "sync_interval",
                        ],
            }

write_value_acls = {
                "edit"  : [
                        "key_attribute",
                        "sync_interval",
                        ],
                "enable"  : [
                        "deletions",
                        "sync_units",
                        ],
                "disable"  : [
                        "deletions",
                        "sync_units",
                        ],
                "delete"  : [
                        "objects",
                        ],
            }

default_acls = []

recursive_default_acls = []

LOCK_TYPE = "resolver.ldap.sync"

commands = {
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
                    'method'            : cli.show_getter("resolver"),
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
                    'method'            : cli.list_getter("resolver"),
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
                    'method'            : cli.list_getter("resolver"),
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
    'sync_interval'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_sync_interval',
                    'args'              : ['sync_interval'],
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
    'run'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'run',
                    'oargs'             : ['object_types'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_deletions'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_deletions',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_deletions'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_deletions',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_sync_units'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sync_units',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_sync_units'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sync_units',
                    'job_type'          : 'process',
                    },
                },
            },
    'delete_objects'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'delete_objects',
                    'oargs'               : ['object_types'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_objects'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_resolver_objects',
                    'oargs'              : ['object_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'oargs'             : ['object_types'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls', 'object_types'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls', 'object_types',],
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

DEFAULT_UNIT = "resolvers"
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.unit"]

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("resolver", commands)
    locking.register_lock_type(LOCK_TYPE, module=__file__)

def register_hooks():
    config.register_auth_on_action_hook("resolver", "run")
    config.register_auth_on_action_hook("resolver", "test")
    config.register_auth_on_action_hook("resolver", "delete_objects")
    config.register_auth_on_action_hook("resolver", "enable_deletions")
    config.register_auth_on_action_hook("resolver", "disable_deletions")
    config.register_auth_on_action_hook("resolver", "change_key_attribute")
    config.register_auth_on_action_hook("resolver", "get_resolver_objects")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("resolver", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    resolver_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    resolver_path_re = '%s[/]%s' % (unit_path_re, resolver_name_re)
    resolver_oid_re = 'resolver|%s' % resolver_path_re
    oid.register_oid_schema(object_type="resolver",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=resolver_name_re,
                            path_regex=resolver_path_re,
                            oid_regex=resolver_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="resolver",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    from otpme.lib import resolver
    resolver_dir_extension = "resolver"
    def path_getter(resolver_oid):
        return backend.config_path_getter(resolver_oid, resolver_dir_extension)
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
                'role',
                'policy',
                ]
        return backend.rebuild_object_index("resolver", objects, after)
    # Register object to config.
    config.register_object_type(object_type="resolver",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["unit", "script"],
                            sync_after=["unit", "script"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = resolver.get_class
    class_getter_args = {'RESOLVER_TYPE' : 'resolver_type'}
    backend.register_object_type(object_type="resolver",
                                dir_name_extension=resolver_dir_extension,
                                class_getter=class_getter,
                                class_getter_args=class_getter_args,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="resolver")

class Resolver(OTPmeObject):
    """ Generic OTPme resolver object. """
    commands = commands
    def __init__(self, object_id=None, name=None, path=None,
        realm=None, site=None, unit=None, **kwargs):
        # Set our type (used in parent class)
        self.type = "resolver"

        # Call parent class init.
        super(Resolver, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        unit=unit,
                                        name=name,
                                        path=path,
                                        **kwargs)
        # The resolver type (e.g. LDAP).
        self.resolver_type = None
        # Object types the resolver is valid for.
        self.object_types = []
        # The attributes this resolver uses to sync objects.
        self.key_attributes = {}
        # Templates the resolver knows.
        self.templates = {}
        # If True we will delete objects that are removed on the resolver site.
        self.sync_deletions = False
        # Sync units=
        self.sync_units = False
        self.sync_interval = 300
        self.track_last_used = True
        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "RESOLVER_TYPE",
                            ]
                        },
                    'node'  : {
                        'untrusted'  : [
                            "RESOLVER_TYPE",
                            ]
                        },
                    }

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = str(name).lower()
        # Set our lock iD used to prevent race condition e.g when delete() is
        # called while we are running.
        self.lock_id = "resolver_sync_%s" % self.name

    def _get_object_config(self, resolver_config=None):
        """ Get object config dict. """
        resolver_base_config = {
                        'RESOLVER_TYPE'             : {
                                                        'var_name'  : 'resolver_type',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'KEY_ATTRIBUTES'            : {
                                                        'var_name'  : 'key_attributes',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
                        'SYNC_DELETIONS'            : {
                                                        'var_name'  : 'sync_deletions',
                                                        'type'      : bool,
                                                        'required'  : True,
                                                    },
                        'SYNC_UNITS'                : {
                                                        'var_name'  : 'sync_units',
                                                        'type'      : bool,
                                                        'required'  : True,
                                                    },
                        'SYNC_INTERVAL'             : {
                                                        'var_name'  : 'sync_interval',
                                                        'type'      : int,
                                                        'required'  : True,
                                                    },
                        }

        object_config = {}
        # Merge resolver config with base resolver config.
        for i in resolver_base_config:
            if i in resolver_config:
                conf = resolver_config[i]
                resolver_config.pop(i)
            else:
                conf = resolver_base_config[i]
                object_config[i] = conf

        for i in resolver_config:
            object_config[i] = resolver_config[i]

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    @property
    def last_run(self):
        last_run = self.get_last_used_time()
        return last_run

    @property
    def is_enabled(self):
        result = backend.search(object_type="resolver",
                                attribute="uuid",
                                value=self.uuid,
                                return_attributes=['enabled'])
        enabled = result[0]
        return enabled

    @check_acls(['enable:sync_units'])
    @object_lock()
    @backend.transaction
    def enable_sync_units(self, run_policies=True,
        force=False, callback=default_callback, _caller="API", **kwargs):
        """ Enable deletion of objects missing on resolver site. """
        if self.sync_units:
            msg = "Sync of units already enabled."
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sync_units",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_units = True
        return self._cache(callback=callback)

    @check_acls(['disable:sync_units'])
    @object_lock()
    @backend.transaction
    def disable_sync_units(self, run_policies=True,
        force=False, callback=default_callback, _caller="API", **kwargs):
        """ Disable deletion of objects missing on resolver site. """
        if not self.sync_units:
            msg = "Sync of units already disabled."
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sync_units",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_units = False
        return self._cache(callback=callback)

    @check_acls(['enable:deletions'])
    @object_lock()
    @backend.transaction
    def enable_deletions(self, run_policies=True,
        force=False, callback=default_callback, _caller="API", **kwargs):
        """ Enable deletion of objects missing on resolver site. """
        if self.sync_deletions:
            msg = "Sync of deletions already enabled."
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_deletions",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_deletions = True
        return self._cache(callback=callback)

    @check_acls(['disable:deletions'])
    @object_lock()
    @backend.transaction
    def disable_deletions(self, run_policies=True,
        force=False, callback=default_callback, _caller="API", **kwargs):
        """ Disable deletion of objects missing on resolver site. """
        if not self.sync_deletions:
            msg = "Sync of deletions already disabled."
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_deletions",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_deletions = False
        return self._cache(callback=callback)

    @check_acls(['edit:key_attribute'])
    @object_lock()
    @backend.transaction
    def change_key_attribute(self, object_type, key_attribute, force=False,
        run_policies=True, callback=default_callback, _caller="API", **kwargs):
        """ Change attribute used to sync objects. """
        if not key_attribute:
            return callback.error("Got empty key attribute.")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_key_attribute",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.key_attributes[object_type] = key_attribute
        return self._cache(callback=callback)

    @check_acls(['run', 'test'])
    def test(self, object_types=None, run_policies=True, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Test the resolver. """
        if run_policies:
            try:
                self.run_policies("test",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Call child class test().
        exit_status = self._test(verbose_level=verbose_level,
                                        callback=callback)
        # Call sync method with testing enabled.
        sync_status = self.start_sync(test=True,
                                    callback=callback,
                                    object_types=object_types,
                                    verbose_level=verbose_level)
        if exit_status is False or sync_status is False:
            return callback.error("There were errors!")

        return callback.ok("All tests successful.")

    @check_acls(['run'])
    def run(self, object_types=None, run_policies=True, verbose_level=0,
        daemon_run=False, callback=default_callback, _caller="API", **kwargs):
        """ Run the resolver. """
        if run_policies:
            try:
                self.run_policies("run",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Set last used time.
        self.update_last_used_time()
        # Call sync method.
        sync_status = self.start_sync(interactive=True,
                                    callback=callback,
                                    daemon_run=daemon_run,
                                    object_types=object_types,
                                    verbose_level=verbose_level)

        if sync_status is False:
            return callback.error()

        return sync_status

    def check_object_resolver(self, object_id, interactive=False,
        run_policies=True, callback=default_callback, **kwargs):
        """ Make sure we are allowed to handle the object. """
        # Get object resolver.
        result = backend.search(attribute="read_oid",
                                value=object_id.read_oid,
                                return_attributes=['resolver'])
        if not result:
            return False

        resolver_uuid = result[0]

        # If we are already the resolver everything is okay.
        if resolver_uuid == self.uuid:
            return True

        # We are not allowed to handle objects without resolver.
        if not resolver_uuid:
            return False

        x_resolver = backend.get_object(object_type="resolver",
                                        uuid=resolver_uuid)
        if not x_resolver:
            msg = ("Adopting %s from orphan resolver: %s"
                    % (object_id.object_type, object_id.name))
            logger.info(msg)
            if interactive:
                callback.send(msg)
            return "adopt"

        msg = ("Cannot import %s added by other resolver: %s: %s"
                % (object_id.object_type, object_id, x_resolver.name))
        logger.critical(msg)
        if interactive:
            callback.send(msg)

        return False

    def start_sync(self, object_types=None, test=False, interactive=None,
        daemon_run=False, verbose_level=0, callback=default_callback):
        """ Start import of objects from this resolver. """
        # Handle locking.
        try:
            sync_lock = locking.acquire_lock(LOCK_TYPE, self.lock_id, timeout=0)
        except LockWaitTimeout:
            return callback.error("This resolver is already running.")

        if test:
            if interactive is None:
                interactive = True
        else:
            if interactive is None:
                interactive = False

        # Used to return the sync status.
        sync_status = True

        # Get object via child class.
        try:
            result = self.fetch_objects(object_types=object_types,
                                        callback=callback)
        except Exception as e:
            msg = ("Failed to fetch objects with resolver: %s: %s"
                    % (self.name, e))
            logger.warning(msg)
            sync_lock.release_lock()
            return callback.error(msg)

        msg = "Processing objects..."
        callback.send(msg)
        logger.info(msg)

        # Count objects we got.
        all_objects = []
        all_remote_objects = {}
        all_local_objects = {}
        for object_type in self.object_types:
            if callback.stop_job:
                return callback.abort()
            if daemon_run:
                if not self.is_enabled:
                    break
                if not config.cluster_status:
                    break
                if config.master_failover:
                    break
                if not config.master_node:
                    break
            if object_type not in result:
                continue
            if not object_type in all_remote_objects:
                all_remote_objects[object_type] = []
            for x in result[object_type]:
                all_objects.append(x)
                all_remote_objects[object_type].append(x)

            if not self.sync_deletions:
                continue

            x_result = self.get_resolver_objects(object_types=[object_type])
            for x_type in x_result:
                if not x_type in all_local_objects:
                    all_local_objects[x_type] = []
                for x in x_result[x_type]:
                    all_local_objects[x_type].append(x)

        added_objects = []
        failed_objects = []
        updated_objects = []
        removed_objects = []
        skipped_objects = []
        unchanged_objects = []
        for object_type in self.object_types:
            if callback.stop_job:
                return callback.abort()
            if daemon_run:
                if not self.is_enabled:
                    break
                if not config.cluster_status:
                    break
                if config.master_failover:
                    break
                if not config.master_node:
                    break
            if object_type not in result:
                continue
            object_failed = False
            # Get attribute that will be mapped to the objects name.
            name_attribute = self.attribute_mappings[object_type]['name']
            # Get UUID attribute.
            try:
                uuid_attribute = self.attribute_mappings[object_type]['uuid']
            except:
                uuid_attribute = None
            try:
                uid_number_attribute = self.attribute_mappings[object_type]['uidNumber']
            except:
                uid_number_attribute = None
            try:
                gid_number_attribute = self.attribute_mappings[object_type]['gidNumber']
            except:
                gid_number_attribute = None

            attr_map_rev = {}
            for dst_attr in self.attribute_mappings[object_type]:
                src_attr = self.attribute_mappings[object_type][dst_attr]
                if src_attr == uid_number_attribute:
                    continue
                if src_attr == gid_number_attribute:
                    continue
                if src_attr == uuid_attribute:
                    continue
                if src_attr == name_attribute:
                    continue
                attr_map_rev[src_attr] = dst_attr

            class AddObject(object):
                def __init__(self, name, path, object_type, attributes):
                    self.name = name
                    self.path = path
                    self.attributes = attributes
                    self.object_type = object_type

                def __str__(self):
                    return self.name

                def __repr__(self):
                    if self.object_type == "unit":
                        return len(self.path)
                    return self.name

                def __hash__(self):
                    return hash(self.__str__())

                def __eq__(self, other):
                    return self.path == other.path

                def __ne__(self, other):
                    return self.path != other.path

                def __lt__(self, other):
                    return self.__repr__() < other.__repr__()

                def __gt__(self, other):
                    return self.__repr__() > other.__repr__()

            add_order = []
            for x in result[object_type]:
                x_attributes = result[object_type][x]
                x_path = x_attributes.pop('object_path')
                add_object = AddObject(name=x,
                                    path=x_path,
                                    object_type=object_type,
                                    attributes=x_attributes)
                add_order.append(add_object)

            for x in sorted(add_order):
                if callback.stop_job:
                    return callback.abort()
                if daemon_run:
                    if not self.is_enabled:
                        break
                    if not config.cluster_status:
                        break
                    if config.master_failover:
                        break
                    if not config.master_node:
                        break
                x_object = None
                x_name = x.name
                x_path = x.path
                x_attributes = x.attributes
                x_path = "/".join(x_path)
                x_path = "/%s/%s/%s" % (self.realm, self.site, x_path)
                x_resolver_key = x_attributes[self.key_attributes[object_type]]
                # Build checksum
                checksum_vals = []
                for a in sorted(x_attributes):
                    vals = x_attributes[a]
                    vals = sorted(vals)
                    checksum_vals.append("%s:%s" % (a, ",".join(vals)))
                x_resolver_checksum = stuff.gen_md5("\n".join(checksum_vals))

                # Get object name.
                if not name_attribute in x_attributes:
                    msg = (_("Got no name attribute: %s: %s")
                            % (x_name, name_attribute))
                    logger.warning(msg)
                    if interactive:
                        callback.error(msg)
                    failed_objects.append(x_name)
                    sync_status = False
                    object_failed = True
                    continue

                # Get UUID value.
                x_uuid = None
                if uuid_attribute:
                    x_uuid = x_attributes[uuid_attribute]
                    x_attributes.pop(uuid_attribute)

                # Get uidNumber value.
                x_uid_number = None
                if uid_number_attribute:
                    x_uid_number = x_attributes.pop(uid_number_attribute)
                    if isinstance(x_uid_number, list):
                        if len(x_uid_number) > 1:
                            msg = (_("Got multiple values for uidNumber: %s: %s")
                                    % (x_name, ",".join(x_uid_number)))
                            logger.warning(msg)
                            if interactive:
                                callback.error(msg)
                            failed_objects.append(x_name)
                            sync_status = False
                            object_failed = True
                            continue
                        x_uid_number = x_uid_number[0]
                    x_uid_number = int(x_uid_number)

                # Check if the object already exists.
                x_result = backend.search(attribute="resolver_key",
                                        value=x_resolver_key,
                                        return_type="oid")
                add_object = False
                update_object = False
                if x_result:
                    x_oid = x_result[0]
                    # Check if we are allowed to handle the object.
                    resolver_valid = self.check_object_resolver(x_oid,
                                                    interactive=interactive,
                                                    callback=callback)
                    if not resolver_valid:
                        msg = "Skipping object: %s" % x_oid
                        logger.info(msg)
                        skipped_objects.append(x_oid)
                        continue

                    if resolver_valid == "adopt":
                        update_object = True

                    if not update_object:
                        checksum_result = backend.search(attribute="read_oid",
                                    value=x_oid.read_oid,
                                    return_attributes=['resolver_checksum'])
                        if not checksum_result:
                            continue

                        x_checksum = checksum_result[0]

                        # Skip unchanged objects.
                        if x_checksum == x_resolver_checksum:
                            unchanged_objects.append(x_oid)
                            continue

                    # Get object.
                    x_object = backend.get_object(object_id=x_oid)
                    update_object = True

                else:
                    if object_type == "user":
                        object_class = User
                    elif object_type == "group":
                        object_class = Group
                    elif object_type == "unit":
                        object_class = Unit
                    else:
                        failed_objects.append(x_name)
                        sync_status = False
                        object_failed = True
                        msg = ("Got unsupported object from resolver: %s: %s"
                                % (object_type, x_name))
                        logger.critical(msg)
                        if interactive:
                            callback.error(msg)
                        continue

                    if test:
                        if self.sync_units and object_type != "unit":
                            if object_types and "unit" not in object_types:
                                unit_path = "/".join(x_path.split("/")[3:-1])
                                unit = backend.get_object(object_type="unit",
                                                        rel_path=unit_path,
                                                        realm=self.realm,
                                                        site=self.site)
                                if not unit:
                                    msg = "Would not add object: Unit missing: %s" % x_name
                                    callback.send(msg)
                                    continue

                    # Try to create object instance.
                    if test:
                        x_path = None

                    if not self.sync_units:
                        x_path = None

                    try:
                        x_object = object_class(name=x_name,
                                                path=x_path,
                                                site=config.site,
                                                realm=config.realm)
                    except Exception as e:
                        failed_objects.append(x_name)
                        sync_status = False
                        object_failed = True
                        msg = ("Unable to import %s: %s: %s"
                                % (object_type, x_name, e))
                        logger.critical(msg)
                        if interactive:
                            callback.error(msg)
                        continue

                    if x_object.exists():
                        resolver_valid = self.check_object_resolver(x_object.oid,
                                                                    interactive=interactive,
                                                                    callback=callback)
                        if not resolver_valid:
                            skipped_objects.append(x_object.oid)
                            continue
                        if resolver_valid != "adopt":
                            skipped_objects.append(x_object.oid)
                            continue
                        update_object = True
                    else:
                        if x_uuid:
                            for t in config.tree_object_types:
                                u_object = backend.get_object(object_type=t,
                                                                uuid=x_uuid)
                                if u_object:
                                    failed_objects.append(x_name)
                                    sync_status = False
                                    object_failed = True
                                    msg = ("UUID conflict: %s <> %s: %s"
                                        % (x_name, u_object.oid, x_uuid))
                                    logger.critical(msg)
                                    if interactive:
                                        callback.error(msg)
                                    continue
                        add_object = True

                    if add_object:
                        added_objects.append(x_object.oid)
                        if test:
                            msg = (_("Would add %s: %s (%s/%s)")
                                    % (object_type, x_name,
                                    len(added_objects), len(all_objects)))
                        else:
                            msg = (_("Adding %s: %s (%s/%s)")
                                    % (object_type, x_name,
                                    len(added_objects), len(all_objects)))
                        logger.info(msg)
                        if interactive:
                            callback.send(msg)
                        group = None
                        if object_type == "user":
                            try:
                                group = x_attributes.pop('object_group')
                            except KeyError:
                                group = None
                        # Try to add object.
                        if not test:
                            # Add default attributes.
                            base_attributes = {}
                            posix_attributes = {}
                            if x_uid_number:
                                posix_attributes['uidNumber'] = x_uid_number
                            default_attributes = {
                                                'base' : base_attributes,
                                                'posix': posix_attributes,
                                                }
                            try:
                                x_object.add(uuid=x_uuid,
                                        group=group,
                                        no_token_infos=True,
                                        extensions=['posix'],
                                        resolver=self.uuid,
                                        creator=self.uuid,
                                        verify_acls=False,
                                        default_attributes=default_attributes,
                                        callback=callback)
                            except Exception as e:
                                config.raise_exception()
                                failed_objects.append(x_name)
                                sync_status = False
                                object_failed = True
                                msg = ("Unable to add %s: %s: %s"
                                        % (object_type, x_name, e))
                                logger.critical(msg)
                                if interactive:
                                    callback.error(msg)
                                continue
                    else:
                        if not test:
                            x_object._write()

                    # Write modified objects (e.g. groups)
                    callback.write_modified_objects()
                    # Release cached locks.
                    callback.release_cache_locks()

                    # Skip unchanged objects.
                    if not update_object:
                        if x_object.resolver_checksum == x_resolver_checksum:
                            unchanged_objects.append(x_object.oid)
                            continue

                if update_object:
                    if test:
                        msg = (_("Would update %s: %s (%s/%s)")
                            % (object_type,
                            x_object.name,
                            (len(updated_objects)+1),
                            len(all_objects)))
                    else:
                        msg = (_("Updating %s: %s (%s/%s)")
                            % (object_type,
                            x_object.name,
                            (len(updated_objects)+1),
                            len(all_objects)))
                    if interactive:
                        callback.send(msg)
                    else:
                        logger.info(msg)

                    # Make sure the object references to us (e.g. after adoption)
                    if not test:
                        adopted = False
                        if x_object.resolver != self.uuid:
                            x_object.set_resolver(self.uuid)
                            adopted = False
                        if x_object.resolver_key != x_resolver_key:
                            x_object.set_resolver_key(x_resolver_key)
                            adopted = False
                        if adopted:
                            try:
                                x_object._write()
                            except Exception as e:
                                sync_status = False
                                object_failed = True
                                failed_objects.append(x_object.oid)
                                msg = (_("Failed to update %s resolver: %s: %s")
                                        % (object_type, x_object.name, e))
                                logger.critical(msg)
                                if interactive:
                                    callback.error(msg)
                                continue

                    # Check if we have to rename the object.
                    if x_object.name != x_name:
                        if test:
                            msg = (_("Would rename %s: %s -> %s")
                                    % (object_type, x_object.name, x_name))
                        else:
                            msg = (_("Renaming %s: %s -> %s")
                                    % (object_type, x_object.name, x_name))
                        if interactive:
                            callback.send(msg)
                        else:
                            logger.info(msg)

                        if not test:
                            # Try to rename object.
                            try:
                                x_object.rename(new_name=x_name, verify_acls=False)
                            except Exception as e:
                                sync_status = False
                                object_failed = True
                                failed_objects.append(x_object.oid)
                                msg = (_("Failed to rename %s: %s: %s")
                                        % (object_type, x_object.name, e))
                                logger.critical(msg)
                                if interactive:
                                    callback.error(msg)
                                continue

                # Add/Update object attributes.
                del_attrs = []
                for a in attr_map_rev:
                    nv = x_attributes[a]
                    if not isinstance(nv, list):
                        nv = [nv]

                    # Handle removed attributes.
                    if a not in x_attributes:
                        del_attrs.append(a)
                        continue
                    if not nv:
                        del_attrs.append(a)

                    try:
                        oa = attr_map_rev[a]
                    except:
                        # Skip attributes without mapping.
                        continue

                    get_current_values = True
                    if test and add_object:
                        cv = []
                        get_current_values = False

                    if get_current_values:
                        try:
                            cv = x_object.get_attribute(oa)
                        except Exception as e:
                            sync_status = False
                            object_failed = True
                            msg = "Unable to handle attribute: %s: %s" % (oa, e)
                            logger.warning(msg)
                            if interactive:
                                callback.error(msg)
                            continue

                    add_values = []
                    del_values = []
                    for xv in nv:
                        if xv in cv:
                            continue
                        add_values.append(xv)

                    for xv in cv:
                        if xv in nv:
                            continue
                        del_values.append(xv)

                    # We first add new attributes to be able to remove a
                    # mandatory attribute afterwards.
                    for av in add_values:
                        if test:
                            msg = (_("Would add attribute: %s: %s") % (oa, av))
                        else:
                            msg = (_("Adding attribute: %s: %s") % (oa, av))
                            if oa in self.id_attributes:
                                av = int(av)
                        if interactive:
                            if verbose_level > 1:
                                callback.send(msg)
                        else:
                            logger.info(msg)

                        if not test:
                            try:
                                x_object.add_attribute(attribute=oa,
                                                        value=av,
                                                        verify_acls=False)
                            except Exception as e:
                                sync_status = False
                                object_failed = True
                                msg = "Unable to add attribute: %s: %s" % (a, e)
                                logger.warning(msg)
                                if interactive:
                                    callback.error(msg)
                                continue

                    # Single values attribute need no deletion.
                    single_val = config.ldap_attribute_types[oa].single_value
                    if single_val:
                        continue

                    for dv in del_values:
                        if test:
                            msg = (_("Would remove attribute: %s: %s")
                                    % (oa, dv))
                        else:
                            msg = (_("Removing attribute: %s: %s")
                                    % (oa, dv))
                        if interactive:
                            if verbose_level > 1:
                                callback.send(msg)
                        else:
                            logger.info(msg)

                        if not test:
                            try:
                                x_object.del_attribute(attribute=oa,
                                                        value=dv,
                                                        verify_acls=False)
                            except MandatoryAttribute as e:
                                pass
                            except Exception as e:
                                sync_status = False
                                object_failed = True
                                msg = (_("Unable to delete attribute: %s: %s: %s")
                                        % (x_object.oid, a, e))
                                logger.warning(msg)
                                if interactive:
                                    callback.error(msg)
                                continue

                for a in del_attrs:
                    if a not in x_object.ldif_attributes:
                        continue
                    if test:
                        msg = (_("Would remove attribute: %s") % a)
                    else:
                        msg = (_("Removing attribute: %s") % a)
                    if interactive:
                        if verbose_level > 1:
                            callback.send(msg)
                    else:
                        logger.info(msg)
                    if not test:
                        try:
                            x_object.del_attribute(attribute=a,
                                                verify_acls=False)
                        except MandatoryAttribute as e:
                            pass
                        except Exception as e:
                            sync_status = False
                            object_failed = True
                            msg = (_("Unable to delete attribute: %s: %s: %s")
                                    % (x_object.oid, a, e))
                            logger.warning(msg)
                            if interactive:
                                callback.error(msg)
                            continue

                if test:
                    continue

                if object_failed:
                    failed_objects.append(x_name)
                    continue

                if update_object:
                    updated_objects.append(x_object.oid)

                logger.debug("Updating resolver checksum: %s"
                            % x_object.oid)
                x_object.set_resolver_key(x_resolver_key)
                x_object.set_resolver_checksum(x_resolver_checksum)
                x_object._write()

        # Delete orphan objects.
        for object_type in all_local_objects:
            for x in all_local_objects[object_type]:
                if callback.stop_job:
                    return callback.abort()
                if daemon_run:
                    if not self.is_enabled:
                        break
                    if not config.cluster_status:
                        break
                    if config.master_failover:
                        break
                    if not config.master_node:
                        break
                if x in all_remote_objects[object_type]:
                    continue

                x_oid = oid.OTPmeOid(object_type=object_type,
                                realm=config.realm,
                                site=config.sitem,
                                name=x)
                if test:
                    msg = (_("Would remove %s: %s") % (object_type, x_oid))
                else:
                    msg = (_("Removing %s: %s") % (object_type, x_oid))

                logger.info(msg)

                if interactive:
                    callback.send(msg)

                if test:
                    continue

                # Try to remove object.
                x_object = backend.get_object(object_id=x_oid)
                try:
                    x_object.delete(force=True, verify_acls=False)
                    removed_objects.append(x_oid)
                except Exception as e:
                    sync_status = False
                    msg = (_("Failed to delete %s: %s: %s")
                            % (object_type, x_oid, e))
                    logger.warning(msg)
                    if interactive:
                        callback.error(msg)

        # Release lock.
        sync_lock.release_lock()

        if sync_status:
            main_msg = "Sync successful"
        else:
            main_msg = "Sync with errors"

        if not added_objects and not updated_objects \
        and not removed_objects and not failed_objects:
            msg = (_("%s. Nothing changed.") % main_msg)
        else:
            msg = (_("%s: adds: %s updates: %s: "
            "removes: %s failed: %s skipped: %s unchanged: %s")
            % (main_msg, len(added_objects), len(updated_objects),
            len(removed_objects), len(failed_objects),
            len(skipped_objects), len(unchanged_objects)))
        logger.info(msg)

        if not sync_status:
            return callback.error(msg)

        return callback.ok(msg)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(self, ldap_template=None, verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Add a resolver. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()

        # Update index.
        self.add_index('resolver_type', self.resolver_type)

        # Call child class method (to do token specific stuff):
        self._add(_caller=_caller,
                callback=callback,
                verbose_level=verbose_level,
                **kwargs)

        if ldap_template:
            if ldap_template not in self.templates:
                msg = "Unknown template: %s" % ldap_template
                return callback.error(msg)
            for x in self.templates[ldap_template]:
                val = self.templates[ldap_template][x]
                setattr(self, x, val)

        # New resolvers should be disabled to allow the admin to
        # manually sync units and add policies etc. before syncing
        # any group/user.
        return OTPmeObject.add(self, enabled=False,
                                verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def rename(self, new_name, callback=default_callback, _caller="API", **kwargs):
        """ Rename resolver. """
        # Check if resolver is in use.
        try:
            rename_lock = locking.acquire_lock(LOCK_TYPE, self.lock_id, timeout=0)
        except LockWaitTimeout:
            return callback.error("This resolver is currently running.")

        # Build new OID.
        new_oid = oid.get(object_type="resolver",
                            realm=self.realm,
                            site=self.site,
                            unit=self.unit,
                            name=new_name)

        try:
            result = self._rename(new_oid=new_oid,
                                callback=callback,
                                _caller=_caller,
                                **kwargs)
        finally:
            # Release lock.
            rename_lock.release_lock()

        return result

    @check_acls(['sync_interval'])
    def set_sync_interval(self, sync_interval,
        callback=default_callback, **kwargs):
        """ Set resolver sync interval. """
        try:
            interval = units.time2int(sync_interval)
        except:
            msg = "Invalid sync interval: %s" % sync_interval
            return callback.error(msg)

        self.sync_interval = interval
        return self._cache(callback=callback)

    @check_acls(['get_objects'])
    def get_resolver_objects(self, object_types=[], return_type="name",
        run_policies=True, force=False, _caller="API",
        callback=default_callback, **kwargs):
        """ Get all resolver objects. """
        if run_policies:
            try:
                self.run_policies("get_resolver_objects",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not object_types:
            object_types = self.object_types

        result = {}
        for object_type in object_types:
            if object_type not in self.object_types:
                raise Exception("Unknown object type: %s" % object_type)

            object_list = backend.search(attribute="resolver",
                                        value=self.uuid,
                                        object_type=object_type,
                                        return_type=return_type)
            if not object_list:
                continue
            result[object_type] = object_list

        if _caller == "API":
            return result

        return callback.ok(result)

    @check_acls(['delete:objects'])
    def delete_objects(self, object_types=[], force=False,
        run_policies=True, verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete resolver objects. """
        if not object_types:
            object_types = self.object_types

        try:
            del_lock = locking.acquire_lock(LOCK_TYPE, self.lock_id, timeout=0)
        except LockWaitTimeout:
            return callback.error("This resolver is currently running.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("delete_objects",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Get all objects of this resolver.
        object_names = self.get_resolver_objects(object_types=object_types,
                                                return_type="name")
        if not force:
            exception = []
            if self.confirmation_policy != "force":
                for object_type in object_names:
                    object_count = len(object_names[object_type])
                    exception.append(_("Resolver '%(resolver_name)s' added "
                                    "%(object_count)s %(object_type)ss.")
                                    % {"resolver_name":self.name,
                                    "object_type":object_type,
                                    "object_count":object_count})
            if exception:
                if self.confirmation_policy != "force":
                    if self.confirmation_policy == "paranoid":
                        msg = (_("%s\nPlease type '%s' to delete objects: ")
                                % ("\n".join(exception), self.name))
                        ask = callback.ask(msg)
                        if ask != self.name:
                            del_lock.release_lock()
                            return callback.abort()
                    else:
                        msg = (_("%s\n%s") % ("\n".join(exception), "Delete objects?: "))
                        ask = callback.ask(msg)
                        if str(ask).lower() != "y":
                            del_lock.release_lock()
                            return callback.abort()

        all_objects = self.get_resolver_objects(object_types=object_types,
                                                return_type="instance")
        delete_status = True
        for object_type in reversed(all_objects):
            object_list = all_objects[object_type]
            for x in object_list:
                if callback.stop_job:
                    return callback.abort()
                msg = (_("Deleting %s: %s") % (object_type, x.oid))
                logger.debug(msg)
                callback.send(msg)
                try:
                    x.delete(force=True,
                            verify_acls=False,
                            callback=callback)
                except Exception as e:
                    config.raise_exception()
                    delete_status = False
                    msg = (_("Failed to delete %s: %s: %s")
                            % (object_type, x.oid, e))
                    logger.warning(msg)
                    callback.send(msg)

                # Write modified objects (e.g. groups)
                callback.write_modified_objects()
                # Release cached locks.
                callback.release_cache_locks()

        # Release lock.
        del_lock.release_lock()

        return delete_status

    @check_acls(['delete:object'])
    @object_lock(full_lock=True)
    @backend.transaction
    def delete(self, delete_objects=False, force=False, run_policies=True,
        verify_acls=True, verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete resolver. """
        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    if not self.sub_type:
                        msg = (_("Permission denied: %s") % self.name)
                        return callback.error(msg, exception=PermissionDenied)
                    sub_type_acl = "delete:%s:%s" % (self.type, self.sub_type)
                    if not parent_object.verify_acl(sub_type_acl,
                                    need_exact_acl=True):
                        msg = (_("Permission denied: %s") % self.name)
                        return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        try:
            del_lock = locking.acquire_lock(LOCK_TYPE, self.lock_id, timeout=0)
        except LockWaitTimeout:
            return callback.error("This resolver is currently running.")

        if not force:
            exception = []
            if self.confirmation_policy != "force":
                if not delete_objects:
                    all_objects = self.get_resolver_objects()
                    for object_type in all_objects:
                        object_count = len(all_objects[object_type])
                        exception.append(_("Resolver '%(resolver_name)s' added "
                                        "%(object_count)s: %(object_type)ss")
                                        % {"resolver_name":self.name,
                                        "object_type":object_type,
                                        "object_count":object_count})
            if exception:
                msg = (_("%s\n%s") % ("\n".join(exception), "Delete resolver "
                        "and all objects?: "))
                ask = callback.ask(msg)
                if str(ask).lower() == "y":
                    delete_objects = True

                if not delete_objects:
                    msg = (_("Delete resolver without objects?: "))
                    ask = callback.ask(msg)
                    if str(ask).lower() != "y":
                        del_lock.release_lock()
                        return callback.abort()
            else:
                if self.confirmation_policy == "paranoid":
                    ask = callback.ask(_("Delete resolver '%s'?: ") % self.name)
                    if str(ask).lower() != "y":
                        del_lock.release_lock()
                        return callback.abort()

        delete_status = True
        if delete_objects:
            delete_status = self.delete_objects(force=True,
                                        verbose_level=verbose_level,
                                        callback=callback)
            if not delete_status:
                if not force:
                    del_lock.release_lock()
                    return callback.error(msg)

        # Delete object using parent class.
        del_status = OTPmeObject.delete(self, verbose_level=verbose_level,
                                        force=force, callback=callback)

        if del_status is False or delete_status is False:
            del_lock.release_lock()
            return callback.error()

        # Release lock.
        del_lock.release_lock()

        return callback.ok()

    def show_config(self, config_lines="", callback=default_callback, **kwargs):
        """ Show resolver config. """
        lines = []

        if self.verify_acl("view:resolver_type"):
            lines.append('RESOLVER_TYPE="%s"' % self.resolver_type)
        else:
            lines.append('RESOLVER_TYPE=""')

        if self.verify_acl("view:sync_interval"):
            sync_interval = units.int2time(self.sync_interval)[0]
            lines.append('SYNC_INTERVAL="%s"' % sync_interval)
        else:
            lines.append('SYNC_INTERVAL=""')

        lines.append('SYNC_UNITS="%s"' % self.sync_units)

        key_attributes = []
        if self.verify_acl("view:key_attribute") \
        or self.verify_acl("edit:key_attribute"):
            for object_type in self.key_attributes:
                key_attr = self.key_attributes[object_type]
                key_attr_str = "%s[%s]" % (object_type, key_attr)
                key_attributes.append(key_attr_str)
        lines.append('KEY_ATTRIBUTES="%s"' % ",".join(key_attributes))

        last_run = self.get_last_used_time()
        if last_run:
            last_run = datetime.datetime.fromtimestamp(last_run)
            last_run = last_run.strftime('%d.%m.%Y %H:%M:%S')
        else:
            last_run = "Never"
        lines.append('LAST_RUN="%s"' % last_run)

        # Append lines from child class.
        lines += config_lines

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)
