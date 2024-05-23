# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

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
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.protocols.utils import register_commands
from otpme.lib.daemon.clusterd import cluster_radius_reload
from otpme.lib.classes.otpme_object import OTPmeClientObject
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

write_acls =  [
                "limit_logins",
                "unlimit_logins",
            ]

read_value_acls =    {
                    "view"      : [
                                "token",
                                "group",
                                "accessgroup",
                                "secret",
                                "address",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                "address",
                                ],
                    "delete"    : [
                                "address",
                                ],
                    "edit"      : [
                                "accessgroup",
                                "secret",
                                ],
                }

default_acls = []
recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : [],
                    'oargs'             : ['address', 'unit'],
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
                    'method'            : cli.show_getter("client"),
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
                    'method'            : cli.list_getter("client"),
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
                    'method'            : cli.list_getter("client"),
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
    'secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_secret',
                    'oargs'             : ['auto_secret', 'secret'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_secret',
                    'job_type'          : 'process',
                    },
                },
            },
    'access_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_access_group',
                    'args'              : ['access_group'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_address'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_address',
                    'args'              : ['address'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_address'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_address',
                    'args'              : ['address'],
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
    'limit_logins'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'limit_logins',
                    'job_type'          : 'thread',
                    },
                },
            },
    'unlimit_logins'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'unlimit_logins',
                    'job_type'          : 'thread',
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
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls',],
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

DEFAULT_UNIT = "clients"
REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                "otpme.lib.classes.group",
                ]

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("client", commands)
    # Register index attributes.
    config.register_index_attribute("address")

def register_hooks():
    config.register_auth_on_action_hook("client", "add_token")
    config.register_auth_on_action_hook("client", "remove_token")
    config.register_auth_on_action_hook("client", "add_address")
    config.register_auth_on_action_hook("client", "del_address")
    config.register_auth_on_action_hook("client", "change_secret")
    config.register_auth_on_action_hook("client", "change_access_group")
    config.register_auth_on_action_hook("client", "show_secret")
    config.register_auth_on_action_hook("client", "limit_logins")
    config.register_auth_on_action_hook("client", "unlimit_logins")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("client", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    client_name_re = '([0-9A-Za-z]([0-9A-Za-z_.-]*[0-9A-Za-z]){0,})'
    client_path_re = '%s[/]%s' % (unit_path_re, client_name_re)
    client_oid_re = 'client|%s' % client_path_re
    oid.register_oid_schema(object_type="client",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=client_name_re,
                            path_regex=client_path_re,
                            oid_regex=client_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="client",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    client_dir_extension = "client"
    def path_getter(client_oid):
        return backend.config_path_getter(client_oid, client_dir_extension)
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
        return backend.rebuild_object_index("client", objects, after)
    # Register object to config.
    config.register_object_type(object_type="client",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["host"],
                            sync_after=["user", "token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register index attributes.
    config.register_index_attribute('accessgroup')
    # Register object to backend.
    class_getter = lambda: Client
    backend.register_object_type(object_type="client",
                                dir_name_extension=client_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="client")

class Client(OTPmeClientObject):
    """ Creates client object """
    commands = commands
    def __init__(self, object_id=None, name=None, realm=None,
        unit=None, site=None, path=None, access_group=None, **kwargs):
        # Set our type (used in parent class).
        self.type = "client"

        # Call parent class init.
        super(Client, self).__init__(object_id=object_id,
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

        self.access_group = None
        self.access_group_uuid = None
        if access_group:
            self.change_access_group(access_group=access_group,
                                    verify_acls=False)

        self.secret = None
        self.secret_len = 32
        # Clients should not inherit ACLs by default.
        self.acl_inheritance_enabled = False
        self.logins_limited = False
        self.radius_reload = False

        self._sync_fields = {
                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "TOKENS",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'ADDRESSES'                 : {
                                                        'var_name'  : 'addresses',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'ACCESS_GROUP'              : {
                                                        'var_name'  : 'access_group_uuid',
                                                        'type'      : 'uuid',
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
                        'SECRET'    : {
                                                        'var_name'  : 'secret',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },
            }

        return super(Client, self)._get_object_config(object_config=object_config)

    def set_variables(self):
        """ Set instance variables. """
        if self.access_group_uuid:
            ag = backend.get_object(object_type="accessgroup",
                                    uuid=self.access_group_uuid,
                                    realm=self.realm,
                                    site=self.site)
            if ag:
                self.access_group = ag.name
        # Set OID.
        self.set_oid()

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string.
        name = str(name)
        # Only base clients must have uppercase names.
        base_clients = config.get_base_objects("client")
        if name.upper() in base_clients:
            self.name = name.upper()
        else:
            self.name = name.lower()

    def _write(self, **kwargs):
        """ Wrapper to make sure radius gets reloaded. """
        result = super(Client, self)._write(**kwargs)
        if not self.radius_reload:
            return result
        self.radius_reload = False
        cluster_radius_reload()
        return result

    # xxxxxxxxxxxxxxxxxxx
    # FIXME: check if IP is valid!!!
    @object_lock()
    @check_acls(['add:address'])
    def add_address(self, address, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Adds a address to this client. """
        if address in self.addresses:
            return callback.error(_("Address '%s' already added to this client.")
                                    % address)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_address",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.addresses.append(address)
        # Update index.
        self.add_index("address", address)
        # Make sure radius gets reloaded
        self.radius_reload = True
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['delete:address'])
    def del_address(self, address, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Deletes a address from this client. """
        if not address in self.addresses:
            return callback.error(_("Address '%s' is not an address of this client.")
                                    % address)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_address",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.addresses.remove(address)
        # Update index.
        self.del_index("address", address)
        # Make sure radius gets reloaded
        self.radius_reload = True
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['edit:accessgroup'])
    def change_access_group(self, access_group=None,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Change client access group. """
        from otpme.lib.classes.accessgroup import AccessGroup
        if access_group == self.access_group:
            return callback.error(_("Group '%s' is already access group of "
                                    "this client.") % access_group)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_access_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        if access_group:
            # Create access group instance.
            g = AccessGroup(name=access_group,
                            realm=self.realm,
                            site=self.site)
            if not g.exists():
                return callback.error(_("Group '%s' does not exist.")
                                        % self.access_group_uuid)
            # Append access group UUID to access groups.
            self.access_group_uuid = g.uuid
            self.access_group = g.name
            # Update Index.
            self.update_index('accessgroup', self.access_group_uuid)
        else:
            self.access_group_uuid = None
            self.access_group = None
            # Update Index.
            self.del_index('accessgroup')

        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['remove:orphans'])
    def remove_orphans(self, force=False, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
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
                callback.send(_("Removing orphan token UUID: %s" % i))
            object_changed = True
            if i in self.tokens:
                self.tokens.remove(i)
            if i in self.token_options:
                self.token_options.pop(i)

        if not object_changed:
            msg = None
            if verbose_level > 0:
                msg = (_("No orphan objects found for %s: %s")
                        % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    def rename(self, new_name, callback=default_callback, _caller="API", **kwargs):
        """ Rename client. """
        base_clients = config.get_base_objects("client")
        if self.name in base_clients:
            return callback.error("Cannot rename base client.")

        # Build new OID.
        new_oid = oid.get(object_type="client",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        result = self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)
        # Make sure radius gets reloaded
        self.radius_reload = True
        return result

    @object_lock(full_lock=True)
    @run_pre_post_add_policies()
    def add(self, address=None, verbose_level=0, callback=default_callback, **kwargs):
        """ Add a client. """
        if address:
            result = backend.search(object_type="client",
                                    attribute="address",
                                    value=address,
                                    return_type="name")
            if result:
                existing_client = result[0]
                msg = "Client with this address already exists: %s" % existing_client
                return callback.error(msg)

        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        self.secret = stuff.gen_secret(32)
        # Add object using parent class.
        add_result = super(Client, self).add(verbose_level=verbose_level,
                                            callback=callback, **kwargs)
        if not add_result:
            msg = "Failed to add client."
            return callback.error(msg)

        if address:
            self.add_address(address)
            msg = "Radius secret: %s" % self.secret
            callback.send(msg)
        # Make sure radius gets reloaded
        self.radius_reload = True
        return callback.ok()

    @object_lock(full_lock=True)
    def delete(self, force=False, run_policies=True, verify_acls=True,
        verbose_level=0, callback=default_callback, _caller="API", **kwargs):
        """ Delete client. """
        if not self.exists():
            return callback.error("Client does not exist exists.")

        base_clients = config.get_base_objects("client")
        if self.name in base_clients:
            return callback.error("Cannot delete base client.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                msg = "Please type '%s' to delete object: " % self.name
                answer = callback.ask(msg)
                if answer != self.name:
                    return callback.abort()
            else:
                answer = callback.ask(_("Delete client '%s'?: ") % self.name)
                if answer.lower() != "y":
                    return callback.abort()

        # Delete object using parent class.
        result = super(Client, self).delete(verbose_level=verbose_level,
                                        force=force, callback=callback)
        # Make sure radius gets reloaded.
        cluster_radius_reload()
        return result

    def show_config(self, callback=default_callback, **kwargs):
        """ Show client config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:token") \
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

        access_group = ""
        if self.verify_acl("view:accessgroup") \
        or self.verify_acl("edit:accessgroup"):
            access_group = str(self.access_group)
        lines.append('ACCESS_GROUP="%s"' % access_group)

        addresses = ""
        if self.verify_acl("view:address") \
        or self.verify_acl("add:address") \
        or self.verify_acl("remove:address"):
            addresses = ",".join(self.addresses)
        lines.append('ADDRESSES="%s"' % addresses)

        secret = ""
        if self.verify_acl("view_all:secret"):
            secret = str(self.secret)
        lines.append('SECRET="%s"' % secret)

        lines.append('TOKENS="%s"' % token_list)

        return super(Client, self).show_config(config_lines=lines,
                                        callback=callback, **kwargs)

    def show(self, **kwargs):
        """ Show client details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
