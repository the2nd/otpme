# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import List
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import cli
from otpme.lib import oid
from otpme.lib import net
from otpme.lib import host
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.pki import utils
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.host import update_ssl_files
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.register import register_module
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

default_callback = config.get_callback()

read_acls = []

write_acls = [
                'update_ca_data',
            ]

read_value_acls = {
                "view"      : [
                            "secret",
                            "status",
                            "auth",
                            "sync",
                            "master",
                            "ca",
                            "ca_data",
                            "alias",
                            ],
            }

write_value_acls = {
                "add"       : [
                            "alias",
                            "realm",
                            ],
                "delete"    : [
                            "alias",
                            ],
                "enable"    : [
                            "auth",
                            "sync",
                            ],
                "disable"   : [
                            "auth",
                            "sync",
                            ],
                "edit"      : [
                            "config",
                            "secret",
                            ],
}

default_acls = []

recursive_default_acls = []

commands = {
    'init'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'   : {
                    'method'            : 'init',
                    'args'              : [ 'realm_master', 'site_address', 'site_fqdn', ],
                    'oargs'             : [
                                            'ca_country',
                                            'ca_state',
                                            'ca_locality',
                                            'ca_organization',
                                            'ca_ou',
                                            'ca_email',
                                            'ca_key_len',
                                            'ca_valid',
                                            'site_key_len',
                                            'site_valid',
                                            'node_key_len',
                                            'node_valid',
                                            'no_dicts',
                                            'dictionaries',
                                            'id_ranges',
                                            'site_address',
                                            'site_fqdn',
                                            ],
                    'job_type'          : 'process',
                    },
                },
            },
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['realm_address'],
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
                    'method'            : cli.show_getter("realm"),
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
                    'method'            : cli.list_getter("realm"),
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
                    'method'            : cli.list_getter("realm"),
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
    'add_alias'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_alias',
                    'args'              : ['alias'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_alias'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_alias',
                    'args'              : ['alias'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls'],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls'],
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
    'dump_ca_data'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ca_data',
                    'job_type'          : 'process',
                    },
                },
            },
    'update_ca_data'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'update_ca_data',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_auth'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_auth',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_auth'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_auth',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_sync'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sync',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_sync'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sync',
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

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(**kwargs):
    return _get_value_acls(read_value_acls, write_value_acls, **kwargs)

def get_default_acls(**kwargs):
    return _get_default_acls(default_acls, **kwargs)

def get_recursive_default_acls(**kwargs):
    return _get_recursive_default_acls(recursive_default_acls, **kwargs)

ADMIN_USER = "root"
ADMIN_USER_ID = 0
ADMIN_GROUP = "root"
ADMIN_GROUP_ID = 0
ADMIN_USER_HOME = "/root"
ADMIN_TOKEN_TYPE = "totp"
REALM_CA = "REALM_CA"
SITE_CA = "SITE_CA"
TOKENSTORE_USER = "TOKENSTORE"
SITE_ADMIN_ROLE = "SITE_ADMIN"
REALM_USER_ROLE = "REALM_USER"
REALM_USERS_GROUP = "realmusers"

REALM_ACCESSGROUP = "REALM"
MGMT_ACCESSGROUP = "MGMT"
JOIN_ACCESSGROUP = "JOIN"

REGISTER_BEFORE = [
                    #"otpme.lib.classes.resolver",
                    #"otpme.lib.classes.policy",
                    #"otpme.lib.extensions",
                    #"otpme.lib.resolver",
                    #"otpme.lib.policy",
                    ]
REGISTER_AFTER = []

def register():
    register_dn()
    register_oid()
    register_hooks()
    register_config()
    register_backend()
    register_commands("realm", commands)
    register_module("otpme.lib.classes.resolver")
    register_module("otpme.lib.classes.policy")
    register_module("otpme.lib.extensions")
    register_module("otpme.lib.resolver")
    register_module("otpme.lib.policy")

def register_hooks():
    config.register_auth_on_action_hook("realm", "add_site")
    config.register_auth_on_action_hook("realm", "enable_sync")
    config.register_auth_on_action_hook("realm", "disable_sync")
    config.register_auth_on_action_hook("realm", "enable_auth")
    config.register_auth_on_action_hook("realm", "disable_auth")
    config.register_auth_on_action_hook("realm", "update_ca_data")

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("realm", "dc")

def register_config():
    """ Register config stuff. """
    # Base CAs that will be created for each realm/site and that cannot be deleted
    # or renamed.
    config.register_config_var("realm_ca", str, REALM_CA)
    config.register_config_var("site_ca", str, SITE_CA)
    # Register base CAs.
    config.register_base_object("ca", REALM_CA)
    config.register_base_object("ca", SITE_CA)

    # Admin user that will be added on realm creation.
    config.register_config_var("admin_user_name", str, ADMIN_USER)
    config.register_config_var("admin_user_uid", int, ADMIN_USER_ID)
    config.register_config_var("admin_user_home", str, ADMIN_USER_HOME)
    config.register_config_var("admin_user_token_type", str, ADMIN_TOKEN_TYPE)
    # Register base user.
    config.register_base_object("user", ADMIN_USER)

    # Base groups that will be created for each site and that cannot be deleted or
    # renamed.
    config.register_config_var("admin_group", str, ADMIN_GROUP)
    config.register_config_var("admin_group_gid", int, ADMIN_GROUP_ID)
    # Register base groups.
    config.register_base_object("group", ADMIN_GROUP)

    # Base access groups that will be created for each site and that cannot be
    # deleted or renamed.
    config.register_config_var("realm_access_group", str, REALM_ACCESSGROUP)
    config.register_config_var("mgmt_access_group", str, MGMT_ACCESSGROUP)
    config.register_config_var("join_access_group", str, JOIN_ACCESSGROUP)

    config.register_base_object("accessgroup", REALM_ACCESSGROUP)
    config.register_base_object("accessgroup", MGMT_ACCESSGROUP)
    config.register_base_object("accessgroup", JOIN_ACCESSGROUP)

    # Base roles that will be created for each site and that cannot be deleted or
    # renamed.
    config.register_config_var("site_admin_role", str, SITE_ADMIN_ROLE)
    config.register_config_var("realm_user_role", str, REALM_USER_ROLE)
    config.register_config_var("realm_users_group", str, REALM_USERS_GROUP)
    config.register_base_object("role", SITE_ADMIN_ROLE)
    config.register_base_object("role", REALM_USER_ROLE)
    config.register_base_object("group", REALM_USERS_GROUP)
    config.register_internal_object("group", REALM_USERS_GROUP)
    # Host auth key length.
    config.register_config_var("default_host_auth_key_len", int, 2048)
    # Register token store user as internal user.
    config.register_config_var("token_store_user", str, TOKENSTORE_USER)
    config.register_internal_object("user", TOKENSTORE_USER)
    # Register token store user as base user.
    config.register_base_object("user", TOKENSTORE_USER)
    # Register token store user as per site user.
    config.register_per_site_object("user", TOKENSTORE_USER)
    # Object types our config parameters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                    'token',
                    ]
    # Default password hash algo.
    config.register_config_parameter(name="default_pw_hash_type",
                                    ctype=str,
                                    default_value="Argon2_i",
                                    object_types=object_types)
    # Session password hash algo.
    config.register_config_parameter(name="session_hash_type",
                                    ctype=str,
                                    default_value="Argon2_i",
                                    object_types=object_types)
    # Session config parameters.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'host',
                    'node',
                    ]
    config.register_config_parameter(name="static_pass_timeout",
                                    ctype=int,
                                    default_value=15,
                                    object_types=object_types)
    config.register_config_parameter(name="static_pass_unused_timeout",
                                    ctype=int,
                                    default_value=5,
                                    object_types=object_types)

def register_oid():
    full_oid_schema = [ 'name' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    realm_path_re = '/%s' % realm_name_re
    realm_oid_re = 'realm|%s' % realm_path_re
    oid.register_oid_schema(object_type="realm",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=realm_name_re,
                            path_regex=realm_path_re,
                            oid_regex=realm_oid_re)
    def get_object_site(object_id):
        """ Get object site from ID. """
        return
    oid.register_site_getter(object_type="realm",
                        getter=get_object_site)

def register_backend():
    """ Register object for the file backend. """
    # The OID getter for tree objects is always the same, so we register it just
    # once in the realm object.
    from otpme.lib.classes.otpme_object import oid_getter
    objects_dir = backend.get_data_dir("objects")
    realm_dir_extension = "realm"
    def path_getter(object_id, object_uuid):
        # Get object realm.
        config_paths = {}
        config_dir_name = "%s.realm" % object_id.realm
        config_dir = os.path.join(objects_dir, config_dir_name)
        config_paths['config_dir'] = config_dir
        config_paths['rmtree_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild(objects):
        return backend.rebuild_object_index("realm", objects)
    class_getter = lambda: Realm
    # Register object to config.
    config.register_object_type(object_type="realm",
                            tree_object=True,
                            add_before=["site"],
                            sync_before=["site"],
                            uniq_name=True,
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm'])
    # Register object to backend.
    backend.register_object_type(object_type="realm",
                                dir_name_extension=realm_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

@match_class_typing
class Realm(OTPmeObject):
    """ OTPme realm object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        path: Union[str,None]=None,
        name: Union[str,None]=None,
        **kwargs,
        ):
        # set our type (used in parent class)
        self.type = "realm"
        # Call parent class init.
        super(Realm, self).__init__(object_id=object_id,
                                    name=name,
                                    path=path,
                                    **kwargs)
        # Set some defaults.
        self.own = False
        self.ca = None
        self.ca_data = None
        #self.aliases = []
        self.master = None
        self.auth_enabled = True
        self.sync_enabled = True

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "ADMIN_TOKEN",
                            "ALIASES",
                            "CA",
                            "CA_DATA",
                            "MASTER",
                            "OWN",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "SYNC_ENABLED",
                            "AUTH_ENABLED",
                            "dc",
                            "o",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "ADMIN_TOKEN",
                            "ALIASES",
                            "CERT",
                            "CA",
                            "CA_DATA",
                            "MASTER",
                            "OWN",
                            "ACLS",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "POLICIES",
                            "POLICY_OPTIONS",
                            "SYNC_ENABLED",
                            "AUTH_ENABLED",
                            "dc",
                            "o",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
            'REALM'                     : {
                                            'var_name'      : 'realm_uuid',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },

            'SITE'                      : {
                                            'var_name'      : 'site_uuid',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },

            'OWN'                       : {
                                            'var_name'  : 'own',
                                            'type'      : bool,
                                            'required'  : True,
                                        },

            'MASTER'                    : {
                                            'var_name'  : 'master',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'CA'                        : {
                                            'var_name'  : 'ca',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'CA_DATA'                   : {
                                            'var_name'  : 'ca_data',
                                            'type'      : str,
                                            'required'  : False,
                                            'encoding'  : 'BASE64',
                                        },

            'SECRET'                   : {
                                            'var_name'  : 'secret',
                                            'type'      : str,
                                            'required'  : False,
                                            'encryption': config.disk_encryption,
                                        },

            'ALIASES'                   : {
                                            'var_name'  : 'aliases',
                                            'type'      : list,
                                            'required'  : False,
                                        },

            'AUTH_ENABLED'              : {
                                            'var_name'  : 'auth_enabled',
                                            'type'      : bool,
                                            'required'  : False,
                                        },


            'SYNC_ENABLED'              : {
                                            'var_name'  : 'sync_enabled',
                                            'type'      : bool,
                                            'required'  : False,
                                        },
            }

        return object_config

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = name.lower()

    def set_variables(self):
        """ Set instance variables. """
        if self.uuid == config.realm_uuid:
            self.own = True
        else:
            self.own = False

    @check_acls(['enable:auth'])
    @object_lock()
    @backend.transaction
    def enable_auth(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable authentication with the realm. """
        if self.auth_enabled:
            msg = (_("Authentication with realm '%s' is already enabled.")
                    % self.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_auth",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.own:
                answer = callback.ask(_("Enable authentication for own realm? "))
                if answer.lower() != "y":
                    return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    msg = (_("Enable authentication with realm '%s'?: ")
                            % self.name)
                    answer = callback.ask(msg)
                    if answer.lower() != "y":
                        return callback.abort()

        self.auth_enabled = True
        self.update_index("auth_enabled", self.auth_enabled)

        return self._write(callback=callback)

    @check_acls(['disable:auth'])
    @object_lock()
    @backend.transaction
    def disable_auth(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable authentication with the realm. """
        if self.own:
            msg = (_("Cannot disable authentication for own realm."))
            return callback.error(msg)

        if not self.auth_enabled:
            msg = (_("Authentication with realm '%s' is already disabled.")
                        % self.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_auth",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.confirmation_policy != "force":
                msg = (_("Disable authentication with realm '%s'?: ")
                            % self.name)
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        if not self.auth_enabled:
            msg = (_("Authentication with realm '%s' is already disabled.")
                        % self.name)
            return callback.error(msg)

        self.auth_enabled = False
        self.update_index("auth_enabled", self.auth_enabled)

        return self._write(callback=callback)

    @check_acls(['enable:sync'])
    @object_lock()
    @backend.transaction
    def enable_sync(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable synchronization with the realm. """
        if self.sync_enabled:
            msg = (_("Synchronization with realm '%s' is already enabled.")
                        % self.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sync",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.confirmation_policy != "force":
                msg = (_("Enable synchronization with realm '%s'?: ")
                            % self.name)
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        self.sync_enabled = True
        self.update_index("sync_enabled", self.sync_enabled)

        return self._write(callback=callback)

    @check_acls(['disable:sync'])
    @object_lock()
    @backend.transaction
    def disable_sync(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable synchronization with the realm. """
        if self.own:
            msg = (_("Cannot disable synchronization for own realm."))
            return callback.error(msg)

        if not self.sync_enabled:
            msg = (_("Synchronization with realm '%s' is already disabled.")
                        % self.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sync",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.confirmation_policy != "force":
                msg = (_("Disable synchronization with realm '%s'?: ")
                            % self.name)
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        self.sync_enabled = False
        self.update_index("sync_enabled", self.sync_enabled)

        return self._write(callback=callback)

    @object_lock()
    @backend.transaction
    def add_alias(
        self,
        alias: str,
        callback=default_callback,
        **kwargs,
        ):
        """ Add an realm alias. """
        if not self.verify_acl(acl="add:alias", check_admin_role=False):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        if alias == self.name:
            msg = (_("Cannot add alias with the same name as this realm."))
            return callback.error(msg)
        if alias in self.aliases:
            msg = (_("Alias '%s' already added to this realm.") % alias)
            return callback.error(msg)

        self.aliases.append(alias)
        self.add_index("alias", alias)

        return self._write(callback=callback)

    @object_lock()
    @backend.transaction
    def del_alias(
        self,
        alias: str,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Deletes an alias from this realm. """
        if not self.verify_acl(acl="delete:alias", check_admin_role=False):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        if not alias in self.aliases:
            msg = (_("Alias '%s' is not an alias of this realm.") % alias)
            return callback.error(msg)

        self.aliases.remove(alias)
        self.del_index("alias", alias)

        return self._write(callback=callback)

    def get_ca_data(
        self,
        verify_acls: bool=True,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Get realms CA data. """
        if verify_acls:
            if not self.verify_acl(acl="view:ca_data", check_admin_role=False):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)
        return callback.ok(self.ca_data)

    @object_lock(full_lock=True)
    @backend.transaction
    def update_ca_data(
        self,
        verify_acls: bool=True,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Update realm's ca data (e.g. cert chains and CRL's). """
        if verify_acls:
            if not self.verify_acl(acl="update_ca_data", check_admin_role=False):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("update_ca_data",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not self.ca:
            if config.realm_init:
                return
            msg = ("Realm got no CA. This should not happen. :(")
            return callback.error(msg)

        realm_ca = backend.get_object(object_type="ca", uuid=self.ca)

        if not realm_ca:
            if config.realm_init:
                return
            msg = ("Missing realm CA. This should not happen. :(")
            return callback.error(msg)

        ca_data = ""
        ca_data = "%s%s" % (ca_data, realm_ca.cert)
        if realm_ca.crl:
            ca_data = "%s%s" % (ca_data, realm_ca.crl)

        # Get list of all sites.
        site_list = backend.search(object_type="site",
                                    attribute="uuid",
                                    value="*",
                                    return_type="instance",
                                    realm=self.name)
        for site in site_list:
            # Skip sites that do not have a CA yet.
            if not site.ca:
                continue
            site_ca = backend.get_object(object_type="ca", uuid=site.ca)
            if not site_ca:
                msg = (_("Uuuuh missing site CA: %s") % site.ca)
                return callback.error(msg)
            if site_ca.cert:
                ca_data = "%s%s" % (ca_data, site_ca.cert)
            if site_ca.crl:
                ca_data = "%s%s" % (ca_data, site_ca.crl)

        if self.ca_data == ca_data:
            return callback.ok()

        # Set new ca_data.
        self.ca_data = ca_data

        # Update CA data in ssl files.
        update_ssl_files(ca_data=ca_data)

        return self._write(callback=callback)

    @object_lock(full_lock=True)
    def init(
        self,
        realm_master: str,
        site_fqdn: str,
        site_address: Union[str,None]=None,
        ca_key_len: Union[int,None]=None,
        ca_valid: Union[int,None]=None,
        ca_country: Union[str,None]=None,
        ca_state: Union[str,None]=None,
        ca_locality: Union[str,None]=None,
        ca_organization: Union[str,None]=None,
        ca_ou: Union[str,None]=None,
        ca_email: Union[str,None]=None,
        site_key_len: Union[int,None]=None,
        site_valid: Union[int,None]=None,
        node_key_len: Union[int,None]=None,
        id_ranges: Union[str,None]=None,
        no_dicts: bool=False,
        dictionaries: List=[],
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Init OTPme realm. """
        from otpme.lib.classes.site import Site
        if ca_valid is None:
            ca_valid = config.default_ca_validity
        if ca_key_len is None:
            ca_key_len = config.default_ca_key_len
        if site_valid is None:
            site_valid = config.default_site_validity
        if site_key_len is None:
            site_key_len = config.default_site_key_len
        if node_key_len is None:
            node_key_len = config.default_node_key_len
        # Check if we do not already have our own realm.
        if config.realm:
            msg = ("We already have our realm initialized. :)")
            return callback.error(msg)

        # Make sure there are not already objects in our realm.
        for t in config.tree_object_types:
            object_list = backend.search(realm=self.name,
                                        attribute="name",
                                        value="*",
                                        object_type=t,
                                        return_type="name")
            if len(object_list) > 0:
                msg = (_("Found %(object_type)ss for realm '%(realm_name)s'. "
                        "Cannot initialize realm.")
                        % {"object_type":t , "realm_name":self.name})
                return callback.error(msg)

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        if not site_address:
            # Try to get site address from DNS.
            result = net.query_dns(site_fqdn)
            if len(result) > 1:
                msg = "Found round-robin DNS. Please give floating IP."
                return callback.error(msg)
            site_address = result[0]

        # We always need a site address as floaging cluster IP.
        if not site_address:
            msg = ("Unable to resolve: %s" % site_fqdn)
            raise OTPmeException(msg)

        if site_address != "127.0.0.1":
            # Make sure we got a valid site address.
            callback.send("Verifying floaging IP: %s" % site_address)
            try:
                net.configure_floating_ip(site_address, gratuitous_arp=False)
            except AddressAlreadyAssigned as e:
                raise
            except Exception as e:
                msg = (_("Unable to configure floaging IP: %s: %s")
                        % (site_address, e))
                raise OTPmeException(msg)
            # Deconfigure floating IP after testing.
            net.deconfigure_floating_ip(site_address)

        # Generate master key before writing first object config..
        if config.key_command.startswith("file://"):
            try:
                config.gen_master_key(skip_if_exists=True,
                                master_pass=config.stdin_pass)
            except Exception as e:
                config.raise_exception()
                msg = (_("Error generating master key: %s") % e)
                return callback.error(msg)

        # Set UUID for our own realm.
        self.uuid = stuff.gen_uuid()
        # Set UUID of the master node.
        config.uuid = stuff.gen_uuid()

        # Generate global password salt.
        try:
            config.set_password_salt()
        except Exception as e:
            msg = (_("Error generating password salt: %s") % e)
            return callback.error(msg)

        # Write our realm.
        self._write(callback=callback)

        # Set config realm.
        config.set_realm(name=self.name, uuid=self.uuid)
        # Set site name.
        config.site = realm_master

        # Create our master site.
        master_site = Site(name=realm_master, realm=config.realm)

        if master_site.exists():
            msg = ("Uuuhhh, our master site already exists.")
            return callback.error(msg)

        msg = (_("Adding site '%(realm_master)s' with address "
                    "'%(site_address)s' as realm master.")
                    % {"realm_master":realm_master,
                    "site_address":site_address})
        callback.send(msg)

        # Get node address from the host we are running on.
        import socket
        node_name = socket.gethostname()

        # Set our host type to "node" on realm init to prevent any issues (e.g.
        # CHECKSUM calculation in backend)
        if not config.host_data['type']:
            config.host_data['type'] = 'node'

        # Add our first site without initializing CA.
        add_status = master_site.add(site_fqdn=site_fqdn,
                                    site_address=site_address,
                                    node_name=node_name,
                                    no_ca=True,
                                    no_node=True,
                                    verify_acls=False,
                                    id_ranges=id_ranges,
                                    no_dicts=no_dicts,
                                    dictionaries=dictionaries,
                                    callback=callback,
                                    **kwargs)
        if not add_status:
            return callback.error("Error creating master site.")

        # Write objects.
        cache.flush()

        config.set_site(name=master_site.name,
                        uuid=master_site.uuid,
                        address=master_site.address,
                        auth_fqdn=site_fqdn,
                        mgmt_fqdn=site_fqdn)
        # Make this site our master.
        self.master = master_site.uuid

        if not self._write(callback=callback):
            msg = ("Error writing realm config")
            return callback.error(msg)

        # Create realm CA.
        from otpme.lib.classes.ca import Ca
        msg = (_("Adding realm CA '%s'.") % config.realm_ca_path)
        callback.send(msg)

        realm_ca = Ca(path=config.realm_ca_path)
        if realm_ca.exists():
            msg = ("Uuuhhh, realm CA already exists.")
            return callback.error(msg)

        if not realm_ca.add(cn=config.realm_ca_path,
                            country=ca_country,
                            state=ca_state,
                            locality=ca_locality,
                            organization=ca_organization,
                            ou=ca_ou, email=ca_email,
                            key_len=ca_key_len, valid=ca_valid,
                            callback=callback, **kwargs):
            msg =(_("Problem adding realm CA '%s'.") % config.realm_ca_path)
            return callback.error(msg)

        # Write objects.
        cache.flush()

        # Set realm CA.
        self.ca = realm_ca.uuid

        # Create site CA.
        if not master_site.create_site_ca(ca_country=ca_country,
                                        ca_state=ca_state,
                                        ca_locality=ca_locality,
                                        ca_organization=ca_organization,
                                        ca_ou=ca_ou, ca_email=ca_email,
                                        ca_key_len=ca_key_len,
                                        ca_valid=ca_valid,
                                        site_key_len=site_key_len,
                                        site_valid=site_valid,
                                        callback=callback,
                                        **kwargs):
            msg = ("Unable to create master site CA.")
            return callback.error(msg)

        # Write objects.
        cache.flush()

        # Generate CSR.
        site_ca = backend.get_object(object_type="ca", uuid=master_site.ca)
        master_node_fqdn = "%s.%s.%s" % (node_name, master_site.name, self.name)
        cert_req, host_key = utils.create_csr(master_node_fqdn,
                                            country=site_ca.country,
                                            state=site_ca.state,
                                            locality=site_ca.locality,
                                            organization=site_ca.organization,
                                            ou=site_ca.ou,
                                            email=site_ca.email,
                                            key_len=node_key_len)

        # Generate master node auth key.
        _host_key = RSAKey(bits=config.default_host_auth_key_len)
        host_public_key = _host_key.public_key_base64
        host_private_key = _host_key.private_key_base64

        # Create site master node.
        if not master_site.create_master_node(node_name=node_name,
                                            public_key=host_public_key,
                                            cert_req=cert_req,
                                            uuid=config.uuid,
                                            gen_jotp=False,
                                            callback=callback,
                                            **kwargs):
            msg = ("Unable to create master node.")
            return callback.error(msg)

        # Write objects.
        cache.flush()

        # Update CA data.
        if not self.update_ca_data(verify_acls=False,
                                    callback=callback,
                                    **kwargs):
            msg = ("Unable to update realm CA data.")
            return callback.error(msg)

        # Add realm object using parent class. This will also assing policies
        # that we needed to assign e.g. uid/gid when creating base objects below.
        OTPmeObject.add(self)

        # Write objects.
        cache.flush()

        # Add default config parameters.
        for parameter in config.valid_config_params:
            default_value = config.valid_config_params[parameter]['default']
            self.set_config_param(parameter, default_value)

        # Write objects.
        cache.flush()

        # Add realm default policies. We do not use self.add_default_policies()
        # here because only our own realm will get default policies.
        default_policies = config.get_default_policies(self.type)
        for policy_name in default_policies:
            result = backend.search(attribute="name",
                                    value=policy_name,
                                    object_type="policy",
                                    return_type="instance",
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                callback.send(_("Unknown default policy: %s") % policy_name)
                continue
            policy = result[0]
            if policy.uuid in self.policies:
                continue
            self.add_policy(policy.name, verify_acls=False)

        # Write objects.
        cache.flush()

        # Finalize base object creation.
        master_site.add_base_objects(callback=callback)
        master_site.add_base_groups(callback=callback)
        master_site.add_per_site_objects(callback=callback)

        # Write objects.
        cache.flush()

        # Get admin token.
        admin_token = backend.get_object(object_type="token",
                                uuid=config.admin_token_uuid)

        # Set admin token as site admin token.
        master_site.admin_token_uuid = admin_token.uuid

        # Add ACLs to view public realm infos.
        realm_user_role = backend.get_object(object_type="role",
                                    uuid=master_site.user_role_uuid)
        site_admin_role = backend.get_object(object_type="role",
                                    uuid=master_site.admin_role_uuid)
        realm_users_group = backend.get_object(object_type="group",
                                    uuid=master_site.realm_users_group_uuid)
        view_objects = [ realm_user_role, site_admin_role, realm_users_group ]
        for o in view_objects:
            acl = "role:%s:view_public" % o.uuid
            self.add_acl(acl=acl,
                        recursive_acls=False,
                        apply_default_acls=False,
                        verify_acls=False)

        # Finally write the realm config.
        self._write(callback=callback)

        # Set site as enabled.
        master_site.enable(force=True, run_policies=False)
        master_site._write(callback=callback)

        # Write objects.
        cache.flush()

        # Get master node.
        result = backend.search(object_type="node",
                                attribute="name",
                                value=node_name,
                                return_type="instance")
        first_node = result[0]

        # Update host key files.
        host.update_data(host_cert=first_node.cert,
                        host_key=host_key,
                        host_auth_key=host_private_key,
                        ca_data=self.ca_data,
                        site_cert=master_site.cert)

        # Add default policies to master node.
        default_policies = config.get_default_policies(first_node.type)
        for policy_name in default_policies:
            result = backend.search(attribute="name",
                                    value=policy_name,
                                    object_type="policy",
                                    return_type="instance",
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                callback.send(_("Unknown default policy: %s") % policy_name)
                continue
            policy = result[0]
            if policy.uuid in first_node.policies:
                continue
            first_node.add_policy(policy.name, verify_acls=False)

        # Make sure DB indices are created after adding all objects.
        msg = "Creating DB indexes..."
        callback.send(msg)
        _index = config.get_index_module()
        _index.command("create_db_indices")

        # We finished our realm init.
        config.realm_init = False
        # Make sure master node stays master node if second node joins.
        config.touch_node_sync_file()

        # Reload after init finshed.
        from otpme.lib import init_otpme
        config.reload()
        init_otpme()

        from otpme.lib import nsscache
        # Update nsscache.
        nsscache.update(config.realm, config.site)
        # Enable nsscache symlinks.
        nsscache.enable()

        msg = ("Realm initialized successful.")
        return callback.ok(msg)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(self, verbose_level=0, callback=default_callback, **kwargs):
        """ Add a realm. """
        # Check if we have our own realm before adding realm trust relationship.
        if not config.realm:
            msg = (_("We do not have a realm. You must first init "
                    "our own realm."))
            return callback.error(msg)

        own_realm = backend.get_object(object_type="realm",
                                    uuid=config.realm_uuid)
        if not own_realm.verify_acl(acl="add:realm", check_admin_role=False):
            msg = (_("Permission denied: %s") % own_realm.name)
            return callback.error(msg, exception=PermissionDenied)

        # Run parent class stuff e.g. add lock.
        result = self._prepare_add(verify_acl=False, callback=callback, **kwargs)
        if result is False:
            return callback.error()

        # Add object using parent class.
        return super(Realm, self).add(verbose_level=verbose_level,
                                    callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(
        self,
        force: bool=False,
        verify_acls: bool=True,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete realm. """
        # We should never delete ourselves ;)
        if self.own:
            return callback.error("Cannot delete own realm!")

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
            if self.confirmation_policy != "force":
                answer = callback.ask(_("Delete realm '%s'?: ") % self.name)
                if answer.lower() != "y":
                    return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show realm config. """
        if not self.verify_acl(acl="view_public:object", check_admin_role=False):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        realm_ca = ""
        if self.ca:
            if self.verify_acl("view:ca"):
                ca = backend.get_object(object_type="ca", uuid=self.ca)
                if ca:
                    realm_ca = ca.rel_path
        lines = []

        auth_enabled = "-"
        if self.verify_acl("view:auth") \
        or self.verify_acl("enable:auth") \
        or self.verify_acl("disable:auth"):
            if self.auth_enabled:
                auth_enabled = True
            else:
                auth_enabled = False

        lines.append('AUTH_ENABLED="%s"' % auth_enabled)

        sync_enabled = "-"
        if self.verify_acl("view:sync") \
        or self.verify_acl("enable:sync") \
        or self.verify_acl("disable:sync"):
            if self.sync_enabled:
                sync_enabled = True
            else:
                sync_enabled = False

        lines.append('SYNC_ENABLED="%s"' % sync_enabled)

        master = ""
        if self.verify_acl("view:master"):
            if self.master:
                master = self.master
        lines.append('MASTER="%s"' % master)

        if self.verify_acl("view:ca"):
            lines.append('CA="%s"' % realm_ca)
        else:
            lines.append('CA=""')

        ca_data = ""
        if self.verify_acl("view:ca_data"):
            if self.ca_data:
                ca_data = encode(self.ca_data, "base64")
        lines.append('CA_DATA="%s"' % ca_data)

        aliases = ""
        if self.verify_acl("view:alias") \
        or self.verify_acl("add:alias") \
        or self.verify_acl("delete:alias"):
            if self.aliases:
                aliases = ",".join(self.aliases)
        lines.append('ALIASES="%s"' % aliases)

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)
    def show(self, **kwargs):
        """ Show realm details """
        #if not self.verify_acl(acl="view_public:object", check_admin_role=False):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
