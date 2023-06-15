# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.otpme_host import OTPmeHost
from otpme.lib.protocols.utils import register_commands

from otpme.lib.classes.otpme_host import \
                    get_acls as _get_acls
from otpme.lib.classes.otpme_host import \
                    get_value_acls as _get_value_acls
from otpme.lib.classes.otpme_host import \
                    get_default_acls as _get_default_acls
from otpme.lib.classes.otpme_host import \
                    get_recursive_default_acls as _get_recursive_default_acls

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

read_acls = []

write_acls =  [
                "limit_logins",
                "unlimit_logins",
            ]

read_value_acls = {
                "view"      : [
                                "cluster_votes",
                                ],
            }

write_value_acls = {
                "edit"      : [
                                "cluster_votes",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : [
                                            'unit',
                                            'country',
                                            'state',
                                            'locality',
                                            'organization',
                                            'ou',
                                            'email',
                                            'key_len',
                                            'valid',
                                        ],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'job_type'          : 'process',
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("node"),
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
                    'method'            : cli.list_getter("node"),
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
                    'method'            : cli.list_getter("node"),
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
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable',
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_ldif'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ldif',
                    'args'              : ['attributes'],
                    'job_type'          : 'thread',
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
    'cluster_votes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_cluster_votes',
                    'args'              : ['new_votes'],
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
    'dump_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_cert',
                    'job_type'          : 'process',
                    },
                },
            },
    'dump_ca_chain'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ca_chain',
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
                    'oargs'             : [ 'keep_sign'],
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
    'public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_public_key',
                    'oargs'            : ['public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'renew_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'renew_cert',
                    'oargs'            : ['cert_req'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_ssh_authorized_keys'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ssh_authorized_keys',
                    'oargs'             : ['user'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_jotp'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_jotp',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_jotp'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_jotp',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_lotp'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_lotp',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_lotp'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_lotp',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_jotp_rejoin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_jotp_rejoin',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_jotp_rejoin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_jotp_rejoin',
                    'job_type'          : 'thread',
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
                    'job_type'          : 'thread',
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
                    'job_type'          : 'thread',
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

def get_acls(split=False, **kwargs):
    """ Get all supported object ACLs """
    if split:
        otpme_host_read_acls, \
        otpme_host_write_acls = _get_acls(split=split, **kwargs)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_host_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_host_write_acls)
        return _read_acls, _write_acls
    otpme_host_acls = _get_acls(**kwargs)
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, otpme_host_acls)
    return _acls

def get_value_acls(split=False, **kwargs):
    """ Get all supported object value ACLs """
    if split:
        otpme_host_read_value_acls, \
        otpme_host_write_value_acls = _get_value_acls(split=split, **kwargs)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                                    otpme_host_read_value_acls)
        _write_value__acls = otpme_acl.merge_value_acls(read_value_acls,
                                                        otpme_host_write_value_acls)
        return _read_value_acls, _write_value__acls
    otpme_host_value_acls = _get_value_acls(**kwargs)
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, otpme_host_value_acls)
    return _acls

def get_default_acls():
    """ Get all supported object default ACLs """
    otpme_host_default_acls = _get_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, otpme_host_default_acls)
    return _acls

def get_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    otpme_host_recursive_default_acls = _get_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                otpme_host_recursive_default_acls)
    return _acls

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.unit"]

DEFAULT_UNIT = "nodes"

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("node", commands)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT, early=True)
    config.register_default_unit("node", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    node_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    node_path_re = '%s[/]%s' % (unit_path_re, node_name_re)
    node_oid_re = 'node|%s' % node_path_re
    oid.register_oid_schema(object_type="node",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=node_name_re,
                            path_regex=node_path_re,
                            oid_regex=node_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="node",
                                getter=rel_path_getter)
def register_hooks():
    config.register_auth_on_action_hook("node", "join")
    config.register_auth_on_action_hook("node", "leave")
    config.register_auth_on_action_hook("node", "add_token")
    config.register_auth_on_action_hook("node", "remove_token")
    config.register_auth_on_action_hook("node", "revoke_cert")
    config.register_auth_on_action_hook("node", "renew_cert")
    config.register_auth_on_action_hook("node", "limit_logins")
    config.register_auth_on_action_hook("node", "unlimit_logins")
    config.register_auth_on_action_hook("node", "change_public_key")
    config.register_auth_on_action_hook("node", "enable_jotp_rejoin")
    config.register_auth_on_action_hook("node", "disable_jotp_rejoin")

def register_backend():
    """ Register object for the file backend. """
    node_dir_extension = "node"
    def path_getter(node_oid):
        return backend.config_path_getter(node_oid, node_dir_extension)
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                'group',
                'ca',
                ]
        return backend.rebuild_object_index("node", objects, after)
    # Register object to config.
    config.register_object_type(object_type="node",
                            tree_object=True,
                            add_after=["accessgroup"],
                            sync_after=["user", "token"],
                            uniq_name=True,
                            object_cache=1024,
                            cache_region="tree_object")
    # Register object to backend.
    class_getter = lambda: Node
    backend.register_object_type(object_type="node",
                                dir_name_extension=node_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="node")
    config.register_object_sync(host_type="host", object_type="node")

class Node(OTPmeHost):
    """ OTPme node object. """
    commands = commands
    def __init__(self, object_id=None, name=None, path=None,
        unit=None, realm=None, site=None, **kwargs):
        # Set our type (used in parent class)
        self.type = "node"
        self.cluster_votes = 1
        # Call parent class init.
        super(Node, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        unit=unit,
                                        name=name,
                                        path=path,
                                        **kwargs)
        # Get ACLs.
        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        self.handle_cert_loading = True
        self.handle_key_loading = True
        self.handle_public_key_loading = True
        self.handle_private_key_loading = True

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "ADDRESS",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "PUBLIC_KEY",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "SECRET",
                            "ADDRESS",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "PUBLIC_KEY",
                            "CLUSTER_VOTES",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        node_config = {
                        'CLUSTER_VOTES'             : {
                                                        'var_name'  : 'cluster_votes',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },
                        }

        # Use parent class method to merge node config.
        return OTPmeHost._get_object_config(self, object_config=node_config)

    @check_acls(['edit:cluster_votes'])
    @object_lock()
    @backend.transaction
    def set_cluster_votes(self, new_votes,
        callback=default_callback, _caller="API", **kwargs):
        """ Set cluster votes. """
        self.cluster_votes = new_votes
        return self._cache(callback=callback)

    def disable(self, *args, force=False, callback=default_callback, **kwargs):
        if not force:
            if self.name == config.master_node:
                msg = "Cannot disable master node."
                return callback.error(msg)
        return super(Node, self).disable(*args, force=force, callback=callback, **kwargs)

    def show_config(self, callback=default_callback, **kwargs):
        """ Show host config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        if self.verify_acl("view:token") \
        or self.verify_acl("add:token") \
        or self.verify_acl("remove:token"):
            token_list = []
            for x_uuid in self.tokens:
                token_oid = backend.get_oid(x_uuid, instance=True)
                # Add UUIDs of orphan tokens.
                if not token_oid:
                    token_list.append(x_uuid)
                    continue
                if not otpme_acl.access_granted(object_id=token_oid,
                                                acl="view_public:object"):
                    continue
                token_path = token_oid.rel_path
                token_list.append(token_path)
            token_list.sort()
        else:
            token_list = [""]

        jotp = ""
        if self.verify_acl("view:jotp"):
            if self.jotp:
                jotp = self.jotp
        lines.append('JOTP="%s"' % jotp)

        jotp_rejoin = ""
        if self.verify_acl("view:jotp_rejoin") \
        or self.verify_acl("enable:jotp_rejoin") \
        or self.verify_acl("disable:jotp_rejoin"):
            jotp_rejoin = str(self.allow_jotp_rejoin)
        lines.append('ALLOW_JOTP_REJOIN="%s"' % jotp_rejoin)

        lotp = ""
        if self.verify_acl("view:lotp"):
            if self.lotp:
                lotp = self.lotp
        lines.append('LOTP="%s"' % lotp)
        lines.append('TOKENS="%s"' % ",".join(token_list))

        if self.verify_acl("view:roles") \
        or self.verify_acl("add:role") \
        or self.verify_acl("remove:role"):
            role_list = []
            for x_uuid in self.roles:
                role_oid = backend.get_oid(x_uuid, instance=True)
                # Add UUIDs of orphan roles.
                if not role_oid:
                    role_list.append(x_uuid)
                    continue
                if not otpme_acl.access_granted(object_id=role_oid,
                                                acl="view_public:object"):
                    continue
                role_name = role_oid.name
                role_list.append(role_name)
            role_list.sort()
        else:
            role_list = []
        lines.append('ROLES="%s"' % ",".join(role_list))

        token_options = {}
        for uuid in self.token_options:
            token = backend.get_object(object_type="token", uuid=uuid)
            if token:
                token_path = token.rel_path
            else:
                token_path = uuid
            token_options[token_path] = self.token_options[uuid]
        lines.append('TOKEN_OPTIONS="%s"' % token_options)

        public_key = ""
        if self.public_key:
            public_key = self.public_key
        lines.append('PUBLIC_KEY="%s"' % public_key)

        return super(Node, self).show_config(
                                config_lines=lines,
                                callback=callback,
                                **kwargs)
