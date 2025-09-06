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
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
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
                                "sync_users",
                                "sync_groups",
                                "dynamic_groups",
                            ],
            }

write_value_acls = {
                "add"       : [
                                "sync_group",
                                "dynamic_group",
                            ],
                "edit"       : [
                                "config",
                            ],
                "remove"    : [
                                "sync_group",
                                "dynamic_group",
                            ],
                "enable"    : [
                                "sync_groups",
                                "sync_by_login_token",
                            ],
                "disable"   : [
                                "sync_groups",
                                "sync_by_login_token",
                             ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : [
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
                    'method'            : cli.show_getter("host"),
                    'args'              : ['realm'],
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'max_policies',
                                        'max_tokens',
                                        'max_roles',
                                        'search_regex',
                                        'sort_by',
                                        'reverse',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        'realm',
                                        'site',
                                        'show_templates',
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
                    'method'            : cli.list_getter("host"),
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
                    'method'            : cli.list_getter("host"),
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
                    'oargs'             : ['attributes'],
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
                    'job_type'          : 'thread',
                    },
                },
            },
    'remove_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'oargs'             : [ 'keep_sign'],
                    'job_type'          : 'thread',
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
    'add_sync_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_sync_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'remove_sync_group'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_sync_group',
                    'args'              : ['group_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_sync_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sync_groups',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_sync_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sync_groups',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_sync_by_login_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sync_by_login_token',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_sync_by_login_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sync_by_login_token',
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
    'list_sync_groups'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sync_groups',
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
                    'job_type'          : 'thread',
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

#REGISTER_BEFORE = ['otpme.lib.policy']
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.unit"]

DEFAULT_UNIT = "hosts"
HOST_TEMPLATE = "host_template"

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_template()
    register_object_unit()
    register_sync_settings()
    register_commands("host", commands)

def register_template():
    config.register_object_template("host", HOST_TEMPLATE)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("host", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    host_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    host_path_re = '%s[/]%s' % (unit_path_re, host_name_re)
    host_oid_re = 'host|%s' % host_path_re
    oid.register_oid_schema(object_type="host",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=host_name_re,
                            path_regex=host_path_re,
                            oid_regex=host_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="host",
                                getter=rel_path_getter)

def register_hooks():
    config.register_auth_on_action_hook("host", "join")
    config.register_auth_on_action_hook("host", "leave")
    config.register_auth_on_action_hook("host", "add_role")
    config.register_auth_on_action_hook("host", "remove_role")
    config.register_auth_on_action_hook("host", "add_token")
    config.register_auth_on_action_hook("host", "remove_token")
    config.register_auth_on_action_hook("host", "revoke_cert")
    config.register_auth_on_action_hook("host", "renew_cert")
    config.register_auth_on_action_hook("host", "limit_logins")
    config.register_auth_on_action_hook("host", "unlimit_logins")
    config.register_auth_on_action_hook("host", "change_public_key")
    config.register_auth_on_action_hook("host", "enable_jotp_rejoin")
    config.register_auth_on_action_hook("host", "disable_jotp_rejoin")
    config.register_auth_on_action_hook("host", "add_dynamic_group")
    config.register_auth_on_action_hook("host", "remove_dynamic_group")

def register_backend():
    """ Register object for the file backend. """
    host_dir_extension = "host"
    def path_getter(host_oid, host_uuid):
        return backend.config_path_getter(host_oid, host_dir_extension)
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                'group',
                'ca',
                'node',
                ]
        return backend.rebuild_object_index("host", objects, after)
    # Register object to config.
    config.register_object_type(object_type="host",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["node"],
                            sync_after=["node", "user", "token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Host
    backend.register_object_type(object_type="host",
                                dir_name_extension=host_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="host")
    config.register_object_sync(host_type="host", object_type="host")

@match_class_typing
class Host(OTPmeHost):
    """ OTPme host object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid, None]=None,
        name: Union[str,None]=None,
        path: Union[str,None]=None,
        unit: Union[str,None]=None,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class)
        self.type = "host"

        # Call parent class init.
        super(Host, self).__init__(object_id=object_id,
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

        self.logins_limited = True
        self.sync_by_login_token = True
        self.sync_groups_enabled = False

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
                            "JOIN_DATE",
                            "JOIN_NODE",
                            "JOIN_NODE_CACHE",
                            "JOIN_TOKEN",
                            "JOIN_TOKEN_CACHE",
                            "DYNAMIC_GROUPS",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "ADDRESS",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "PUBLIC_KEY",
                            "JOIN_DATE",
                            "JOIN_NODE",
                            "JOIN_NODE_CACHE",
                            "JOIN_TOKEN",
                            "JOIN_TOKEN_CACHE",
                            "DYNAMIC_GROUPS",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        host_config = {
                        'SYNC_USERS'                 : {
                                                        'var_name'  : 'sync_users',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'SYNC_GROUPS'               : {
                                                        'var_name'  : 'sync_groups',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'SYNC_GROUPS_ENABLED'      : {
                                                        'var_name'  : 'sync_groups_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'SYNC_BY_LOGIN_TOKEN'      : {
                                                        'var_name'  : 'sync_by_login_token',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        }

        # Use parent class method to merge host config.
        return OTPmeHost._get_object_config(self, object_config=host_config)

    def get_sync_parameters(self, realm: str, site: str, peer_uuid: str):
        """ Get data to build sync list. """
        # Get sync paramters via parten class.
        sync_params = super(Host, self).get_sync_parameters(realm, site, peer_uuid)
        skip_admin = sync_params['skip_admin']
        sync_object_types = sync_params['object_types']
        # Tokens/users to include.
        user_uuids = []
        token_uuids = []
        include_uuids = {}
        checksum_only_types = []
        # Sync token/users by login token.
        if self.sync_by_login_token:
            if self.logins_limited:
                try:
                    sync_object_types.remove("user")
                except ValueError:
                    pass
                checksum_only_types.append("user")
                try:
                    sync_object_types.remove("token")
                except ValueError:
                    pass
                checksum_only_types.append("token")
            else:
                # Get users/tokens to sync from REALM accessgroup.
                result = backend.search(object_type="accessgroup",
                                        attribute="name",
                                        value=config.realm_access_group,
                                        return_type="instance",
                                        realm=config.realm,
                                        site=self.site)
                if not result:
                    msg = (_("Unable to find realm accessgroup: %s")
                            % config.realm_access_group)
                    raise OTPmeException(msg)

                realm_access_group = result[0]
                # Get tokens to sync form accessgroup.
                token_uuids += realm_access_group.get_tokens(include_roles=True,
                                                            skip_disabled=False,
                                                            return_type="uuid")
                # Get users to sync form accessgroup.
                user_uuids += realm_access_group.get_token_users(include_roles=True,
                                                                skip_disabled=False,
                                                                return_type="uuid")
            # Get users to sync from host.
            user_uuids += self.get_sync_users(include_roles=True,
                                            skip_disabled=False,
                                            return_type="uuid")
            # Get token users to sync from host.
            user_uuids += self.get_token_users(include_roles=True,
                                            skip_disabled=False,
                                            return_type="uuid")
            # Get tokens to sync from host.
            token_uuids += self.get_tokens(include_roles=True,
                                        skip_disabled=False,
                                        return_type="uuid")

        # Sync users by sync groups.
        if self.sync_groups_enabled:
            try:
                sync_object_types.remove("user")
            except ValueError:
                pass
            checksum_only_types.append("user")
            try:
                sync_object_types.remove("token")
            except ValueError:
                pass
            checksum_only_types.append("token")
            for group_uuid in self.sync_groups:
                x_group = backend.get_object(uuid=group_uuid)
                if not x_group:
                    continue
                # Get users.
                user_uuids += x_group.get_sync_users(include_roles=True,
                                                    skip_disabled=False,
                                                    return_type="uuid")
                # Get token users.
                user_uuids += x_group.get_token_users(include_roles=True,
                                                    skip_disabled=False,
                                                    return_type="uuid")
                # Get tokens
                token_uuids += x_group.get_tokens(include_roles=True,
                                                skip_disabled=False,
                                                return_type="uuid")
                # Get default group users.
                user_uuids += x_group.default_group_users

        # Check for admin user/token to sync.
        admin_user = None
        admin_token = backend.get_object(uuid=config.admin_token_uuid)
        if admin_token:
            admin_user = backend.get_object(uuid=admin_token.owner_uuid)
        if admin_user:
            if skip_admin:
                try:
                    user_uuids.remove(admin_user.uuid)
                except ValueError:
                    pass
                try:
                    token_uuids.remove(admin_token.uuid)
                except ValueError:
                    pass
            else:
                if admin_user.uuid not in user_uuids:
                    user_uuids.append(admin_user.uuid)
                if admin_token.uuid not in token_uuids:
                    token_uuids.append(admin_token.uuid)

        return_attributes = ['default_token']
        for user_uuid in user_uuids:
            result = backend.search(object_type="user",
                                    attribute="uuid",
                                    value=user_uuid,
                                    return_attributes=return_attributes)
            if not result:
                continue
            default_token_uuid = result[0]
            token_uuids.append(default_token_uuid)

        return_attributes = ['destination_token']
        for token_uuid in list(token_uuids):
            result = backend.search(object_type="user",
                                    attribute="uuid",
                                    value=user_uuid,
                                    return_attributes=return_attributes)
            if not result:
                continue
            destination_token_uuid = result[0]
            token_uuids.append(destination_token_uuid)

        if user_uuids:
            include_uuids['user'] = list(set(user_uuids))
        if token_uuids:
            include_uuids['token'] = list(set(token_uuids))

        # Build sync parameters.
        sync_params['include_uuids'] = include_uuids
        sync_params['object_types'] = sync_object_types
        sync_params['checksum_only_types'] = checksum_only_types
        return sync_params

    @check_acls(['enable:sync_by_login_token'])
    @object_lock()
    @backend.transaction
    def enable_sync_by_login_token(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable sync by assigned tokens. """
        if self.sync_by_login_token:
            return callback.error(_("Already enabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sync_by_login_token",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_by_login_token = True
        return self._cache(callback=callback)

    @check_acls(['disable:sync_by_login_token'])
    @object_lock()
    @backend.transaction
    def disable_sync_by_login_token(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable sync by assigned tokens. """
        if not self.sync_by_login_token:
            return callback.error(_("Already disabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sync_by_login_token",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_by_login_token = False
        return self._cache(callback=callback)

    @check_acls(['add:sync_group'])
    @object_lock()
    @backend.transaction
    def add_sync_group(
        self,
        group_name: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add sync group. """
        result = backend.search(object_type="group",
                                    attribute="name",
                                    value=group_name,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="uuid")
        if not result:
            msg = "Unknown group: %s" % group_name
            return callback.error(msg)
        group_uuid = result[0]

        if group_uuid in self.sync_groups:
            msg = (_("Sync group already assigned: %s" % group_name))
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_sync_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_groups.append(group_uuid)
        # Update index.
        self.add_index('sync_group', group_uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:sync_group'])
    @object_lock()
    @backend.transaction
    def remove_sync_group(
        self,
        group_name: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Remove sync group. """
        result = backend.search(object_type="group",
                                    attribute="name",
                                    value=group_name,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="uuid")
        if not result:
            msg = "Unknown group: %s" % group_name
            return callback.error(msg)
        group_uuid = result[0]

        if group_uuid not in self.sync_groups:
            msg = (_("Sync group not assigned: %s" % group_name))
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_sync_group",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_groups.remove(group_uuid)
        # Update index.
        self.del_index('sync_group', group_uuid)
        return self._cache(callback=callback)

    @check_acls(['enable:sync_groups'])
    @object_lock()
    @backend.transaction
    def enable_sync_groups(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable sync groups. """
        if self.sync_groups_enabled:
            return callback.error(_("Already enabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sync_groups",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_groups_enabled = True
        return self._cache(callback=callback)

    @check_acls(['disable:sync_groups'])
    @object_lock()
    @backend.transaction
    def disable_sync_groups(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable sync groups. """
        if not self.sync_groups_enabled:
            return callback.error(_("Already disabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sync_groups",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sync_groups_enabled = False
        return self._cache(callback=callback)

    @cli.check_rapi_opts()
    def get_sync_groups(
        self,
        return_type: str="name",
        skip_disabled: bool=False,
        include_roles: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Get all sync groups assigned to this object. """
        exception = None
        if not return_type in [ 'instance', 'uuid', 'oid', 'name', 'read_oid', 'full_oid']:
            exception = "Unknown return type: %s" % return_type
        if _caller != "API" and return_type == "instance":
            exception = "Unknown return type: %s" % return_type
        if exception:
            if _caller != "API":
                return callback.error(exception)
            else:
                raise Exception(exception)

        result = []
        if self.sync_groups:
            # Remove duplicates.
            group_uuids = sorted(list(set(self.sync_groups)))
            # Search users (return attribute) via user UUID.
            search_attrs = {}
            if skip_disabled:
                search_attrs['enabled'] = {}
                search_attrs['enabled']['value'] = True
            result += backend.search(object_type="group",
                                    attribute="uuid",
                                    values=group_uuids,
                                    attributes=search_attrs,
                                    return_type=return_type)
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    def show_config( self, callback: JobCallback=default_callback, **kwargs):
        """ Show host config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        if self.verify_acl("view:tokens") \
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

        lines.append('SYNC_BY_LOGIN_TOKEN="%s"' % self.sync_by_login_token)
        lines.append('SYNC_GROUPS_ENABLED="%s"' % self.sync_groups_enabled)
        if self.verify_acl("view:sync_groups") \
        or self.verify_acl("add:sync_group") \
        or self.verify_acl("remove:sync_group"):
            sync_group_list = []
            for x_uuid in self.sync_groups:
                group_oid = backend.get_oid(x_uuid, instance=True)
                # Add UUIDs of orphan groups.
                if not group_oid:
                    sync_group_list.append(x_uuid)
                    continue
                if not otpme_acl.access_granted(object_id=group_oid,
                                                acl="view_public:object"):
                    continue
                group_name = group_oid.name
                sync_group_list.append(group_name)
            sync_group_list.sort()
        else:
            sync_group_list = [""]
        lines.append('SYNC_GROUPS="%s"' % ",".join(sync_group_list))

        return super(Host, self).show_config(config_lines=lines,
                                    callback=callback, **kwargs)
