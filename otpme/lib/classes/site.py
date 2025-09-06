# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from cryptography import x509
from typing import List
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import net
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import trash
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.classes.node import Node
from otpme.lib.classes.user import User
from otpme.lib.classes.group import Group
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.register import register_module
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.pki.utils import check_ssl_cert_key
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.protocols.utils import register_commands
from otpme.lib.policy.idrange.idrange import IdrangePolicy
from otpme.lib.daemon.clusterd import cluster_radius_reload
from otpme.lib.compression.base import get_uncompressed_size
from otpme.lib.policy.idrange.idrange  import BASE_POLICY_NAME
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
                                "trust",
                                "address",
                                "auth_fqdn",
                                "mgmt_fqdn",
                                "auth",
                                "sync",
                                "ca",
                                "cert",
                                "cert_key",
                                "admin_role",
                                "user_role",
                                "admin_token",
                                "sso_secret",
                                "sso_csrf_secret",
                                "cluster_key",
                                "fido2_ca_cert",
                                ],
        }

write_value_acls = {
                    "add"       : [
                                "unit",
                                "trust",
                                "fido2_ca_cert",
                                ],
                    "delete"    : [
                                "unit",
                                "trust",
                                "fido2_ca_cert",
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
                                "address",
                                "auth_fqdn",
                                "mgmt_fqdn",
                                "radius_cert",
                                "radius_key",
                                "sso_cert",
                                "sso_key",
                                "sso_secret",
                                "sso_csrf_secret",
                                "cluster_key",
                                ],
                    "renew"     : [
                                "cert",
                                ],
                    "revoke"    : [
                                "cert",
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
                    "+user",
                    "+group",
                    "+accessgroup",
                    "+client",
                    "+node",
                    "+host",
                    "+role",
                    "+ca",
                    "+token",
                ]

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['node_name', 'site_fqdn'],
                    'oargs'             : [
                                            'site_address',
                                            'dictionaries',
                                            'id_ranges',
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
                                            'no_dicts',
                                            ],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'args'              : ['node_name', 'site_fqdn'],
                    'oargs'             : [
                                            'site_address',
                                            'dictionaries',
                                            'id_ranges',
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
                                            'no_dicts',
                                        ],
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
                    'method'            : cli.show_getter("site"),
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
                    'method'            : cli.list_getter("site"),
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
                    'method'            : cli.list_getter("site"),
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
    'add_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls', 'object_types'],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls', 'object_types',],
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
    'address'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_address',
                    'args'              : ['address'],
                    'job_type'          : 'process',
                    },
                },
            },
    'auth_fqdn'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_auth_fqdn',
                    'args'              : ['fqdn'],
                    'job_type'          : 'process',
                    },
                },
            },
    'mgmt_fqdn'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_mgmt_fqdn',
                    'args'              : ['fqdn'],
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
    'dump_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_cert_key',
                    'oargs'              : ['passphrase'],
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
    'dump_ca_chain'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_ca_chain',
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
    'revoke_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'revoke_cert',
                    'job_type'          : 'process',
                    },
                },
            },
    'renew_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'renew_cert',
                    'job_type'          : 'process',
                    },
                },
            },
    'radius_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_radius_cert',
                    'args'              : ['radius_cert'],
                    'job_type'          : 'process',
                    },
                },
            },
    'radius_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_radius_key',
                    'args'              : ['radius_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_radius_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_radius_cert',
                    'job_type'          : 'process',
                    },
                },
            },
    'del_radius_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_radius_key',
                    'job_type'          : 'process',
                    },
                },
            },
    'sso_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_sso_cert',
                    'args'              : ['sso_cert'],
                    'job_type'          : 'process',
                    },
                },
            },
    'sso_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_sso_key',
                    'args'              : ['sso_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sso_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_sso_cert',
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sso_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_sso_key',
                    'job_type'          : 'process',
                    },
                },
            },
    'sso_secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_sso_secret',
                    'args'              : ['secret'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'sso_csrf_secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_sso_csrf_secret',
                    'args'              : ['secret'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'cluster_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_cluster_key',
                    'args'              : ['cluster_key'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'add_fido2_ca_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_fido2_ca_cert',
                    'args'              : ['ca_cert'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_fido2_ca_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_fido2_ca_cert',
                    'args'              : ['subject'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'add_trust'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_trust',
                    'args'              : ['site_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_fido2_ca_certs'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_fido2_ca_certs',
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_trust'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_trust',
                    'args'              : ['site_name'],
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

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.realm",
                ]

SSO_CLIENT_NAME = "SSO"
SSO_ACCESSGROUP = "SSO"
SSO_USER_ROLE = "SSO_USER"

TEMPLATES_UNIT = "templates"

def register():
    register_dn()
    register_oid()
    register_hooks()
    register_config()
    register_backend()
    register_sync_settings()
    register_templates_unit()
    register_commands("site", commands)
    register_module("otpme.lib.classes.data_objects.rsa_key")
    register_module("otpme.lib.classes.data_objects.cert")

def register_sync_settings():
    #config.register_cluster_sync(object_type="site")
    config.register_object_sync(host_type="node", object_type="site")

def register_templates_unit():
    config.register_base_object("unit", TEMPLATES_UNIT, early=True)
    config.register_default_unit("template", TEMPLATES_UNIT)

def register_dn():
    """ Register DN attribute. """
    config.register_dn_attribute("site", "ou")

def register_config():
    """ Register config stuff. """
    config.register_config_var("default_site_validity", int, 5475)
    config.register_config_var("default_site_key_len", int, 2048)
    # Register SSO base client and accessgroup.
    config.register_config_var("sso_client_name", str, SSO_CLIENT_NAME)
    config.register_config_var("sso_access_group", str, SSO_ACCESSGROUP)
    config.register_base_object("accessgroup",  SSO_ACCESSGROUP)
    client_attrs = {'access_group':SSO_ACCESSGROUP}
    config.register_base_object(object_type="client",
                            name=config.sso_client_name,
                            attributes=client_attrs)
    config.register_config_var("sso_user_role", str, SSO_USER_ROLE)
    config.register_base_object("role", SSO_USER_ROLE)

def register_hooks():
    config.register_auth_on_action_hook("site", "add_unit")
    config.register_auth_on_action_hook("site", "change_address")
    config.register_auth_on_action_hook("site", "change_auth_fqdn")
    config.register_auth_on_action_hook("site", "change_mgmt_fqdn")
    config.register_auth_on_action_hook("site", "enable_auth")
    config.register_auth_on_action_hook("site", "disable_auth")
    config.register_auth_on_action_hook("site", "enable_sync")
    config.register_auth_on_action_hook("site", "disable_sync")
    config.register_auth_on_action_hook("site", "renew_cert")
    config.register_auth_on_action_hook("site", "add_trust")
    config.register_auth_on_action_hook("site", "del_trust")

def register_oid():
    full_oid_schema = [ 'realm', 'name' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    site_path_re = '/%s[/]%s' % (realm_name_re, site_name_re)
    site_oid_re = 'site|%s' % site_path_re
    oid.register_oid_schema(object_type="site",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=site_name_re,
                            path_regex=site_path_re,
                            oid_regex=site_oid_re)
    def get_object_site(object_id):
        """ Get object site from ID. """
        return oid.get_object_name(object_id)
    oid.register_site_getter(object_type="site",
                        getter=get_object_site)

def register_backend():
    """ Register object for the file backend. """
    site_dir_extension = "site"
    objects_dir = backend.get_data_dir("objects")
    def path_getter(object_id, object_uuid):
        config_paths = {}
        realm_dir_extension = backend.get_object_path_settings("realm")
        realm_dir_extension = realm_dir_extension['dir_name_extension']
        realm_dir_name = "%s.%s" % (object_id.realm, realm_dir_extension)
        site_dir_name = "%s.%s" % (object_id.name, site_dir_extension)
        config_dir = os.path.join(objects_dir, realm_dir_name, site_dir_name)
        config_paths['config_dir'] = config_dir
        config_paths['rmtree_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild(objects):
        after = [
                'realm',
                ]
        return backend.rebuild_object_index("site", objects, after)
    class_getter = lambda: Site
    # Register object to config.
    config.register_object_type(object_type="site",
                            tree_object=True,
                            add_before=["unit"],
                            add_after=["realm"],
                            sync_after=["realm"],
                            uniq_name=True,
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site'])
    # Register object to backend.
    backend.register_object_type(object_type="site",
                                dir_name_extension=site_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

@match_class_typing
class Site(OTPmeObject):
    """ OTPme site object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        path: Union[str,None]=None,
        name: Union[str,None]=None,
        realm: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class).
        self.type = "site"

        # Call parent class init.
        super(Site, self).__init__(object_id=object_id,
                                    realm=realm,
                                    name=name,
                                    path=path,
                                    **kwargs)
        self.ca = None
        self.admin_role_uuid = None
        self.user_role_uuid = None
        self.sso_user_role_uuid = None
        self.realm_users_group_uuid = None

        self.auth_fqdn = None
        self.mgmt_fqdn = None
        self.address = None
        self.auth_enabled = True
        self.sync_enabled = True
        self.admin_token_uuid = None
        self._base_policies_post_methods = {}
        self.handle_cert_loading = True
        self.handle_key_loading = True
        #self.handle_public_key_loading = True
        #self.handle_private_key_loading = True
        self.radius_cert = None
        self.radius_key = None
        self.radius_reload = False
        self.sso_cert = None
        self.sso_key = None
        self.sso_secret = None
        self.sso_csrf_secret = None
        self.required_votes = 0
        self.cluster_key = None
        self.fido2_ca_certs = {}

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "FQDN",
                            "ADDRESS",
                            "ADMIN_ROLE",
                            "CA",
                            "CERT",
                            "MASTER",
                            "USER_ROLE",
                            "TRUSTED_SITES",
                            "EXTENSIONS",
                            "BASE_ATTRIBUTES",
                            "OBJECT_CLASSES",
                            "INITIALIZED",
                            "SYNC_ENABLED",
                            "AUTH_ENABLED",
                            "ADMIN_TOKEN",
                            "ADMIN_ROLE",
                            "USER_ROLE",
                            "AUTH_FQDN",
                            "MGMT_FQDN",
                            "ou",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "FQDN",
                            "ADDRESS",
                            "ADMIN_ROLE",
                            "CA",
                            "CERT",
                            "ACLS",
                            "MASTER",
                            "USER_ROLE",
                            "TRUSTED_SITES",
                            "EXTENSIONS",
                            "BASE_ATTRIBUTES",
                            "OBJECT_CLASSES",
                            "INITIALIZED",
                            "SYNC_ENABLED",
                            "AUTH_ENABLED",
                            "ADMIN_TOKEN",
                            "ADMIN_ROLE",
                            "USER_ROLE",
                            "AUTH_FQDN",
                            "MGMT_FQDN",
                            "RADIUS_CERT",
                            "RADIUS_KEY",
                            "FIDO2_CA_CERTS",
                            "ou",
                            ]
                        },
                    }
        # Register site users group.
        try:
            config.register_internal_object("group", self.name)
        except AlreadyRegistered:
            pass

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

            'TRUSTED_SITES'             : {
                                            'var_name'      : 'trusted_sites',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'CA'                        : {
                                            'var_name'  : 'ca',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'ADMIN_ROLE'                : {
                                            'var_name'  : 'admin_role_uuid',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'USER_ROLE'                 : {
                                            'var_name'  : 'user_role_uuid',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'REALM_USERS_GROUP'         : {
                                            'var_name'  : 'realm_users_group_uuid',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'SSO_USER_ROLE'             : {
                                            'var_name'  : 'sso_user_role_uuid',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'ADDRESS'                   : {
                                            'var_name'  : 'address',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'MGMT_FQDN'                      : {
                                            'var_name'  : 'mgmt_fqdn',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'AUTH_FQDN'                      : {
                                            'var_name'  : 'auth_fqdn',
                                            'type'      : str,
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

            'ADMIN_TOKEN'                : {
                                            'var_name'  : 'admin_token_uuid',
                                            'type'      : 'uuid',
                                            'required'  : False,
                                        },

            'RADIUS_CERT'                : {
                                            'var_name'  : 'radius_cert',
                                            'type'      : str,
                                            'required'  : False,
                                            'encoding'  : 'BASE64',
                                        },

            'RADIUS_KEY'                : {
                                            'var_name'  : 'radius_key',
                                            'type'      : str,
                                            'required'  : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'SSO_CERT'                  : {
                                            'var_name'  : 'sso_cert',
                                            'type'      : str,
                                            'required'  : False,
                                            'encoding'  : 'BASE64',
                                        },

            'SSO_KEY'                   : {
                                            'var_name'  : 'sso_key',
                                            'type'      : str,
                                            'required'  : False,
                                            'encryption': config.disk_encryption,
                                        },

            'SSO_SECRET'                : {
                                            'var_name'  : 'sso_secret',
                                            'type'      : str,
                                            'required'  : False,
                                            'encryption': config.disk_encryption,
                                        },
            'SSO_CSRF_SECRET'           : {
                                            'var_name'  : 'sso_csrf_secret',
                                            'type'      : str,
                                            'required'  : False,
                                            'encryption': config.disk_encryption,
                                        },
            'REQUIRED_VOTES'            : {
                                            'var_name'  : 'required_votes',
                                            'type'      : int,
                                            'required'  : False,
                                        },
            'CLUSTER_KEY'               : {
                                            'var_name'  : 'cluster_key',
                                            'type'      : str,
                                            'required'  : False,
                                            'encryption': config.disk_encryption,
                                        },
            'FIDO2_CA_CERTS'            : {
                                            'var_name'  : 'fido2_ca_certs',
                                            'type'      : dict,
                                            'required'  : False,
                                        },
            }

        return object_config

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is lowercase.
        self.name = name.lower()

    def set_variables(self):
        """ Set instance variables. """
        return True

    def _write(self, **kwargs):
        """ Wrapper to make sure radius gets reloaded. """
        result = super(Site, self)._write(**kwargs)
        if not self.radius_reload:
            return result
        self.radius_reload = False
        reload_radius = True
        if self.radius_cert and self.radius_key:
            try:
                check_ssl_cert_key(self.radius_cert, self.radius_key)
            except:
                reload_radius = False
        if reload_radius == True:
            cluster_radius_reload()
        return result

    def get_master_site(self):
        own_realm = backend.get_object(uuid=config.realm_uuid)
        master_site = backend.get_object(uuid=own_realm.master)
        return master_site

    @object_lock()
    def _handle_acl(
        self,
        action: str,
        acl: object,
        recursive_acls: bool=False,
        apply_default_acls: bool=False,
        object_types: List=[],
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Method to call inherit_default_acl() for all site units. """
        exception = None

        if action == "add":
            inherit_method = "inherit_default_acl"
        else:
            inherit_method = "disinherit_default_acl"

        if not recursive_acls and not apply_default_acls:
            return callback.ok()

        all_units = backend.search(attribute="uuid",
                                    value="*",
                                    object_type="unit",
                                    return_type="instance",
                                    realm=config.realm,
                                    site=self.name)
        for unit in all_units:
            # Skip all non top level units.
            if unit and unit.unit:
                continue

            if recursive_acls:
                # Get ACL apply IDs.
                apply_id, recursive_apply_id = unit.get_acl_apply_ids(acl=acl)

                if apply_id:
                    add_status = unit.handle_acl(action=action,
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
                if object_types and "unit" not in object_types:
                    inherit_acl = False
                if inherit_acl:
                    unit_inherit_method = getattr(unit, inherit_method)
                    add_status = unit_inherit_method(acl=acl,
                                    recursive_acls=recursive_acls,
                                    apply_default_acls=apply_default_acls,
                                    object_types=object_types,
                                    verify_acls=verify_acls,
                                    verbose_level=verbose_level,
                                    callback=callback,
                                    **kwargs)
                    if not add_status:
                        exception = True
        if exception:
            return callback.error()

        return callback.ok()

    @check_acls(['edit:address'])
    @object_lock()
    @backend.transaction
    def change_address(
        self,
        address: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change site IP address. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_address",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # FIXME: Check if we got a valid address
        self.address = address
        # Update index.
        self.update_index("address", self.address)
        return self._write(callback=callback)

    @check_acls(['edit:auth_fqdn'])
    @object_lock()
    @backend.transaction
    def change_auth_fqdn(
        self,
        fqdn: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change site auth FQDN. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_auth_fqdn",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # FIXME: Check if we got a valid FQDN.
        self.auth_fqdn = fqdn
        # Update index.
        self.update_index("auth_fqdn", self.auth_fqdn)
        return self._write(callback=callback)

    @check_acls(['edit:mgmt_fqdn'])
    @object_lock()
    @backend.transaction
    def change_mgmt_fqdn(
        self,
        fqdn: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change site mgmt FQDN. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_mgmt_fqdn",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # FIXME: Check if we got a valid FQDN.
        self.mgmt_fqdn = fqdn
        # Update index.
        self.update_index("mgmt_fqdn", self.mgmt_fqdn)
        return self._write(callback=callback)

    @check_acls(['edit:radius_cert'])
    @object_lock()
    @backend.transaction
    def change_radius_cert(
        self,
        radius_cert: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change radius cert. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_radius_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.radius_cert = radius_cert
        # Make sure radius gets reloaded.
        self.radius_reload = True
        return self._cache(callback=callback)

    @check_acls(['edit:radius_cert'])
    @object_lock()
    @backend.transaction
    def del_radius_cert(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete radius cert. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_radius_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.radius_cert = None
        # Make sure radius gets reloaded.
        self.radius_reload = True
        return self._cache(callback=callback)

    @check_acls(['edit:radius_key'])
    @object_lock()
    @backend.transaction
    def change_radius_key(
        self,
        radius_key: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change radius cert. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_radius_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.radius_key = radius_key
        # Make sure radius gets reloaded.
        self.radius_reload = True
        return self._cache(callback=callback)

    @check_acls(['edit:radius_cert'])
    @object_lock()
    @backend.transaction
    def del_radius_key(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete radius key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_radius_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.radius_key = None
        # Make sure radius gets reloaded.
        self.radius_reload = True
        return self._cache(callback=callback)

    @check_acls(['edit:sso_cert'])
    @object_lock()
    @backend.transaction
    def change_sso_cert(
        self,
        sso_cert: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change sso cert. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_sso_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sso_cert = sso_cert
        return self._cache(callback=callback)

    @check_acls(['edit:sso_cert'])
    @object_lock()
    @backend.transaction
    def del_sso_cert(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete sso cert. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_sso_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sso_cert = None
        return self._cache(callback=callback)

    @check_acls(['edit:sso_key'])
    @object_lock()
    @backend.transaction
    def change_sso_key(
        self,
        sso_key: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change sso cert. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_sso_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sso_key = sso_key
        return self._cache(callback=callback)

    @check_acls(['edit:sso_cert'])
    @object_lock()
    @backend.transaction
    def del_sso_key(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete sso key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_sso_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sso_key = None
        return self._cache(callback=callback)

    @check_acls(['edit:sso_secret'])
    @object_lock()
    @backend.transaction
    def change_sso_secret(
        self,
        secret: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change sso secret. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_sso_secret",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sso_secret = secret
        return self._cache(callback=callback)

    @check_acls(['edit:sso_csrf_secret'])
    @object_lock()
    @backend.transaction
    def change_sso_csrf_secret(
        self,
        secret: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change sso CSRF secret. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_sso_csrf_secret",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.sso_csrf_secret = secret
        return self._cache(callback=callback)

    @check_acls(['edit:cluster_key'])
    @object_lock()
    @backend.transaction
    def change_cluster_key(
        self,
        cluster_key: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change cluster key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_cluster_key",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.cluster_key = cluster_key
        return self._cache(callback=callback)

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
        """ Enable authentication with the site. """
        if self.auth_enabled:
            msg = (_("Authentication with site '%s' is already enabled.")
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
            if self.uuid == config.site_uuid:
                msg = (_("Enable authentication for own site? "))
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    msg = (_("Enable authentication with site '%s'?: " )
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
        """ Disable authentication with the site. """
        if not self.auth_enabled:
            msg = (_("Authentication with site '%s' is already disabled.")
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
            if self.uuid == config.site_uuid:
                msg = (_("Disable authentication for own site? "
                        "This will disable ALL logins!: "))
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    msg = (_("Disable authentication with site '%s'?: ")
                            % self.name)
                    answer = callback.ask(msg)
                    if answer.lower() != "y":
                        return callback.abort()

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
        """ Enable synchronization with the site. """
        if self.sync_enabled:
            msg = (_("Synchronization with site '%s' is already enabled.")
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
            if self.uuid == config.site_uuid:
                msg = (_("Enable synchronization of own site '%s'?: " )
                        % self.name)
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    msg = (_("Enable synchronization with site '%s'?: " )
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
        """ Disable synchronization with the site. """
        if self.uuid == config.site_uuid:
            msg = (_("Cannot disable synchronization of own site."))
            return callback.error(msg)

        if not self.sync_enabled:
            msg = (_("Synchronization with site '%s' is already disabled.")
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
                msg = (_("Disable synchronization with site '%s'?: ")
                        % self.name)
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        self.sync_enabled = False
        self.update_index("sync_enabled", self.sync_enabled)
        return self._write(callback=callback)

    def create_site_cert(
        self,
        valid: Union[int,None]=None,
        key_len: Union[int,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Create site certificate """
        from otpme.lib.classes.ca import Ca
        if key_len is None:
            key_len = config.default_site_key_len
        if valid is None:
            valid = config.default_site_validity
        site_ca = Ca(path=config.site_ca_path)
        site_ca.exists()

        msg = (_("Generating site certificate (%s bits).") % key_len)
        callback.send(msg)

        cn = "%s.%s" % (self.name, self.realm)
        try:
            cert, \
            key = site_ca.create_server_cert(cn=cn,
                                            key_len=key_len,
                                            valid=valid,
                                            self_signed=False,
                                            verify_acls=False)
        except Exception as e:
            msg = (_("Unable to create site certificate: %s") % e)
            raise OTPmeException(msg)

        return cert, key

    @check_acls(['renew:cert'])
    @object_lock(full_lock=True)
    @backend.transaction
    def renew_cert(
        self,
        valid: Union[int,None]=None,
        key_len: Union[int,None]=None,
        run_policies: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Renew site certificate """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("renew_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if verbose_level > 0:
            msg = (_("Generating new site certificate (%s bits).") % key_len)
            callback.send(msg)
            # Wait a moment before starting CPU intensive job to prevent delay
            # when transmitting above message to user.
            time.sleep(0.01)

        # Create new site certificate.
        try:
            cert, \
            key = self.create_site_cert(key_len=key_len,
                                        valid=valid,
                                        callback=callback)
        except Exception as e:
            msg = str(e)
            return callback.error(msg)

        # Try to revoke old certificate.
        if self.cert:
            from otpme.lib.classes.ca import Ca
            site_ca = Ca(path=config.site_ca_path)
            site_ca.exists()
            try:
                site_ca.revoke_cert(cert=self.cert,
                                verify_acls=False,
                                callback=callback)
            except Exception as e:
                msg = (_("Unable to revoke certificate: %s") % e)
                return callback.error(msg)

        # Set new key/cert.
        self.cert = cert
        self.key = key
        return self._write(callback=callback)

    @object_lock(full_lock=True)
    def create_site_ca(
        self,
        ca_country: Union[str,None]=None,
        ca_state: Union[str,None]=None,
        ca_locality: Union[str,None]=None,
        ca_organization: Union[str,None]=None,
        ca_ou: Union[str,None]=None,
        ca_email: Union[str,None]=None,
        cert: Union[str,None]=None,
        key: Union[str,None]=None,
        no_cert: bool=False,
        ca_key_len: Union[int,None]=None,
        ca_valid: Union[int,None]=None,
        site_key_len: Union[int,None]=None,
        site_valid: Union[int,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Create site CA """
        from otpme.lib.classes.ca import Ca
        if site_valid is None:
            site_valid = config.default_site_validity
        if ca_valid is None:
            ca_valid = config.default_ca_validity
        if ca_key_len is None:
            ca_key_len = config.default_ca_key_len
        # Create site CA cert using the realm CA.
        if not no_cert and not cert and not key:
            # Get realm CA.
            callback.send(_("Loading realm CA '%s'.") % config.realm_ca_path)
            realm_ca = Ca(path=config.realm_ca_path)
            if not realm_ca.exists():
                msg = (_("Problem loading realm CA '%s'.")
                        % config.realm_ca_path)
                return callback.error(msg)

            # Create site CA cert.
            try:
                cert, key = realm_ca.create_ca_cert(cn=config.site_ca_path,
                                                country=ca_country,
                                                state=ca_state,
                                                locality=ca_locality,
                                                organization=ca_organization,
                                                ou=ca_ou, email=ca_email,
                                                verify_acls=False)
            except Exception as e:
                msg = (_("Error creating site CA cert: %s") % e)
                return callback.error(msg)

        # Create site CA.
        callback.send(_("Adding site CA '%s'.") % config.site_ca_path)
        site_ca = Ca(path=config.site_ca_path)
        if not site_ca.exists():
            if not site_ca.add(cn=config.site_ca_path,
                                country=ca_country,
                                state=ca_state,
                                locality=ca_locality,
                                organization=ca_organization,
                                ou=ca_ou, email=ca_email,
                                no_cert=no_cert,
                                cert=cert,
                                key=key,
                                key_len=ca_key_len,
                                valid=ca_valid,
                                callback=callback):
                msg = (_("Problem adding site CA '%s'.") % config.site_ca_path)
                return callback.error(msg)

        # Set site CA.
        self.ca = site_ca.uuid

        if not no_cert:
            try:
                self.renew_cert(key_len=site_key_len,
                                    valid=site_valid,
                                    callback=callback)
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        # Write config.
        self._write(callback=callback)

        # Update realm CA data.
        if not no_cert:
            try:
                site_ca.update_realm_ca_data(callback=callback)
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        return callback.ok()

    @object_lock(full_lock=True)
    def create_master_node(
        self,
        node_name: str,
        cert_req: Union[str,None]=None,
        gen_jotp: bool=True,
        cert_valid: Union[int,None]=None,
        uuid: Union[str,None]=None,
        public_key: Union[str,None]=None,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Creating master node object for this site. """
        if cert_valid is None:
            cert_valid = config.default_node_validity
        # Create node instance.
        node = Node(name=node_name,
                    realm=config.realm,
                    site=self.name,
                    uuid=uuid)
        if node.exists():
            msg = (_("Error: node '%s' already exists.") % node_name)
            return callback.error(msg)

        # Add node.
        try:
            node.add(cert_req=cert_req,
                    cert_valid=cert_valid,
                    public_key=public_key,
                    enabled=True,
                    gen_jotp=gen_jotp,
                    callback=callback)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error adding node: %s") % e)
            raise OTPmeException(msg)

        # Write UUID file only on realm init.
        if config.realm_init:
            msg = (_("Writing node UUID to file: %s") % config.uuid_file)
            callback.send(msg)
            try:
                fd = open(config.uuid_file, "w")
                fd.write(node.uuid)
                fd.close()
            except Exception as e:
                msg = (_("Error writing UUID file: %s") % e)
                raise OTPmeException(msg)

        return self._write(callback=callback)

    @check_acls(['add:trust'])
    @object_lock()
    @backend.transaction
    def add_trust(
        self,
        site_name: str,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add site trust relationship. """
        if self.uuid != config.site_uuid:
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        result = backend.search(object_type="site",
                                attribute="name",
                                value=site_name,
                                return_type="uuid")
        if not result:
            msg = (_("Unknown site: %s") % site_name)
            return callback.error(msg)

        site_uuid = result[0]

        if site_uuid == self.uuid:
            msg = (_("Cannot add trust relationship with site itself."))
            return callback.error(msg)

        if site_uuid in self.trusted_sites:
            msg = (_("Relationship with site already exists: %s") % site_name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_trust",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.trusted_sites.append(site_uuid)
        # Update index.
        self.add_index("trusted_site", site_uuid)

        return self._write(callback=callback)

    @check_acls(['delete:trust'])
    @object_lock()
    @backend.transaction
    def del_trust(
        self,
        site_name: str,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete site trust relationship. """
        if self.uuid != config.site_uuid:
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        # Allow removal of orphan site UUIDs.
        if stuff.is_uuid(site_name):
            site_uuid = site_name
        else:
            result = backend.search(object_type="site",
                                    attribute="name",
                                    value=site_name,
                                    return_type="uuid")
            if not result:
                msg = (_("Unknown site: %s") % site_name)
                return callback.error(msg)
            site_uuid = result[0]

        if not site_uuid in self.trusted_sites:
            msg = (_("Relationship with site does not exist: %s") % site_name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_trust",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.trusted_sites.remove(site_uuid)
        # Update index.
        self.del_index("trusted_site", site_uuid)

        return self._write(callback=callback)

    @object_lock(full_lock=True)
    @run_pre_post_add_policies()
    @backend.transaction
    def add(
        self,
        node_name: str,
        site_address: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add site. """
        from otpme.lib.register import register_modules
        # Register all modules.
        register_modules()
        kwargs['site_address'] = site_address
        kwargs['node_name'] = node_name
        kwargs['callback'] = callback

        if config.site_init:
            msg = ("There is already a site add job running.")
            return callback.error(msg)

        if not config.realm_init:
            #if verify_acls:
            #    own_realm = backend.get_object(object_type="realm", uuid=config.realm_uuid)
            #    if not own_realm.verify_acl(acl="add:site", check_admin_role=False):
            #        msg (_("Permission denied: %s") % own_realm.name)
            #        return callback.error(msg, exception=PermissionDenied)

            # Run parent class stuff e.g. verify ACLs.
            result = self._prepare_add(callback=callback)
            if result is False:
                return callback.error()

        if config.realm_init:
            self.uuid = stuff.gen_uuid()
            kwargs['uuid'] = self.uuid
        else:
            config.site_init = True

        # Start site add.
        add_result = self._add(**kwargs)
        if not add_result:
            config.site_init = False
            return add_result

        config.site_init = False

        # Update index.
        self.update_index("address", self.address)
        self.update_index("auth_fqdn", self.auth_fqdn)
        self.update_index("mgmt_fqdn", self.mgmt_fqdn)
        self.update_index("auth_enabled", self.auth_enabled)
        self.update_index("sync_enabled", self.sync_enabled)
        callback.send("Site added successful.")
        return self._write(callback=callback)

    def add_per_site_objects(self, callback: JobCallback=default_callback):
        """ Add per site objects. """
        #self.add_object_templates(callback=callback)
        self.add_per_site_users(callback=callback)

    def add_per_site_users(self, callback: JobCallback=default_callback):
        """ Add users that exists on all sites (e.g. TOKENSTORE). """
        per_site_users = config.get_per_site_objects("user")
        for user_name in per_site_users:
            # Create user.
            x_user = User(name=user_name,
                        realm=self.realm,
                        site=self.name)
            if x_user.exists():
                continue
            try:
                x_user.add(verify_acls=False, callback=callback)
            except Exception as e:
                msg = (_("Problem adding user: %s") % e)
                config.raise_exception()
                raise OTPmeException(msg)

            if x_user.name != config.token_store_user:
                continue

            # Add token ACLs policy to TOKENSTORE.
            x_user.add_policy("token_acls",
                            verify_acls=False,
                            callback=callback)

    def add_object_templates(self, callback: JobCallback=default_callback):
        """ Add object templates. """
        for object_type in config.tree_object_types:
            object_name = config.get_object_template(object_type)
            if object_name is None:
                continue
            msg = (_("Adding %s template: %s") % (object_type, object_name))
            callback.send(msg)
            class_getter, \
            getter_args = backend.get_class_getter(object_type)
            object_unit = config.get_default_unit("template")
            object_class = class_getter()
            try:
                x_object = object_class(name=object_name,
                                        unit=object_unit,
                                        realm=self.realm,
                                        site=self.name,
                                        template=True)
            except Exception as e:
                config.raise_exception()
                msg = "Error loading object class: %s" % e
                return callback.error(msg)

            if x_object.exists():
                continue
            try:
                x_object.add(verify_acls=False, callback=callback)
            except Exception as e:
                msg = (_("Problem adding user: %s") % e)
                raise OTPmeException(msg)

    @object_lock(full_lock=True)
    def _add(
        self,
        node_name: str,
        site_address: Union[str,None]=None,
        site_fqdn: Union[str,None]=None,
        no_ca: bool=False,
        no_node: bool=False,
        ca_country: Union[str,None]=None,
        ca_state: Union[str,None]=None,
        ca_locality: Union[str,None]=None,
        ca_organization: Union[str,None]=None,
        ca_ou: Union[str,None]=None,
        ca_email: Union[str,None]=None,
        ca_key_len: Union[int,None]=None,
        ca_valid: Union[int,None]=None,
        site_key_len: Union[int,None]=None,
        site_valid: Union[int,None]=None,
        dictionaries: Union[List,None]=None,
        no_dicts: bool=False,
        id_ranges: Union[str,None]=None,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a site. """
        from otpme.lib.classes.dictionary import Dictionary
        if site_key_len is None:
            site_key_len = config.default_site_key_len
        if site_valid is None:
            site_valid = config.default_site_validity
        if ca_valid is None:
            ca_valid = config.default_ca_validity
        if ca_key_len is None:
            ca_key_len = config.default_ca_key_len

        # Disable interactive policies (e.g. reauth).
        if "interactive" not in config.ignore_policy_tags:
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

        if not config.realm_init:
            result = backend.search(object_type="host",
                                    attribute="name",
                                    value=node_name,
                                    realm=self.realm,
                                    site=self.name)
            if result:
                msg = (_("Host already exists: %s") % node_name)
                return callback.error(msg)
            result = backend.search(object_type="node",
                                    attribute="name",
                                    value=node_name,
                                    realm=self.realm,
                                    site=self.name)
            if result:
                msg = (_("Node already exists: %s") % node_name)
                return callback.error(msg)

        # Set site FQDN.
        self.auth_fqdn = site_fqdn
        self.mgmt_fqdn = site_fqdn

        # Set site address.
        self.address = site_address

        # Set flask secrets.
        self.sso_secret = stuff.gen_secret(len=64, encoding="hex")
        self.sso_csrf_secret = stuff.gen_secret(len=64, encoding="hex")
        # Set cluster key.
        self.cluster_key = stuff.gen_secret(len=64, encoding="hex")

        # Set REALM_USERS_GROUP UUID.
        self.user_role_uuid = stuff.gen_uuid()
        # Add site REALM_USER role to REALM_USERS_GROUP.
        if not config.realm_init:
            master_site = self.get_master_site()
            if self.uuid != master_site.uuid:
                realm_users_group = backend.get_object(uuid=master_site.realm_users_group_uuid)
                realm_users_group.add_role(role_uuid=self.user_role_uuid,
                                            callback=callback)
                # Write role object.
                callback.write_modified_objects()
                cache.flush()

        # Set config site.
        config.set_site(name=self.name,
                        uuid=self.uuid,
                        address=self.address,
                        auth_fqdn=self.auth_fqdn,
                        mgmt_fqdn=self.mgmt_fqdn)

        # Add site object BEFORE creating base objects (e.g. site gets default
        # policies).
        OTPmeObject.add(self, enabled=False,
                        verbose_level=verbose_level,
                        callback=callback,
                        **kwargs)

        no_cert = True
        if config.realm_init:
            no_cert = False
        try:
            add_status = self.add_early_objects(id_ranges=id_ranges,
                                                callback=callback)
        except Exception as e:
            config.raise_exception()
            callback.send("Error adding base objects: %s" % e)
            add_status = False

        if not add_status:
            return callback.error("Unable to add base objects.")

        # Create base dicts.
        if no_dicts:
            dictionaries_sorted = []
        else:
            dictionaries_sorted = dictionaries

        # Get base dictionaries.
        base_dictionaries = config.get_base_objects("dictionary")

        for d in dictionaries_sorted:
            if not d in base_dictionaries:
                return callback.error("Unknown dictionary: %s" % d)

        for d in dictionaries_sorted:
            # Get dict type.
            dict_type = base_dictionaries[d]['type']

            dictionary = Dictionary(name=d, realm=self.realm, site=self.name)
            if dictionary.exists():
                dictionary.add_default_policies()
                continue
            if not dictionary.add(verify_acls=False, dict_type=dict_type, callback=callback):
                msg = (_("Problem adding base dictionary '%s'.")
                        % dictionary.path)
                return callback.error(msg)
            # Get path to dictionary file.
            dict_file = "%s/%s.gz" % (config.dictionary_dir, d)

            if not os.path.exists(dict_file):
                msg = (_("No such file or directory: %s") % dict_file)
                return callback.error(msg)

            pbar = None
            title = (_("Processing file: %s ") % os.path.basename(dict_file))
            if config.use_api:
                try:
                    file_size = get_uncompressed_size(dict_file)
                except UnsupportedCompressionType:
                    file_size = os.path.getsize(dict_file)
                pbar = stuff.get_progressbar(maxval=file_size, title=title)
            else:
                callback.send(title)

            from otpme.lib.spsc import SPSC
            spsc = SPSC()
            spsc.import_from_file(filename=dict_file,
                                    dict_name=d,
                                    min_word_len=3,
                                    progressbar=pbar)

            word_list = spsc.dump(d)
            dictionary.add_words(word_list)

        # If we got some dicts add them to the password_strength policy.
        if dictionaries_sorted:
            call_methods = []
            policy_name = "password_strength"
            strength_checker = "spsc"
            strength_checker_dicts = ",".join(dictionaries_sorted)
            strength_checker_opts = 'min_score=2;dict_order=%s' % strength_checker_dicts
            x = {'change_strength_checker': {'strength_checker': strength_checker}},
            call_methods.append(x)
            x = {'change_strength_checker_opts': {'options': strength_checker_opts}},
            call_methods.append(x)

            # Get policy.
            result = backend.search(attribute="name",
                                    value=policy_name,
                                    object_type="policy",
                                    return_type="instance",
                                    realm=config.realm,
                                    site=config.site)
            policy = result[0]

            # Set policy properties.
            for x in call_methods:
                method_name = list(x[0])[0]
                policy_method = getattr(policy, method_name)
                policy_method_args = dict(x[0][method_name])
                policy_method_args['callback'] = callback
                policy_method(verify_acls=False, **policy_method_args)

        # Write objects.
        callback.write_modified_objects()
        cache.flush()

        # Create site CA if not disabled.
        if not no_ca:
            self.create_site_ca(ca_country=ca_country,
                                ca_state=ca_state,
                                ca_locality=ca_locality,
                                ca_organization=ca_organization,
                                ca_ou=ca_ou, ca_email=ca_email,
                                no_cert=no_cert,
                                ca_key_len=ca_key_len,
                                ca_valid=ca_valid,
                                site_key_len=site_key_len,
                                site_valid=site_valid,
                                callback=callback)

        # Create master node if not disabled.
        if not no_node:
            self.create_master_node(node_name=node_name,
                                    callback=callback)
        # Add site using parent class.
        return self._write(callback=callback)

    @object_lock(full_lock=True)
    def add_early_objects(
        self,
        id_ranges: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add site base objects. """
        from otpme.lib.classes.unit import Unit
        all_units = []
        # Create early base units.
        early_units = config.get_base_objects("unit", early=True)
        for u in early_units:
            unit_path = "/%s/%s/%s" % (self.realm, self.name, u)
            unit = Unit(path=unit_path)
            all_units.append(unit)
            if unit.exists():
                #unit.add_default_policies()
                continue
            if not unit.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base unit '%s'.") % unit_path)
                config.raise_exception()
                return callback.error(msg)
        # Add ID range policy.
        id_range_policy = IdrangePolicy(name=BASE_POLICY_NAME,
                                        realm=self.realm,
                                        site=self.name)
        id_range_policy.add(callback=callback)
        if id_ranges is None:
            id_ranges = "uidNumber:s:70000-80000,gidNumber:s:70000-80000"
        id_ranges = id_ranges.split(",")
        for id_range in id_ranges:
            id_range_policy.add_id_range(id_range=id_range)
        id_range_policy._write(callback=callback)
        # Create base policies.
        self.add_base_policies(callback=callback)
        return True

    @object_lock(full_lock=True)
    def add_base_objects(
        self,
        #dictionaries: List=[],
        #no_dicts: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add site base objects. """
        from otpme.lib.classes.unit import Unit
        all_units = []
        # Create early base units.
        early_units = config.get_base_objects("unit", early=True)
        for u in early_units:
            unit_path = "/%s/%s/%s" % (self.realm, self.name, u)
            unit = Unit(path=unit_path)
            all_units.append(unit)
            if unit.exists():
                #unit.add_default_policies()
                continue
            if not unit.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base unit '%s'.") % unit_path)
                config.raise_exception()
                return callback.error(msg)

        # Create base units.
        base_units = config.get_base_objects("unit")
        for u in base_units:
            unit_path = "/%s/%s/%s" % (self.realm, self.name, u)
            unit = Unit(path=unit_path)
            all_units.append(unit)
            if unit.exists():
                #unit.add_default_policies()
                continue
            if not unit.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base unit '%s'.") % unit_path)
                config.raise_exception()
                return callback.error(msg)

        # Add default policies to units.
        default_policies = config.get_default_policies("unit")
        for policy_name in default_policies:
            policy_objects = default_policies[policy_name]
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
            for unit in all_units:
                if policy.uuid in unit.policies:
                    continue
                if policy_objects:
                    if unit.name not in policy_objects:
                        continue
                unit.add_policy(policy.name, verify_acls=False)

        # Default policies to site.
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
        callback.write_modified_objects()
        cache.flush()

        # Create base access groups.
        from otpme.lib.classes.accessgroup import AccessGroup
        base_access_groups = config.get_base_objects("accessgroup")
        for g in base_access_groups:
            template = base_access_groups[g]['template']
            group = AccessGroup(name=g,
                                realm=self.realm,
                                site=self.name,
                                template=template)
            if group.exists():
                group.add_default_policies()
                continue

            if not group.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base accessgroup '%s'.") % g)
                return callback.error(msg)

            # Do not enable sessions for MGMT and JOIN accessgroups.
            if group.name != config.join_access_group \
            and group.name != config.mgmt_access_group:
                group.enable_sessions(verify_acls=False, callback=callback)
                group.change_session_timeout(verify_acls=False,
                                            timeout="1D",
                                            callback=callback)
                group.change_unused_session_timeout(verify_acls=False,
                                                     unused_timeout="1D",
                                                    callback=callback)
            if group.name == config.realm_access_group:
                realm_access_group = group
                # Set max sessions for REALM group to 3.
                group.change_max_sessions(verify_acls=False,
                                        max_sessions=3,
                                        callback=callback)
                # Set relogin timeout for REALM group to 1 second.
                group.change_relogin_timeout(verify_acls=False,
                                            relogin_timeout="1m",
                                            callback=callback)
            if group.name == config.sso_access_group:
                sso_access_group = group
                # Set max sessions for SSO portal group to 3.
                group.change_max_sessions(verify_acls=False,
                                        max_sessions=3,
                                        callback=callback)
                # Set relogin timeout for SSO portal to 1 second.
                group.change_relogin_timeout(verify_acls=False,
                                            relogin_timeout="1m",
                                            callback=callback)
                # Enable session master for SSO portal.
                group.enable_session_master(verify_acls=False,
                                            callback=callback)
            if group.name == config.ldap_access_group:
                # Set max sessions for ldap (ldaptor) group to 3.
                group.change_max_sessions(verify_acls=False,
                                        max_sessions=3,
                                        callback=callback)
                # Set relogin timeout for ldap group to 1 second.
                group.change_relogin_timeout(verify_acls=False,
                                            relogin_timeout="1m",
                                            callback=callback)
            if group.name != config.realm_access_group \
            and group.name != config.sso_access_group \
            and group.name != config.join_access_group:
                # Add some base groups as child groups of REALM group.
                realm_access_group.add_child_group(verify_acls=False,
                                                    group_name=group.name,
                                                    callback=callback)
        # Create base clients.
        from otpme.lib.classes.client import Client
        base_clients = config.get_base_objects("client")
        for c in base_clients:
            template = base_clients[c]['template']
            attributes = base_clients[c]['attributes']
            client = Client(name=c,
                            realm=self.realm,
                            site=self.name,
                            template=template,
                            **attributes)
            if client.exists():
                client.add_default_policies()
                continue

            if not client.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base client '%s'.") % c)
                return callback.error(msg)

            ## Set accessgroup of client.
            #access_group = base_clients[c]['attributes']['accessgroup']
            #client.change_access_group(access_group=access_group,
            #                            verify_acls=False)
        # Create scripts.
        from otpme.lib.classes.script import Script
        for script_name in os.listdir(config.script_dir):
            script_path = "%s/%s" % (config.script_dir, script_name)
            script = Script(name=script_name,
                            site=self.name,
                            realm=self.realm)
            if script.exists():
                script.add_default_policies()
                continue

            # Try to read script as base64 encoded string.
            try:
                fd = open(script_path, "r")
                script_base64 = encode(fd.read(), "base64")
                fd.close()
            except Exception as e:
                fd.close()
                msg = (_("Error reading script file: %s") % e)
                return callback.error(msg)
            # Add script.
            try:
                script.add(script_base64, verify_acls=False, callback=callback)
            except Exception as e:
                msg = (_("Error adding script: %s") % e)
                logger.critical(msg, exc_info=True)
                return callback.error(msg)

        # Create base groups.
        self.add_base_groups(callback=callback)

        # Add per-site users group.
        users_group = Group(name=config.users_group,
                    realm=self.realm,
                    site=self.name)
        if users_group.exists():
            users_group.add_default_policies()
        else:
            if not users_group.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding site users group '%s'.") % users_group.path)
                return callback.error(msg)

        # Create base roles.
        from otpme.lib.classes.role import Role
        base_roles = config.get_base_objects("role")
        for r in base_roles:
            template = base_roles[r]['template']
            roles_unit = config.get_default_unit("role")
            role_path = "/%s/%s/%s/%s" % (self.realm,
                                        self.name,
                                        roles_unit, r)
            # Select role UUID set by _add(). This is required because we
            # add REALM_USER role to REALM_USERS_GROUP on master site.
            role_uuid = None
            if r == config.realm_user_role:
                role_uuid = self.user_role_uuid

            # Add role.
            role = Role(path=role_path, template=template, uuid=role_uuid)
            if not role.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base role '%s'.") % role.path)
                return callback.error(msg)

            # Add some base roles to realm access group by default.
            if role.name == config.site_admin_role \
            or role.name == config.realm_user_role:
                result = backend.search(object_type="accessgroup",
                                        attribute="name",
                                        value=config.realm_access_group,
                                        realm=self.realm,
                                        site=self.name,
                                        return_type="instance")
                if not result:
                    msg = (_("Unable to find realm accessgroup."))
                    return callback.error(msg)

                realm_access_group = result[0]
                realm_access_group.add_role(role_name=role.name,
                                            verify_acls=False,
                                            callback=callback)
            # Set site admin role.
            if role.name == config.site_admin_role:
                site_admin_role = role
                self.admin_role_uuid = role.uuid
            # Set realm users role.
            if role.name == config.realm_user_role:
                realm_user_role = role
            # Set SSO users role.
            if role.name == config.sso_user_role:
                sso_user_role = role
                self.sso_user_role_uuid = role.uuid

        # Add site REALM_USER role to REALM_USERS_GROUP.
        master_site = self.get_master_site()
        if self.uuid == master_site.uuid:
            realm_users_group = backend.get_object(uuid=master_site.realm_users_group_uuid)
            realm_users_group.add_role(realm_user_role.name,
                                        verify_acls=False,
                                        callback=callback)
        # Add REALM_USER role to site users group.
        users_group.add_role(realm_user_role.name,
                            verify_acls=False,
                            callback=callback)
        users_group._write(callback=callback)
        # Add SSO_USER role to SSO accessgroup.
        sso_access_group.add_role(sso_user_role.name,
                            verify_acls=False,
                            callback=callback)
        sso_access_group._write(callback=callback)

        self.add_object_templates(callback=callback)

        # Run base policies post methods.
        self.add_base_policies(callback=callback)
        for policy in self._base_policies_post_methods:
            post_methods = self._base_policies_post_methods[policy]
            for x in post_methods:
                method_name = list(x[0])[0]
                policy_method = getattr(policy, method_name)
                policy_method_args = dict(x[0][method_name])
                policy_method_args['callback'] = callback
                policy_method(verify_acls=False, **policy_method_args)

        # Add default policies to base policies.
        base_policies = config.get_base_objects("policy")
        for policy_name in base_policies:
            result = backend.search(object_type="policy",
                                    attribute="name",
                                    value=policy_name,
                                    return_type="instance")
            if not result:
                continue
            policy = result[0]
            policy.add_default_policies(callback=callback)

        # Write objects.
        callback.write_modified_objects()
        cache.flush()

        callback.send("Adding default ACLs...")

        # Add default ACLs to allow view of some objects for realm users.
        # FIXME: Make this list a register method (e.g. get all unit default ACLs.)
        view_objects = [
			"unit",
			"user",
			"role",
			"group",
			"accessgroup",
			"script",
			"ca",
			"client",
			"host",
			"node",
			"policy",
			"dictionary",
			"resolver",
			]
        for o in view_objects:
            acl = "role:%s:++%s:view_public" % (realm_user_role.uuid, o)
            self.add_acl(acl=acl,
                        recursive_acls=True,
                        apply_default_acls=True,
                        object_types=view_objects,
                        verify_acls=False,
                        verbose_level=1,
                        callback=callback)

        # Add ACLs to view LDIF attributes.
        view_objects = [ "unit", "user", "group" ]
        for o in view_objects:
            acl = "role:%s:++%s:view:attribute" % (realm_user_role.uuid, o)
            self.add_acl(acl=acl,
                        recursive_acls=True,
                        apply_default_acls=True,
                        object_types=view_objects,
                        verify_acls=False,
                        verbose_level=1,
                        callback=callback)

        # Add ACLs to view public site infos.
        view_roles = [ realm_user_role, site_admin_role ]
        for r in view_roles:
            acl = "role:%s:view_public" % r.uuid
            self.add_acl(acl=acl,
                        recursive_acls=False,
                        apply_default_acls=False,
                        verify_acls=False,
                        verbose_level=1,
                        callback=callback)

        # Add "dump" ACLs for default scripts.
        acl = "role:%s:dump" % realm_user_role.uuid
        for script_name in os.listdir(config.script_dir):
            _script = backend.search(object_type="script",
                                    attribute="name",
                                    value=script_name,
                                    return_type="instance",
                                    realm=self.realm,
                                    site=self.name)[0]
            _script.add_acl(acl=acl,
                        recursive_acls=False,
                        apply_default_acls=False,
                        verify_acls=False,
                        verbose_level=1,
                        callback=callback)
        # Write objects.
        callback.write_modified_objects()
        cache.flush()

        # Add internal users.
        internal_users = config.get_internal_objects("user")
        per_site_users = config.get_per_site_objects("user")
        for user_name in internal_users:
            if user_name in per_site_users:
                continue
            # Create internal user.
            x_user = User(name=user_name,
                        realm=self.realm,
                        site=self.name)
            if x_user.exists():
                x_user.add_default_policies()
                continue
            try:
                x_user.add(verify_acls=False, callback=callback, **kwargs)
            except Exception as e:
                msg = (_("Problem adding user: %s") % e)
                raise OTPmeException(msg)

        # Create admin user.
        return self.add_admin_user(callback=callback)

    def add_base_policies(self, callback: JobCallback=default_callback):
        """ Add base policies. """
        from otpme.lib import policy as _policy
        base_policies = config.get_base_objects("policy")
        for policy_name in base_policies:
            policy_config = base_policies[policy_name]
            policy_type = policy_config['type']
            call_methods = policy_config['call_methods']

            # Get policy class.
            policy_class = _policy.get_class(policy_type)

            # Create policy instance.
            policy = policy_class(name=policy_name,
                                    realm=self.realm,
                                    site=self.name)
            # Add post methods to run (e.g. add group to policy that is not yet
            # created).
            try:
                post_methods = policy_config['post_methods']
                self._base_policies_post_methods[policy] = post_methods
            except KeyError:
                pass

            # Check if object exists.
            if policy.exists():
                continue

            if not policy.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base policy '%s'.") % policy.name)
                return callback.error(msg)

            # Set policy properties.
            for x in call_methods:
                method_name = list(x[0])[0]
                policy_method = getattr(policy, method_name)
                policy_method_args = dict(x[0][method_name])
                policy_method_args['callback'] = callback
                policy_method(verify_acls=False, **policy_method_args)

        # Write objects.
        callback.write_modified_objects()
        cache.flush()

    @object_lock(full_lock=True)
    def add_base_groups(self, callback: JobCallback=default_callback):
        """ Create base groups. """
        master_site = self.get_master_site()
        base_groups = config.get_base_objects("group")
        for g in base_groups:
            # Realm users group is only needed on master site.
            if g == config.realm_users_group:
                if self.uuid != master_site.uuid:
                    continue
            template = base_groups[g]['template']
            group = Group(name=g,
                        realm=self.realm,
                        site=self.name,
                        template=template)
            if group.exists():
                group.add_default_policies()
                continue

            if not group.add(verify_acls=False, callback=callback):
                msg = (_("Problem adding base group '%s'.") % group.path)
                return callback.error(msg)

            # Set realm users group UUID.
            if group.name == config.realm_users_group:
                if self.uuid == master_site.uuid:
                    self.realm_users_group_uuid = group.uuid
                else:
                    self.realm_users_group_uuid = master_site.realm_users_group_uuid

    @object_lock(full_lock=True)
    def add_admin_user(self, callback: JobCallback=default_callback):
        """ Create site admin user. """
        # Create admin user.
        msg = (_("Adding admin user: %s") % config.admin_user_name)
        callback.send(msg)
        admin_user = User(name=config.admin_user_name,
                            realm=self.realm,
                            site=self.name)
        if not admin_user.exists():
            try:
                admin_user.add(add_default_token=True,
                                gen_qrcode=True,
                                verify_acls=False,
                                callback=callback)
            except Exception as e:
                msg = (_("Problem adding admin user: %s") % e)
                config.raise_exception()
                return callback.error(msg)

        # Write objects.
        callback.write_modified_objects()
        cache.flush()

        # Get admin user token UUID.
        admin_token_name = self.get_config_parameter('default_token_name')
        admin_token = admin_user.token(token_name=admin_token_name)
        self.admin_token_uuid = admin_token.uuid
        config.admin_token_uuid = admin_token.uuid

        # Get JOIN accessgroup.
        result = backend.search(object_type="accessgroup",
                                attribute="name",
                                value=config.join_access_group,
                                return_type="instance",
                                realm=self.realm,
                                site=self.name)
        if not result:
            msg = ("Unable to find %s accessgroup." % config.join_access_group)
            return callback.error(msg)

        join_accessgroup = result[0]

        # Add admin token to JOIN access group.
        join_accessgroup.add_token(token_path=admin_token.rel_path,
                                    run_policies=False,
                                    verify_acls=False)

        # Write objects.
        callback.write_modified_objects()
        cache.flush()

        # Whitelist admin token in auth_on_action policy.
        try:
            auth_on_action_policy = backend.get_object(object_type="policy",
                                                        realm=self.realm,
                                                        site=self.name,
                                                        name="auth_on_action")
        except:
            auth_on_action_policy = None

        if auth_on_action_policy:
            auth_on_action_policy.add_whitelist(token_path=admin_token.rel_path,
                                                verify_acls=False)

        # Write objects.
        callback.write_modified_objects()
        cache.flush()

        return self._write(callback=callback)

    @check_acls(['add:fido2_ca_cert'])
    @object_lock()
    def add_fido2_ca_cert(
        self,
        ca_cert: str,
        force: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if isinstance(ca_cert, str):
            ca_cert = ca_cert.encode()
        try:
            x_cert = x509.load_pem_x509_certificate(ca_cert)
        except Exception as e:
            msg = "Failed to load PEM cert: %s" % e
            return callback.error(msg)
        if x_cert.subject.rfc4514_string() in self.fido2_ca_certs:
            msg = "Cert already added."
            return callback.error(msg)
        self.fido2_ca_certs[x_cert.subject.rfc4514_string()] = ca_cert.decode()
        return self._cache(callback=callback)

    @check_acls(['delete:fido2_ca_cert'])
    @object_lock()
    def del_fido2_ca_cert(
        self,
        subject: str,
        force: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        try:
            self.fido2_ca_certs.pop(subject)
        except KeyError:
            msg = "Unknown CA cert: %s" % subject
            return callback.error(msg)
        return self._cache(callback=callback)

    @check_acls(['view:fido2_ca_cert'])
    @object_lock()
    def get_fido2_ca_certs(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        subjects = list(self.fido2_ca_certs.keys())
        subjects = "\n".join(subjects)
        return callback.ok(subjects)

    # FIXME: make sure we remove all references before deleting a site
    @check_acls(['delete:object'])
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
        """ Delete site. """
        # We should never delete ourselves ;)
        if config.site == self.name:
            return callback.error("Cannot delete own site!")

        # Get parent object to check ACLs.
        if verify_acls:
            if not self.verify_acl("delete:object"):
                msg = (_("Permission denied: %s") % self.name)
                return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.confirmation_policy != "force":
                if self.confirmation_policy == "paranoid":
                    msg = "Please type '%s' to delete object: " % self.name
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
                else:
                    msg = (_("Delete site '%s'?: ") % self.name)
                    answer = callback.ask(msg)
                    if answer.lower() != "y":
                        return callback.abort()

        # Get all objects of this site.
        result = backend.search(attribute="uuid",
                                value="*",
                                realm=config.realm,
                                site=self.name)
        objects = {}
        for x in result:
            object_id = backend.get_oid(x, instance=True)
            object_type = object_id.object_type
            if object_id.site != self.name:
                continue
            if not object_type in objects:
                objects[object_type] = []
            objects[object_type].append(object_id)

        # Delete objects in the correct order.
        for object_type in reversed(config.object_add_order):
            if not object_type in objects:
                continue
            for object_id in objects[object_type]:
                msg = "Deleting: %s" % object_id
                callback.send(msg)
                if config.auth_token:
                    deleted_by = "token:%s" % config.auth_token.rel_path
                else:
                    deleted_by = "API"
                trash.add(object_id, deleted_by)
                backend.delete_object(object_id, cluster=True)

        # Delete object using parent class.
        return super(Site, self).delete(verbose_level=verbose_level,
                                    force=force, callback=callback)

    @check_acls(['delete:orphans'])
    @object_lock()
    def remove_orphans(
        self,
        force: bool=False,
        recursive: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
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
                msg = (_("%s%s|%s: Found the following orphan ACLs: %s\n")
                        % (msg, self.type, self.name, ",".join(acl_list)))

            if msg:
                answer = callback.ask(_("%sRemove?: ") % msg)
                if answer.lower() != "y":
                    remove_orphans = False

        if remove_orphans:
            if self.remove_orphan_acls(force=True, verbose_level=verbose_level,
                                        callback=callback, **kwargs):
                object_changed = True

        if recursive:
            all_units = backend.search(attribute="uuid",
                                        object_type="unit",
                                        value="*",
                                        return_type="instance",
                                        realm=config.realm,
                                        site=self.name)
            for unit in all_units:
                # Skip all non top level units..
                if unit and unit.unit:
                    continue
                if verbose_level > 1:
                    callback.send(_("Processing %s") % unit.oid)
                if unit.remove_orphans(force=force,
                                        verbose_level=verbose_level,
                                        recursive=recursive,
                                        callback=callback, **kwargs):
                    object_changed = True
        if not object_changed:
            msg = (_("No orphan objects found for %s: %s")
                    % (self.type, self.name))
            return callback.ok(msg)

        return self._write(callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show site config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        admin_token = ""
        if self.admin_token_uuid:
            if self.verify_acl("view:admin_token"):
                token = backend.get_object(object_type="token",
                                    uuid=self.admin_token_uuid)
                if token:
                    admin_token = token.rel_path

        admin_role = ""
        if self.admin_role_uuid:
            if self.verify_acl("view:admin_role"):
                role = backend.get_object(object_type="role",
                                    uuid=self.admin_role_uuid)
                if role:
                    admin_role = role.rel_path

        user_role = ""
        if self.user_role_uuid:
            if self.verify_acl("view:user_role"):
                role = backend.get_object(object_type="role",
                                    uuid=self.user_role_uuid)
                if role:
                    user_role = role.rel_path

        site_ca = ""
        if self.ca:
            if self.verify_acl("view:ca"):
                ca = backend.get_object(object_type="ca", uuid=self.ca)
                if ca:
                    site_ca = ca.rel_path

        cluster_key = ""
        if self.verify_acl("view:cluster_key") \
        or self.verify_acl("edit:cluster_key"):
            cluster_key = self.cluster_key

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

        trusted_sites = []
        if self.verify_acl("view:trust") \
        or self.verify_acl("add:trust") \
        or self.verify_acl("delete:trust"):
            for x in self.trusted_sites:
                s = backend.get_object(object_type="site", uuid=x)
                if s:
                    trusted_sites.append(s.name)
                else:
                    trusted_sites.append(x)
        lines.append('TRUSTED_SITES="%s"' % ",".join(trusted_sites))

        if self.verify_acl("view:address") \
        or self.verify_acl("edit:address"):
            lines.append('ADDRESS="%s"' % self.address)
        else:
            lines.append('ADDRESS=""')

        if self.verify_acl("view:sso_secret") \
        or self.verify_acl("edit:sso_secret"):
            lines.append('SSO_SECRET="%s"' % self.sso_secret)
        else:
            lines.append('SSO_SECRET=""')

        if self.verify_acl("view:sso_csrf_secret") \
        or self.verify_acl("edit:sso_csrf_secret"):
            lines.append('SSO_CSRF_SECRET="%s"' % self.sso_csrf_secret)
        else:
            lines.append('SSO_CSRF_SECRET=""')

        lines.append('CA="%s"' % site_ca)
        lines.append('ADMIN_ROLE="%s"' % admin_role)
        lines.append('USER_ROLE="%s"' % user_role)
        lines.append('ADMIN_TOKEN="%s"' % admin_token)

        lines.append('CLUSTER_KEY="%s"' % cluster_key)

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show site details """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
