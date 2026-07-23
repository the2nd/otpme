# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import magic
import base64
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
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.protocols.utils import register_commands
from otpme.lib.daemon.clusterd import cluster_radius_reload
from otpme.lib.classes.otpme_object import OTPmeClientObject
from otpme.lib.classes.otpme_object import name_len_setter
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
                                "roles",
                                "tokens",
                                "accessgroups",
                                "scopes",
                                "secret",
                                "login_url",
                                "auth_cache",
                                "auth_cache_timeout",
                                "sso_enabled",
                                "sso_popup",
                                "sso_name",
                                "helper_url",
                                "address",
                                "dot1x_auth",
                                "oidc_auth",
                                "oidc_redirect_uris",
                                "oidc_logout_redirect_uris",
                                "oidc_auth_method",
                                "oidc_id_token_alg",
                                "oidc_subject_type",
                                "oidc_sector_identifier_uri",
                                "oidc_backchannel_logout_uri",
                                "oidc_backchannel_tls_verify",
                                "oidc_force_backchannel_logout",
                                "oidc_backchannel_ca_cert",
                                "oidc_grant_types",
                                "oidc_response_types",
                                ],
                    "dump"      : [
                                "sso_logo",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                "role",
                                "token",
                                "address",
                                "sso_logo",
                                "oidc_redirect_uri",
                                "oidc_logout_redirect_uri",
                                "oidc_grant_type",
                                "oidc_response_type",
                                ],
                    "remove"    : [
                                "role",
                                "token",
                                ],
                    "delete"    : [
                                "address",
                                "sso_logo",
                                "oidc_redirect_uri",
                                "oidc_logout_redirect_uri",
                                "oidc_grant_type",
                                "oidc_response_type",
                                ],
                    "enable"    : [
                                "sso",
                                "sso_popup",
                                "auth_cache",
                                "dot1x_auth",
                                "oidc_auth",
                                "oidc_backchannel_tls_verify",
                                "oidc_force_backchannel_logout",
                                ],
                    "disable"   : [
                                "sso",
                                "sso_popup",
                                "auth_cache",
                                "dot1x_auth",
                                "oidc_auth",
                                "oidc_backchannel_tls_verify",
                                "oidc_force_backchannel_logout",
                                ],
                    "edit"      : [
                                "config",
                                "accessgroup",
                                "secret",
                                "login_url",
                                "helper_url",
                                "sso_name",
                                "auth_cache_timeout",
                                "oidc_auth_method",
                                "oidc_id_token_alg",
                                "oidc_subject_type",
                                "oidc_sector_identifier_uri",
                                "oidc_backchannel_logout_uri",
                                "oidc_backchannel_ca_cert",
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
                    'oargs'             : ['address', 'unit', 'enable_oidc', 'scopes', 'add_scopes', 'no_default_scopes'],
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
                                        'max_scopes',
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
    'show_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : ['parameter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_oidc'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_oidc',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_oidc'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_oidc',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_dot1x'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_dot1x',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_dot1x'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_dot1x',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_oidc_force_backchannel_logout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_oidc_force_backchannel_logout',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_oidc_force_backchannel_logout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_oidc_force_backchannel_logout',
                    'job_type'          : 'thread',
                    },
                },
            },
    'auth_cache_timeout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_auth_cache_timeout',
                    'args'              : ['timeout'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_auth_cache'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_auth_cache',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_auth_cache'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_auth_cache',
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
    'sso_logo'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_sso_logo',
                    'args'              : ['image_data'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'dump_sso_logo'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump_sso_logo',
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_sso_logo'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_sso_logo',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_sso'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sso',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_sso'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sso',
                    'job_type'          : 'thread',
                    },
                },
            },
    'sso_name'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_sso_name',
                    'oargs'             : ['sso_name'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'login_url'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_login_url',
                    'oargs'             : ['login_url'],
                    'job_type'          : 'process',
                    },
                },
            },
    'helper_url'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_helper_url',
                    'oargs'             : ['helper_url'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_sso_popup'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_sso_popup',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_sso_popup'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_sso_popup',
                    'job_type'          : 'thread',
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
    'add_oidc_redirect_uri'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_oidc_redirect_uri',
                    'args'              : ['uri'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_oidc_redirect_uri'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_oidc_redirect_uri',
                    'args'              : ['uri'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_oidc_redirect_uris'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_oidc_redirect_uris',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_oidc_logout_redirect_uri'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_oidc_logout_redirect_uri',
                    'args'              : ['uri'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_oidc_logout_redirect_uri'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_oidc_logout_redirect_uri',
                    'args'              : ['uri'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_oidc_logout_redirect_uris'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_oidc_logout_redirect_uris',
                    'job_type'          : 'process',
                    },
                },
            },
    'oidc_auth_method'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_oidc_auth_method',
                    'args'              : ['method'],
                    'job_type'          : 'process',
                    },
                },
            },
    'oidc_id_token_alg'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_oidc_id_token_alg',
                    'args'              : ['alg'],
                    'job_type'          : 'process',
                    },
                },
            },
    'oidc_subject_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_oidc_subject_type',
                    'args'              : ['subject_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'oidc_sector_identifier_uri'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_oidc_sector_identifier_uri',
                    'oargs'             : ['uri', 'validate', 'clear'],
                    'job_type'          : 'process',
                    },
                },
            },
    'oidc_backchannel_logout_uri'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_oidc_backchannel_logout_uri',
                    'oargs'             : ['uri', 'clear'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_oidc_backchannel_tls_verify'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_oidc_backchannel_tls_verify',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_oidc_backchannel_tls_verify'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_oidc_backchannel_tls_verify',
                    'job_type'          : 'thread',
                    },
                },
            },
    'oidc_backchannel_ca_cert'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_oidc_backchannel_ca_cert',
                    'oargs'             : ['ca_cert', 'clear'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_oidc_grant_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_oidc_grant_type',
                    'args'              : ['grant_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_oidc_grant_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_oidc_grant_type',
                    'args'              : ['grant_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_oidc_grant_types'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_oidc_grant_types',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_oidc_response_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_oidc_response_type',
                    'args'              : ['response_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_oidc_response_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_oidc_response_type',
                    'args'              : ['response_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_oidc_response_types'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_oidc_response_types',
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
    'list_scopes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'list_scopes',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type'],
                    'dargs'             : {'return_type':'name', 'include_roles':False, 'skip_disabled':False},
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
    config_params = config.get_config_parameters("client")
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
    acls += config.get_default_acls("client")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("client")
    return acls

DEFAULT_UNIT = "clients"
REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                "otpme.lib.classes.group",
                ]

def register():
    register_oid()
    config.register_config_parameter(name="max_client_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("client", commands)
    # Register index attributes.
    config.register_index_attribute("address")
    config.register_index_attribute("oidc_auth")
    config.register_index_attribute("sso_enabled")
    config.register_index_attribute("auth_cache_enabled")
    config.register_index_attribute("auth_cache_timeout")
    config.register_recursive_default_acl("site", "+client")
    config.register_default_acl("unit", "+client")
    config.register_recursive_default_acl("unit", "+client")

def register_hooks():
    config.register_auth_on_action_hook("client", "add_role")
    config.register_auth_on_action_hook("client", "remove_role")
    config.register_auth_on_action_hook("client", "add_token")
    config.register_auth_on_action_hook("client", "remove_token")
    config.register_auth_on_action_hook("client", "add_address")
    config.register_auth_on_action_hook("client", "del_address")
    config.register_auth_on_action_hook("client", "add_oidc_redirect_uri")
    config.register_auth_on_action_hook("client", "del_oidc_redirect_uri")
    config.register_auth_on_action_hook("client", "add_oidc_logout_redirect_uri")
    config.register_auth_on_action_hook("client", "del_oidc_logout_redirect_uri")
    config.register_auth_on_action_hook("client", "change_oidc_auth_method")
    config.register_auth_on_action_hook("client", "change_oidc_id_token_alg")
    config.register_auth_on_action_hook("client", "change_oidc_subject_type")
    config.register_auth_on_action_hook("client", "change_oidc_sector_identifier_uri")
    config.register_auth_on_action_hook("client", "change_oidc_backchannel_logout_uri")
    config.register_auth_on_action_hook("client", "enable_oidc_force_backchannel_logout")
    config.register_auth_on_action_hook("client", "disable_oidc_force_backchannel_logout")
    config.register_auth_on_action_hook("client", "enable_oidc_backchannel_tls_verify")
    config.register_auth_on_action_hook("client", "disable_oidc_backchannel_tls_verify")
    config.register_auth_on_action_hook("client", "change_oidc_backchannel_ca_cert")
    config.register_auth_on_action_hook("client", "add_oidc_grant_type")
    config.register_auth_on_action_hook("client", "del_oidc_grant_type")
    config.register_auth_on_action_hook("client", "add_oidc_response_type")
    config.register_auth_on_action_hook("client", "del_oidc_response_type")
    config.register_auth_on_action_hook("client", "change_secret")
    config.register_auth_on_action_hook("client", "enable_dot1x")
    config.register_auth_on_action_hook("client", "disable_dot1x")
    config.register_auth_on_action_hook("client", "enable_oidc")
    config.register_auth_on_action_hook("client", "disable_oidc")
    config.register_auth_on_action_hook("client", "enable_auth_cache")
    config.register_auth_on_action_hook("client", "disable_auth_cache")
    config.register_auth_on_action_hook("client", "change_auth_cache_timeout")
    config.register_auth_on_action_hook("client", "change_login_url")
    config.register_auth_on_action_hook("client", "add_sso_logo")
    config.register_auth_on_action_hook("client", "del_sso_logo")
    config.register_auth_on_action_hook("client", "dump_sso_logo")
    config.register_auth_on_action_hook("client", "enable_sso")
    config.register_auth_on_action_hook("client", "disable_sso")
    config.register_auth_on_action_hook("client", "enable_sso_popup")
    config.register_auth_on_action_hook("client", "disable_sso_popup")
    config.register_auth_on_action_hook("client", "change_helper_url")
    config.register_auth_on_action_hook("client", "change_access_group")
    config.register_auth_on_action_hook("client", "show_secret")
    config.register_auth_on_action_hook("client", "limit_logins")
    config.register_auth_on_action_hook("client", "unlimit_logins")
    config.register_auth_on_action_hook("client", "set_config_parameter")

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
    client_path_re = f'{unit_path_re}[/]{client_name_re}'
    client_oid_re = f'client|{client_path_re}'
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
    def path_getter(client_oid, client_uuid):
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

@match_class_typing
class Client(OTPmeClientObject):
    """ Creates client object """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        name: Union[str,None]=None,
        realm: Union[str,None]=None,
        unit: Union[str,None]=None,
        site: Union[str,None]=None,
        path: Union[str,None]=None,
        access_group: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class).
        self.type = "client"

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

        self.track_last_used = True

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
        self.sso_name = self.name
        self.sso_enabled = False
        self.sso_popup = False
        self.login_url = None
        self.helper_url = None
        self.auth_cache_timeout = 60
        self.auth_cache_enabled = False
        self.dot1x_auth = False
        self.oidc_auth = False
        self.oidc_token_endpoint_auth_method = "client_secret_basic"
        self.oidc_id_token_signed_response_alg = "RS256"
        self.oidc_subject_type = "public"
        self.oidc_sector_identifier_uri = None
        self.oidc_backchannel_logout_uri = None
        self.oidc_backchannel_tls_verify = True
        self.oidc_backchannel_ca_cert = None
        self.oidc_force_backchannel_logout = False

        self._sync_fields = {
                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "TOKENS",
                            "ROLES",
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
                        'SECRET'                    : {
                                                        'var_name'  : 'secret',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },
                        'DOT1X_AUTH'                : {
                                                        'var_name'  : 'dot1x_auth',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'OIDC_AUTH'                : {
                                                        'var_name'  : 'oidc_auth',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'OIDC_REDIRECT_URIS'       : {
                                                        'var_name'  : 'oidc_redirect_uris',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'OIDC_LOGOUT_REDIRECT_URIS': {
                                                        'var_name'  : 'oidc_logout_redirect_uris',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'OIDC_TOKEN_ENDPOINT_AUTH_METHOD' : {
                                                        'var_name'  : 'oidc_token_endpoint_auth_method',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG' : {
                                                        'var_name'  : 'oidc_id_token_signed_response_alg',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OIDC_SUBJECT_TYPE'        : {
                                                        'var_name'  : 'oidc_subject_type',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OIDC_SECTOR_IDENTIFIER_URI' : {
                                                        'var_name'  : 'oidc_sector_identifier_uri',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OIDC_BACKCHANNEL_LOGOUT_URI' : {
                                                        'var_name'  : 'oidc_backchannel_logout_uri',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OIDC_FORCE_BACKCHANNEL_LOGOUT' : {
                                                        'var_name'  : 'oidc_force_backchannel_logout',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'OIDC_BACKCHANNEL_TLS_VERIFY' : {
                                                        'var_name'  : 'oidc_backchannel_tls_verify',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'OIDC_BACKCHANNEL_CA_CERT'   : {
                                                        'var_name'  : 'oidc_backchannel_ca_cert',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OIDC_GRANT_TYPES'         : {
                                                        'var_name'  : 'oidc_grant_types',
                                                        'type'      : list,
                                                        'default'   : ["authorization_code", "refresh_token"],
                                                        'required'  : False,
                                                    },
                        'OIDC_RESPONSE_TYPES'      : {
                                                        'var_name'  : 'oidc_response_types',
                                                        'type'      : list,
                                                        'default'   : ["code"],
                                                        'required'  : False,
                                                    },
                        'AUTH_CACHE_ENABLED'        : {
                                                        'var_name'  : 'auth_cache_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'AUTH_CACHE_TIMEOUT'        : {
                                                        'var_name'  : 'auth_cache_timeout',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },
                        'SSO_LOGO'                  : {
                                                        'var_name'  : 'sso_logo',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
                        'SSO_NAME'                  : {
                                                        'var_name'  : 'sso_name',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'SSO_ENABLED'               : {
                                                        'var_name'  : 'sso_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'LOGIN_URL'                 : {
                                                        'var_name'  : 'login_url',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'HELPER_URL'                : {
                                                        'var_name'  : 'helper_url',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'SSO_POPUP'                 : {
                                                        'var_name'  : 'sso_popup',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
            }

        return super()._get_object_config(object_config=object_config)

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

    def _set_name(self, name: str):
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
        result = super()._write(**kwargs)
        if not self.radius_reload:
            return result
        self.radius_reload = False
        cluster_radius_reload()
        return result

    # FIXME: check if IP is valid!!!
    @object_lock()
    @check_acls(['add:address'])
    @audit_log()
    @object_changelog()
    def add_address(
        self,
        address: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Adds a address to this client. """
        if address in self.addresses:
            msg = _("Address '{address}' already added to this client.")
            msg = msg.format(address=address)
            return callback.error(msg)
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
    @audit_log()
    @object_changelog()
    def del_address(
        self,
        address: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Deletes a address from this client. """
        if not address in self.addresses:
            msg = _("Address '{address}' is not an address of this client.")
            msg = msg.format(address=address)
            return callback.error(msg)
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

    @staticmethod
    def _validate_oidc_redirect_uri(uri: str):
        """ Validate an OIDC redirect URI per RFC 6749 + 8252.

        Reject anything that isn't http/https, has a fragment, or
        uses http with a non-loopback host. Returns nothing on
        success, raises OTPmeException on failure.
        """
        from urllib.parse import urlparse
        try:
            parsed = urlparse(uri)
        except Exception:
            msg = _("Invalid redirect URI: {uri}")
            msg = msg.format(uri=uri)
            raise OTPmeException(msg) from None
        if parsed.scheme not in ("http", "https"):
            msg = _("Redirect URI must use http or https: {uri}")
            msg = msg.format(uri=uri)
            raise OTPmeException(msg)
        if not parsed.hostname:
            msg = _("Redirect URI must include a host: {uri}")
            msg = msg.format(uri=uri)
            raise OTPmeException(msg)
        if parsed.fragment:
            msg = _("Redirect URI must not contain a fragment: {uri}")
            msg = msg.format(uri=uri)
            raise OTPmeException(msg)
        loopback_hosts = ("localhost", "127.0.0.1", "::1")
        if parsed.scheme == "http" and parsed.hostname not in loopback_hosts:
            msg = _("http redirect URI only allowed for loopback hosts: {uri}")
            msg = msg.format(uri=uri)
            raise OTPmeException(msg)

    @object_lock()
    @check_acls(['add:oidc_redirect_uri'])
    @audit_log()
    @object_changelog()
    def add_oidc_redirect_uri(
        self,
        uri: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add an OIDC redirect URI to this client. """
        try:
            self._validate_oidc_redirect_uri(uri)
        except OTPmeException as e:
            return callback.error(str(e))
        if uri in self.oidc_redirect_uris:
            msg = _("Redirect URI '{uri}' already added to this client.")
            msg = msg.format(uri=uri)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_oidc_redirect_uri",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_redirect_uris.append(uri)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['delete:oidc_redirect_uri'])
    @audit_log()
    @object_changelog()
    def del_oidc_redirect_uri(
        self,
        uri: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Remove an OIDC redirect URI from this client. """
        if uri not in self.oidc_redirect_uris:
            msg = _("Redirect URI '{uri}' is not registered for this client.")
            msg = msg.format(uri=uri)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_oidc_redirect_uri",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_redirect_uris.remove(uri)
        return self._cache(callback=callback)

    @check_acls(['view:oidc_redirect_uris'])
    @audit_log()
    def show_oidc_redirect_uris(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Return the list of registered OIDC redirect URIs. """
        return callback.ok(list(self.oidc_redirect_uris))

    @object_lock()
    @check_acls(['add:oidc_logout_redirect_uri'])
    @audit_log()
    @object_changelog()
    def add_oidc_logout_redirect_uri(
        self,
        uri: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add an OIDC post-logout redirect URI to this client. """
        try:
            self._validate_oidc_redirect_uri(uri)
        except OTPmeException as e:
            return callback.error(str(e))
        if uri in self.oidc_logout_redirect_uris:
            msg = _("Logout redirect URI '{uri}' already added to this client.")
            msg = msg.format(uri=uri)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_oidc_logout_redirect_uri",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_logout_redirect_uris.append(uri)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['delete:oidc_logout_redirect_uri'])
    @audit_log()
    @object_changelog()
    def del_oidc_logout_redirect_uri(
        self,
        uri: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Remove an OIDC post-logout redirect URI from this client. """
        if uri not in self.oidc_logout_redirect_uris:
            msg = _("Logout redirect URI '{uri}' is not registered for this client.")
            msg = msg.format(uri=uri)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_oidc_logout_redirect_uri",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_logout_redirect_uris.remove(uri)
        return self._cache(callback=callback)

    @check_acls(['view:oidc_logout_redirect_uris'])
    @audit_log()
    def show_oidc_logout_redirect_uris(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Return the list of registered OIDC post-logout redirect URIs. """
        return callback.ok(list(self.oidc_logout_redirect_uris))

    @object_lock()
    @check_acls(['edit:oidc_auth_method'])
    @audit_log()
    @object_changelog()
    def change_oidc_auth_method(
        self,
        method: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set the OIDC token endpoint authentication method.

        Allowed values:
            client_secret_basic  -- HTTP Basic auth with secret (default)
            client_secret_post   -- secret in form body
            none                 -- public client; PKCE always required
        """
        allowed = ("client_secret_basic", "client_secret_post", "none")
        if method not in allowed:
            msg = _("Invalid OIDC auth method '{method}'. Allowed: {allowed}")
            msg = msg.format(method=method, allowed=", ".join(allowed))
            return callback.error(msg)
        if method == self.oidc_token_endpoint_auth_method:
            msg = _("OIDC auth method already set to '{method}'.")
            msg = msg.format(method=method)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_oidc_auth_method",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_token_endpoint_auth_method = method
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['edit:oidc_id_token_alg'])
    @audit_log()
    @object_changelog()
    def change_oidc_id_token_alg(
        self,
        alg: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set the JWT signing algorithm for ID tokens issued to this
        client.

        Allowed values:
            RS256 (default), RS384, RS512  -- RSA + SHA
            ES256, ES384, ES512            -- ECDSA + SHA
            EdDSA                          -- Ed25519

        The site MUST have an active signing key with a matching alg
        for issuance to succeed; this is checked at sign-time, not
        here, so that an admin can configure alg before adding the
        matching key to the site.
        """
        allowed = ("RS256", "RS384", "RS512",
                   "ES256", "ES384", "ES512",
                   "EdDSA")
        if alg not in allowed:
            msg = _("Invalid OIDC ID token alg '{alg}'. Allowed: {allowed}")
            msg = msg.format(alg=alg, allowed=", ".join(allowed))
            return callback.error(msg)
        if alg == self.oidc_id_token_signed_response_alg:
            msg = _("OIDC ID token alg already set to '{alg}'.")
            msg = msg.format(alg=alg)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_oidc_id_token_alg",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_id_token_signed_response_alg = alg
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['edit:oidc_subject_type'])
    @audit_log()
    @object_changelog()
    def change_oidc_subject_type(
        self,
        subject_type: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set the OIDC subject type used for the ``sub`` claim.

        Allowed values:
            public    -- stable user identifier; same sub across RPs
            pairwise  -- per-sector HMAC-derived sub; different per RP

        For pairwise the site needs an oidc_pairwise_secret; this is
        checked at sign-time, not here.
        """
        allowed = ("public", "pairwise")
        if subject_type not in allowed:
            msg = _("Invalid OIDC subject type '{subject_type}'. Allowed: {allowed}")
            msg = msg.format(subject_type=subject_type, allowed=", ".join(allowed))
            return callback.error(msg)
        if subject_type == self.oidc_subject_type:
            msg = _("OIDC subject type already set to '{subject_type}'.")
            msg = msg.format(subject_type=subject_type)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_oidc_subject_type",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_subject_type = subject_type
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['edit:oidc_sector_identifier_uri'])
    @audit_log()
    @object_changelog()
    def change_oidc_sector_identifier_uri(
        self,
        uri: str=None,
        validate: bool=False,
        clear: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set or clear the OIDC sector identifier URI.

        Required only for ``subject_type=pairwise`` when the RP spans
        multiple hosts and wants the same ``sub`` across them.

        With ``validate=True`` the URI is fetched immediately and
        every registered redirect URI must appear in the JSON array
        it returns (per OIDC Core 8.1). Default is lazy: stored
        without round-trip, validation deferred to sign-time.
        """
        from urllib.parse import urlparse
        if clear:
            new_value = None
        else:
            if not uri:
                msg = _("Either provide a URI or use --clear.")
                return callback.error(msg)
            try:
                parsed = urlparse(uri)
            except Exception:
                msg = _("Invalid URI: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            if parsed.scheme != "https":
                msg = _("Sector identifier URI must use https: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            if not parsed.hostname:
                msg = _("Sector identifier URI must include a host: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            if validate:
                err = self._validate_sector_identifier_uri(uri)
                if err:
                    return callback.error(err)
            new_value = uri

        if new_value == self.oidc_sector_identifier_uri:
            msg = _("Sector identifier URI already set to '{uri}'.")
            msg = msg.format(uri=new_value)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_oidc_sector_identifier_uri",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_sector_identifier_uri = new_value
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['edit:oidc_backchannel_logout_uri'])
    @audit_log()
    @object_changelog()
    def change_oidc_backchannel_logout_uri(
        self,
        uri: str=None,
        clear: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set or clear the OIDC backchannel logout URI.

        The OP POSTs a signed Logout Token to this URL when the user
        logs out, so the RP can terminate its local session
        server-to-server (independent of any browser).

        Strict HTTPS-only (no loopback exception like for
        ``redirect_uri``); the URL is fetched server-to-server so
        TLS termination at the RP host is the only viable transport.
        """
        from urllib.parse import urlparse
        if clear:
            new_value = None
        else:
            if not uri:
                msg = _("Either provide a URI or use --clear.")
                return callback.error(msg)
            try:
                parsed = urlparse(uri)
            except Exception:
                msg = _("Invalid URI: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            if parsed.scheme != "https":
                msg = _("Backchannel logout URI must use https: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            if not parsed.hostname:
                msg = _("Backchannel logout URI must include a host: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            if parsed.fragment:
                msg = _("Backchannel logout URI must not contain a fragment: {uri}")
                msg = msg.format(uri=uri)
                return callback.error(msg)
            new_value = uri

        if new_value == self.oidc_backchannel_logout_uri:
            msg = _("Backchannel logout URI already set to '{uri}'.")
            msg = msg.format(uri=new_value)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_oidc_backchannel_logout_uri",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_backchannel_logout_uri = new_value
        return self._cache(callback=callback)

    @check_acls(['enable:oidc_backchannel_tls_verify'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_oidc_backchannel_tls_verify(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable TLS certificate verification for back-channel logout. """
        if self.oidc_backchannel_tls_verify:
            msg = _("Backchannel TLS verification already enabled.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_oidc_backchannel_tls_verify",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_backchannel_tls_verify = True
        return self._write(callback=callback)

    @check_acls(['disable:oidc_backchannel_tls_verify'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_oidc_backchannel_tls_verify(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable TLS certificate verification for back-channel logout.

        Intended for lab/dev RPs with self-signed certs. In production,
        prefer pinning the RP's CA via change_oidc_backchannel_ca_cert.
        """
        if not self.oidc_backchannel_tls_verify:
            msg = _("Backchannel TLS verification already disabled.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_oidc_backchannel_tls_verify",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_backchannel_tls_verify = False
        return self._write(callback=callback)

    @check_acls(['enable:oidc_force_backchannel_logout'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_oidc_force_backchannel_logout(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable forced back-channel logout. """
        if self.oidc_force_backchannel_logout:
            msg = _("Backchannel logout already forced.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_oidc_force_backchannel_logout",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_force_backchannel_logout = True
        return self._write(callback=callback)

    @check_acls(['disable:oidc_force_backchannel_logout'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_oidc_force_backchannel_logout(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable forced back-channel logout. """
        if not self.oidc_force_backchannel_logout:
            msg = _("Forced backchannel logout already disabled.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_oidc_force_backchannel_logout",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_force_backchannel_logout = False
        return self._write(callback=callback)

    @object_lock()
    @check_acls(['edit:oidc_backchannel_ca_cert'])
    @audit_log()
    @object_changelog()
    def change_oidc_backchannel_ca_cert(
        self,
        ca_cert: str=None,
        clear: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set or clear a PEM CA bundle used to verify the RP's TLS
        cert on back-channel logout. When set, this CA bundle replaces
        the system trust store for this client's backchannel POST --
        use it to pin to an internal/private CA.

        Has no effect when oidc_backchannel_tls_verify is disabled.
        """
        if clear:
            new_value = None
        else:
            if not ca_cert:
                msg = _("Either provide a CA cert (PEM) or use --clear.")
                return callback.error(msg)
            # Minimal sanity check -- full parsing happens at dispatch
            # time. We just reject obviously-wrong input here.
            if "-----BEGIN CERTIFICATE-----" not in ca_cert:
                msg = _("CA cert must be PEM-encoded.")
                return callback.error(msg)
            new_value = ca_cert

        if new_value == self.oidc_backchannel_ca_cert:
            msg = _("Backchannel CA cert unchanged.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_oidc_backchannel_ca_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_backchannel_ca_cert = new_value
        return self._cache(callback=callback)

    OIDC_GRANT_TYPES_WHITELIST = (
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
    )

    OIDC_RESPONSE_TYPES_WHITELIST = (
        "code",
        # Future: ``code id_token`` (Hybrid Flow) and ``id_token``
        # (Implicit Flow). Only ``code`` is implemented today (sso1.py
        # /authorize_validate hardcodes the check, discovery
        # advertises only this); adding values here without the
        # corresponding handler logic and discovery update would be a
        # configuration footgun.
    )

    @object_lock()
    @check_acls(['add:oidc_grant_type'])
    @audit_log()
    @object_changelog()
    def add_oidc_grant_type(
        self,
        grant_type: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Allow an OIDC grant type for this client. """
        if grant_type not in self.OIDC_GRANT_TYPES_WHITELIST:
            msg = _("Invalid OIDC grant type '{grant_type}'. Allowed: {allowed}")
            msg = msg.format(grant_type=grant_type,
                             allowed=", ".join(self.OIDC_GRANT_TYPES_WHITELIST))
            return callback.error(msg)
        if grant_type in self.oidc_grant_types:
            msg = _("Grant type '{grant_type}' already enabled for this client.")
            msg = msg.format(grant_type=grant_type)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_oidc_grant_type",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_grant_types.append(grant_type)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['delete:oidc_grant_type'])
    @audit_log()
    @object_changelog()
    def del_oidc_grant_type(
        self,
        grant_type: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable an OIDC grant type for this client. """
        if grant_type not in self.oidc_grant_types:
            msg = _("Grant type '{grant_type}' is not enabled for this client.")
            msg = msg.format(grant_type=grant_type)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_oidc_grant_type",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_grant_types.remove(grant_type)
        return self._cache(callback=callback)

    @check_acls(['view:oidc_grant_types'])
    @audit_log()
    def show_oidc_grant_types(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Return the list of allowed OIDC grant types. """
        return callback.ok(list(self.oidc_grant_types))

    @object_lock()
    @check_acls(['add:oidc_response_type'])
    @audit_log()
    @object_changelog()
    def add_oidc_response_type(
        self,
        response_type: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Allow an OIDC response type for this client. """
        if response_type not in self.OIDC_RESPONSE_TYPES_WHITELIST:
            msg = _("Invalid OIDC response type '{response_type}'. Allowed: {allowed}")
            msg = msg.format(response_type=response_type,
                             allowed=", ".join(self.OIDC_RESPONSE_TYPES_WHITELIST))
            return callback.error(msg)
        if response_type in self.oidc_response_types:
            msg = _("Response type '{response_type}' already enabled for this client.")
            msg = msg.format(response_type=response_type)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_oidc_response_type",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_response_types.append(response_type)
        return self._cache(callback=callback)

    @object_lock()
    @check_acls(['delete:oidc_response_type'])
    @audit_log()
    @object_changelog()
    def del_oidc_response_type(
        self,
        response_type: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable an OIDC response type for this client. """
        if response_type not in self.oidc_response_types:
            msg = _("Response type '{response_type}' is not enabled for this client.")
            msg = msg.format(response_type=response_type)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_oidc_response_type",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.oidc_response_types.remove(response_type)
        return self._cache(callback=callback)

    @check_acls(['view:oidc_response_types'])
    @audit_log()
    def show_oidc_response_types(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Return the list of allowed OIDC response types. """
        return callback.ok(list(self.oidc_response_types))

    def _validate_sector_identifier_uri(self, uri: str):
        """ Fetch the sector identifier URI and check inclusion of all
        registered redirect URIs. Returns None on success or an error
        message string on failure. """
        import json
        from urllib.request import Request, urlopen
        try:
            req = Request(uri, headers={"Accept": "application/json"})
            with urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            return _("Could not fetch sector identifier URI: {err}").format(err=e)
        try:
            published = json.loads(body)
        except Exception as e:
            return _("Sector identifier URI did not return valid JSON: {err}").format(err=e)
        if not isinstance(published, list):
            return _("Sector identifier URI must return a JSON array of redirect URIs.")
        published_set = {str(x) for x in published}
        missing = [u for u in self.oidc_redirect_uris if u not in published_set]
        if missing:
            return _("Sector identifier URI is missing these registered redirect URIs: {missing}").format(
                missing=", ".join(missing))
        return None

    @object_lock()
    @check_acls(['edit:accessgroup'])
    @audit_log()
    @object_changelog()
    def change_access_group(
        self,
        access_group: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change client access group. """
        from otpme.lib.classes.accessgroup import AccessGroup
        if access_group == self.access_group:
            msg = _("Group '{access_group}' is already access group of this client.")
            msg = msg.format(access_group=access_group)
            return callback.error(msg)
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
                msg = _("Group '{group_uuid}' does not exist.")
                msg = msg.format(group_uuid=self.access_group_uuid)
                return callback.error(msg)
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

    @check_acls(['edit:auth_cache_timeout'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def change_auth_cache_timeout(
        self,
        timeout: int=60,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable auth cache. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_auth_cache_timeout",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.auth_cache_timeout = timeout
        self.update_index("auth_cache_timeout", self.auth_cache_timeout)

        return self._write(callback=callback)

    @check_acls(['enable:dot1x_auth'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_dot1x(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable dot1x auth. """
        if self.dot1x_auth:
            msg = (_("Dot1x auth already enabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_dot1x",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.dot1x_auth = True
        self.update_index("dot1x_auth", self.dot1x_auth)

        return self._write(callback=callback)

    @check_acls(['disable:dot1x_auth'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_dot1x(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable dot1x auth. """
        if not self.dot1x_auth:
            msg = (_("Dot1x auth already disabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_dot1x",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.dot1x_auth = False
        self.update_index("dot1x_auth", self.dot1x_auth)

        return self._write(callback=callback)

    @check_acls(['enable:oidc_auth'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_oidc(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable OIDC auth. """
        if self.oidc_auth:
            msg = (_("OIDC auth already enabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_oidc",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.oidc_auth = True
        self.update_index("oidc_auth", self.oidc_auth)

        return self._write(callback=callback)

    @check_acls(['disable:oidc_auth'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_oidc(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable OIDC auth. """
        if not self.oidc_auth:
            msg = (_("OIDC auth already disabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_oidc",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.oidc_auth = False
        self.update_index("oidc_auth", self.oidc_auth)

        return self._write(callback=callback)

    @check_acls(['enable:auth_cache'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_auth_cache(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable auth cache. """
        if self.auth_cache_enabled:
            msg = (_("Auth cache already enabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_auth_cache",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.auth_cache_enabled = True
        self.update_index("auth_cache_enabled", self.auth_cache_enabled)

        return self._write(callback=callback)

    @check_acls(['disable:auth_cache'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_auth_cache(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable auth cache. """
        if not self.auth_cache_enabled:
            msg = (_("Auth cache already disabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_auth_cache",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.auth_cache_enabled = False
        self.update_index("auth_cache_enabled", self.auth_cache_enabled)

        return self._write(callback=callback)

    @check_acls(['add:sso_logo'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def add_sso_logo(
        self,
        image_data: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_sso_logo",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Check if data is base64 and decode.
        if stuff.is_base64(image_data):
            image_data = base64.b64decode(image_data)

        magic_handler = magic.Magic(mime=True, uncompress=True)
        image_type = magic_handler.from_buffer(image_data)
        if isinstance(image_data, str):
            image_data = image_data.encode()
        image_base64 = base64.b64encode(image_data)
        image_base64 = image_base64.decode()
        self.sso_logo['image_data'] = image_base64
        self.sso_logo['image_type'] = image_type

        return self._write(callback=callback)

    @check_acls(['del:sso_logo'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def del_sso_logo(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_sso_logo",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.sso_logo = {}

        return self._write(callback=callback)

    @check_acls(['dump:sso_logo'])
    @object_lock()
    @audit_log()
    def dump_sso_logo(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("dump_sso_logo",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if not self.sso_logo:
            msg = _("No logo set.")
            return callback.error(msg)

        return callback.ok(self.sso_logo)

    @check_acls(['edit:sso_name'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def change_sso_name(
        self,
        sso_name: str,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_sso_name",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.sso_name = sso_name

        return self._write(callback=callback)

    @check_acls(['enable:sso'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_sso(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable SSO portal app. """
        if self.sso_enabled:
            msg = (_("SSO already enabled."))
            return callback.error(msg)

        if not self.login_url:
            msg = _("Login URL not configured.")
            return callback.error(msg)

        if not self.helper_url:
            msg = _("Helper URL not configured.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sso",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.sso_enabled = True
        self.update_index("sso_enabled", self.sso_enabled)

        return self._write(callback=callback)

    @check_acls(['disable:sso'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_sso(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable SSO portal app. """
        if not self.sso_enabled:
            msg = (_("SSO already disabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sso",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.sso_enabled = False
        self.update_index("sso_enabled", self.sso_enabled)

        return self._write(callback=callback)

    @object_lock()
    @check_acls(acls=['edit:login_url'])
    @audit_log()
    @object_changelog()
    def change_login_url(
        self,
        login_url: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change object login_url """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_login_url",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Set new login_url.
        self.login_url = login_url

        return self._cache(callback=callback)

    @object_lock()
    @check_acls(acls=['edit:helper_url'])
    @audit_log()
    @object_changelog()
    def change_helper_url(
        self,
        helper_url: str=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change object helper_url """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_helper_url",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Set new helper_url.
        self.helper_url = helper_url

        return self._cache(callback=callback)

    @check_acls(['enable:sso_popup'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def enable_sso_popup(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Enable SSO portal app. """
        if self.sso_popup:
            msg = (_("SSO popup already enabled."))
            return callback.error(msg)

        if not self.login_url:
            msg = _("Login URL not configured.")
            return callback.error(msg)

        if not self.helper_url:
            msg = _("Helper URL not configured.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_sso_popup",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.sso_popup = True

        return self._write(callback=callback)

    @check_acls(['disable:sso_popup'])
    @object_lock()
    @audit_log()
    @object_changelog()
    def disable_sso_popup(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Disable SSO portal app. """
        if not self.sso_popup:
            msg = (_("SSO popup already disabled."))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_sso_popup",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        self.sso_popup = False

        return self._write(callback=callback)

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
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
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
    def add(
        self,
        address: Union[str,None]=None,
        enable_oidc: bool=False,
        scopes: Union[list,None]=None,
        add_scopes: Union[list,None]=None,
        no_default_scopes: bool=False,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a client. """
        if address:
            result = backend.search(object_type="client",
                                    attribute="address",
                                    value=address,
                                    return_type="name")
            if result:
                existing_client = result[0]
                msg = f"Client with this address already exists: {existing_client}"
                return callback.error(msg)

        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        self.secret = stuff.gen_secret(32)
        # Add object using parent class.
        add_result = super().add(verbose_level=verbose_level,
                                            callback=callback, **kwargs)
        if not add_result:
            msg = _("Failed to add client.")
            return callback.error(msg)

        if address:
            self.add_address(address)
            msg = f"Radius secret: {self.secret}"
            callback.send(msg)
        if enable_oidc:
            self.enable_oidc()
            # Resolve scopes:
            #   --scopes <list>      -> replaces defaults entirely
            #   --no-default-scopes  -> drops defaults
            #   --add-scopes <list>  -> appended on top of whatever's left
            if scopes is None:
                if no_default_scopes:
                    scopes = []
                else:
                    scopes = self.get_config_parameter("oidc_default_scopes") or []
            scopes = set(scopes) | set(add_scopes or [])
            # Pre-validate all named scopes exist before mutating any.
            scope_objs = []
            for x in scopes:
                scope = backend.get_object(object_type="scope",
                                        name=x,
                                        realm=config.realm,
                                        site=config.site)
                if scope is None:
                    msg = _("Scope '{name}' does not exist.")
                    msg = msg.format(name=x)
                    return callback.error(msg)
                scope_objs.append(scope)
            for scope in scope_objs:
                scope.add_client(client_name=self.name,
                                callback=callback)
        elif scopes or add_scopes:
            msg = _("Warning: --scopes/--add-scopes ignored because --enable-oidc was not set.")
            callback.send(msg)
        # Make sure radius gets reloaded
        self.radius_reload = True
        return callback.ok()

    @object_lock()
    @check_acls(['add:role'])
    def add_role(
        self,
        role_name: str=None,
        role_uuid: str=None,
        return_uuid: bool=False,
        verbose_level: int=0,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a role to objects member roles list and add role to default scopes. """
        add_status = super().add_role(role_name=role_name,
                                        role_uuid=role_uuid,
                                        return_uuid=True,
                                        verbose_level=verbose_level,
                                        _caller=_caller,
                                        callback=callback,
                                        **kwargs)
        if not add_status:
            return callback.error()

        role_uuid = add_status
        role_oid = backend.get_oid(uuid=role_uuid, instance=True)

        scopes = self.get_scopes(include_roles=False,
                                skip_disabled=True,
                                return_type="uuid")

        for scope_uuid in scopes:
            scope = backend.get_object(uuid=scope_uuid)
            if not scope:
                continue
            if not scope.auto_member:
                continue
            scope.add_role(role_name=role_oid.name,
                            verify_acls=False,
                            callback=callback)
        if return_uuid:
            return role_uuid
        return callback.ok()

    @check_acls(['add:token'])
    @object_lock()
    def add_token(
        self,
        token_path: str,
        return_uuid: bool=False,
        force: bool=False,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a token to objects member tokens list and add token to default scopes. """
        add_status = super().add_token(token_path=token_path,
                                        return_uuid=True,
                                        force=force,
                                        _caller=_caller,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs)
        if not add_status:
            return callback.error()

        token_uuid = add_status
        token_oid = backend.get_oid(uuid=token_uuid, instance=True)

        scopes = self.get_scopes(include_roles=False,
                                skip_disabled=True,
                                return_type="uuid")

        for scope_uuid in scopes:
            scope = backend.get_object(uuid=scope_uuid)
            if not scope:
                continue
            if not scope.auto_member:
                continue
            scope.add_token(token_path=token_oid.rel_path,
                            verify_acls=False,
                            callback=callback)
        if return_uuid:
            return token_uuid
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
        """ Delete client. """
        if not self.exists():
            return callback.error("Client does not exist.")

        base_clients = config.get_base_objects("client")
        if self.name in base_clients:
            return callback.error("Cannot delete base client.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {client_name}")
                    msg = msg.format(client_name=self.name)
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
        # Make sure radius gets reloaded.
        cluster_radius_reload()
        return result

    def show_config(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Show client config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

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

        access_group = ""
        if self.verify_acl("view:accessgroups") \
        or self.verify_acl("edit:accessgroup"):
            access_group = str(self.access_group)
        lines.append(f'ACCESS_GROUP="{access_group}"')

        addresses = ""
        if self.verify_acl("view:address") \
        or self.verify_acl("add:address") \
        or self.verify_acl("remove:address"):
            addresses = ",".join(self.addresses)
        lines.append(f'ADDRESSES="{addresses}"')

        secret = ""
        if self.verify_acl("view_all:secret"):
            secret = str(self.secret)
        lines.append(f'SECRET="{secret}"')

        lines.append(f'TOKENS="{token_list}"')
        lines.append(f'ROLES="{role_list}"')

        auth_cache_enabled = ""
        if self.verify_acl("view:auth_cache") \
        or self.verify_acl("enable:auth_cache") \
        or self.verify_acl("disable:auth_cache"):
            auth_cache_enabled = self.auth_cache_enabled
        lines.append(f'AUTH_CACHE_ENABLED="{auth_cache_enabled}"')

        dot1x_auth = ""
        if self.verify_acl("view:dot1x_auth") \
        or self.verify_acl("enable:dot1x_auth") \
        or self.verify_acl("disable:dot1x_auth"):
            dot1x_auth = self.dot1x_auth
        lines.append(f'DOT1X_AUTH="{dot1x_auth}"')

        oidc_auth = ""
        if self.verify_acl("view:oidc_auth") \
        or self.verify_acl("enable:oidc_auth") \
        or self.verify_acl("disable:oidc_auth"):
            oidc_auth = self.oidc_auth
        lines.append(f'OIDC_AUTH="{oidc_auth}"')

        oidc_redirect_uris = ""
        if self.verify_acl("view:oidc_redirect_uris") \
        or self.verify_acl("add:oidc_redirect_uri") \
        or self.verify_acl("delete:oidc_redirect_uri"):
            oidc_redirect_uris = ",".join(self.oidc_redirect_uris)
        lines.append(f'OIDC_REDIRECT_URIS="{oidc_redirect_uris}"')

        oidc_logout_redirect_uris = ""
        if self.verify_acl("view:oidc_logout_redirect_uris") \
        or self.verify_acl("add:oidc_logout_redirect_uri") \
        or self.verify_acl("delete:oidc_logout_redirect_uri"):
            oidc_logout_redirect_uris = ",".join(self.oidc_logout_redirect_uris)
        lines.append(f'OIDC_LOGOUT_REDIRECT_URIS="{oidc_logout_redirect_uris}"')

        oidc_auth_method = ""
        if self.verify_acl("view:oidc_auth_method") \
        or self.verify_acl("edit:oidc_auth_method"):
            oidc_auth_method = self.oidc_token_endpoint_auth_method
        lines.append(f'OIDC_TOKEN_ENDPOINT_AUTH_METHOD="{oidc_auth_method}"')

        oidc_id_token_alg = ""
        if self.verify_acl("view:oidc_id_token_alg") \
        or self.verify_acl("edit:oidc_id_token_alg"):
            oidc_id_token_alg = self.oidc_id_token_signed_response_alg
        lines.append(f'OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG="{oidc_id_token_alg}"')

        oidc_subject_type = ""
        if self.verify_acl("view:oidc_subject_type") \
        or self.verify_acl("edit:oidc_subject_type"):
            oidc_subject_type = self.oidc_subject_type
        lines.append(f'OIDC_SUBJECT_TYPE="{oidc_subject_type}"')

        oidc_sector_identifier_uri = ""
        if self.verify_acl("view:oidc_sector_identifier_uri") \
        or self.verify_acl("edit:oidc_sector_identifier_uri"):
            oidc_sector_identifier_uri = self.oidc_sector_identifier_uri or ""
        lines.append(f'OIDC_SECTOR_IDENTIFIER_URI="{oidc_sector_identifier_uri}"')

        oidc_backchannel_logout_uri = ""
        if self.verify_acl("view:oidc_backchannel_logout_uri") \
        or self.verify_acl("edit:oidc_backchannel_logout_uri"):
            oidc_backchannel_logout_uri = self.oidc_backchannel_logout_uri or ""
        lines.append(f'OIDC_BACKCHANNEL_LOGOUT_URI="{oidc_backchannel_logout_uri}"')

        oidc_force_backchannel_logout = ""
        if self.verify_acl("view:oidc_force_backchannel_logout") \
        or self.verify_acl("enable:oidc_force_backchannel_logout") \
        or self.verify_acl("disable:oidc_force_backchannel_logout"):
            oidc_force_backchannel_logout = self.oidc_force_backchannel_logout
        lines.append(f'OIDC_FORCE_BACKCHANNEL_LOGOUT="{oidc_force_backchannel_logout}"')

        oidc_backchannel_tls_verify = ""
        if self.verify_acl("view:oidc_backchannel_tls_verify") \
        or self.verify_acl("enable:oidc_backchannel_tls_verify") \
        or self.verify_acl("disable:oidc_backchannel_tls_verify"):
            oidc_backchannel_tls_verify = self.oidc_backchannel_tls_verify
        lines.append(f'OIDC_BACKCHANNEL_TLS_VERIFY="{oidc_backchannel_tls_verify}"')

        oidc_backchannel_ca_cert = ""
        if self.verify_acl("view:oidc_backchannel_ca_cert") \
        or self.verify_acl("edit:oidc_backchannel_ca_cert"):
            # Render only a presence flag -- the PEM itself can be many
            # KB and clutters the listing.
            oidc_backchannel_ca_cert = "set" if self.oidc_backchannel_ca_cert else ""
        lines.append(f'OIDC_BACKCHANNEL_CA_CERT="{oidc_backchannel_ca_cert}"')

        oidc_grant_types = ""
        if self.verify_acl("view:oidc_grant_types") \
        or self.verify_acl("add:oidc_grant_type") \
        or self.verify_acl("delete:oidc_grant_type"):
            oidc_grant_types = ",".join(self.oidc_grant_types)
        lines.append(f'OIDC_GRANT_TYPES="{oidc_grant_types}"')

        oidc_response_types = ""
        if self.verify_acl("view:oidc_response_types") \
        or self.verify_acl("add:oidc_response_type") \
        or self.verify_acl("delete:oidc_response_type"):
            oidc_response_types = ",".join(self.oidc_response_types)
        lines.append(f'OIDC_RESPONSE_TYPES="{oidc_response_types}"')

        sso_name = ""
        if self.verify_acl("view:sso_name"):
            sso_name = self.sso_name
        lines.append(f'SSO_NAME="{sso_name}"')

        sso_enabled = ""
        if self.verify_acl("view:sso_enabled"):
            sso_enabled = self.sso_enabled
        lines.append(f'SSO_ENABLED="{sso_enabled}"')

        sso_popup = ""
        if self.verify_acl("view:sso_popup"):
            sso_popup = self.sso_popup
        lines.append(f'SSO_POPUP="{sso_popup}"')

        login_url = ""
        if self.verify_acl("view:login_url"):
            login_url = self.login_url
        lines.append(f'LOGIN_URL="{login_url}"')

        helper_url = ""
        if self.verify_acl("view:helper_url"):
            helper_url = self.helper_url
        lines.append(f'HELPER_URL="{helper_url}"')

        return super().show_config(config_lines=lines,
                                        callback=callback, **kwargs)

    def show(self, **kwargs):
        """ Show client details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
