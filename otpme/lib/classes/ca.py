# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.pki import utils
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
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

logger = config.logger

default_callback = config.get_callback()

read_acls = []

write_acls = [
        "create_cert",
        "create_ca_cert",
        "create_server_cert",
        "create_client_cert",
        "create_node_cert",
        "create_host_cert",
        "update_crl",
        "renew",
        "revoke",
        ]

read_value_acls = {
                    "view"      : [
                                    "country",
                                    "state",
                                    "locality",
                                    "organization",
                                    "ou",
                                    "email",
                                    "cert",
                                    "key",
                                    "crl",
                                ],
        }

write_value_acls = {
                    "renew"     : [ "cert" ],
                    "revoke"    : [ "cert" ],
                    "edit"      : [ "crl_validity" ],
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
                    'method'            : cli.show_getter("ca"),
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
                    'method'            : cli.list_getter("ca"),
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
                    'method'            : cli.list_getter("ca"),
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
                    'args'              : ['passphrase'],
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
    'dump_crl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_crl',
                    'job_type'          : 'process',
                    },
                },
            },
    'crl_validity'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_crl_validity',
                    'args'              : ['crl_validity'],
                    'job_type'          : 'process',
                    },
                },
            },
    'update_crl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'update_crl',
                    'job_type'          : 'process',
                    },
                },
            },
    'revoke'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'revoke_cert',
                    'args'              : ['object_unit'],
                    'job_type'          : 'process',
                    },
                },
            },
    'renew'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'renew_cert',
                    'args'              : ['object_unit'],
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

VALID_CERT_KEY_LENS = [
                        1024,
                        2048,
                        4096,
                        8192,
                    ]
# FIXME: we need to consider which types we need to support.
VALID_SIGN_ALGOS = [
                        #'md2',
                        #'md5',
                        #'sha',
                        #'sha1',
                        #'sha224',
                        'sha256',
                        'sha384',
                        'sha512',
                        #'dss',
                        #'dss1',
                        #'mdc2',
                        #'ripemd160',
                    ]

DEFAULT_UNIT = "cas"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                ]

def register():
    register_oid()
    register_hooks()
    register_config()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("ca", commands)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("ca", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT, early=True)

def register_config():
    """ Registger config stuff. """
    # Object types our config parameters are valid for.
    object_types = [
                        'realm',
                        'site',
                        'unit',
                        'ca',
                    ]
    # Length for certificate keys.
    config.register_config_parameter(name="cert_key_len",
                                    ctype=int,
                                    default_value=2048,
                                    valid_values=VALID_CERT_KEY_LENS,
                                    object_types=object_types)
    # Sign algorithm for certificates.
    config.register_config_parameter(name="cert_sign_algo",
                                    ctype=str,
                                    default_value="sha256",
                                    valid_values=VALID_SIGN_ALGOS,
                                    object_types=object_types)
    # Sign algorithm for CRLs.
    config.register_config_parameter(name="crl_sign_algo",
                                    ctype=str,
                                    default_value="sha256",
                                    valid_values=VALID_SIGN_ALGOS,
                                    object_types=object_types)
    # Default certificate settings.
    config.register_config_var("default_ca_validity", int, 5475)
    config.register_config_var("default_ca_key_len", int, 4096)
    config.register_config_var("default_node_validity", int, 5475)
    config.register_config_var("default_node_key_len", int, 4096)
    config.register_config_var("default_host_validity", int, 5475)
    config.register_config_var("default_host_key_len", int, 4096)
    config.register_config_var("default_client_validity", int, 5475)
    config.register_config_var("default_client_key_len", int, 4096)
    config.register_config_var("default_server_validity", int, 5475)
    config.register_config_var("default_server_key_len", int, 4096)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    ca_name_re = '([0-9A-Za-z]([0-9A-Za-z_.-]*[0-9A-Za-z]){0,})'
    ca_path_re = '%s[/]%s' % (unit_path_re, ca_name_re)
    ca_oid_re = 'ca|%s' % ca_path_re
    oid.register_oid_schema(object_type="ca",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=ca_name_re,
                            path_regex=ca_path_re,
                            oid_regex=ca_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="ca",
                                getter=rel_path_getter)
def register_hooks():
    config.register_auth_on_action_hook("ca", "create_cert")
    config.register_auth_on_action_hook("ca", "create_ca_cert")
    config.register_auth_on_action_hook("ca", "create_server_cert")
    config.register_auth_on_action_hook("ca", "create_client_cert")
    config.register_auth_on_action_hook("ca", "update_crl")
    config.register_auth_on_action_hook("ca", "revoke_cert")

def register_backend():
    """ Register object for the file backend. """
    ca_dir_extension = "ca"
    def path_getter(ca_oid):
        return backend.config_path_getter(ca_oid, ca_dir_extension)
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                'group',
                ]
        return backend.rebuild_object_index("ca", objects, after)
    # Register object to config.
    config.register_object_type(object_type="ca",
                            tree_object=True,
                            add_after=["unit"],
                            sync_after=["unit"],
                            uniq_name=True,
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Ca
    backend.register_object_type(object_type="ca",
                                dir_name_extension=ca_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="ca")

class Ca(OTPmeObject):
    """ Creates CA object """
    commands = commands
    def __init__(self, object_id=None, path=None, name=None,
        unit=None, site=None, realm=None, **kwargs):
        # Set our type (used in parent class)
        self.type = "ca"

        # Call parent class init.
        super(Ca, self).__init__(object_id=object_id,
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

        # SSL cert defaults
        self.country = None
        self.state = None
        self.locality = None
        self.organization = None
        self.ou = None
        self.email = None

        # CAs should not inherit ACLs by default.
        self.acl_inheritance_enabled = False
        self.crl = None
        self.crl_validity = 3650
        self.last_crl_update = 0.0
        # Objects we can handle certificates for.
        self.supported_objects = [ 'node', 'host' ]

        self._sync_fields = {
                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            "CRL",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
            'CRL'                       : {
                                            'var_name'  : 'crl',
                                            'type'      : str,
                                            'required'  : False,
                                            'encoding'  : 'BASE64',
                                        },

            'REVOKED_CERTS'             : {
                                            'var_name'  : 'revoked_certs',
                                            'type'      : dict,
                                            'required'  : False,
                                        },

            'COUNTRY'                   : {
                                            'var_name'  : 'country',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'STATE'                     : {
                                            'var_name'  : 'state',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'LOCALITY'                  : {
                                            'var_name'  : 'locality',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'ORGANIZATION'              : {
                                            'var_name'  : 'organization',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'OU'                        : {
                                            'var_name'  : 'ou',
                                            'type'      : str,
                                            'required'  : False,
                                        },

            'EMAIL'                     : {
                                            'var_name'  : 'email',
                                            'type'      : str,
                                            'required'  : False,
                                        },
            'CRL_VALIDITY'              : {
                                            'var_name'  : 'crl_validity',
                                            'type'      : int,
                                            'required'  : False,
                                        },
            'LAST_CRL_UPDATE'           : {
                                            'var_name'  : 'last_crl_update',
                                            'type'      : float,
                                            'required'  : False,
                                        },
            }

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string.
        name = str(name)
        # Only base CAs must have uppercase names.
        base_cas = config.get_base_objects("ca")
        if name.upper() in base_cas:
            self.name = name.upper()
        else:
            self.name = name.lower()

    @check_acls(['edit:crl_validity'])
    @object_lock()
    def set_crl_validity(self, crl_validity, callback=default_callback, **kwargs):
        try:
            crl_validity = int(crl_validity)
        except:
            msg = "CRL validity must be <int>."
            return callback.error(msg)
        self.crl_validity = crl_validity
        return self._cache(callback=callback)

    @check_acls(['create_cert'])
    @object_lock(full_lock=True)
    def create_cert(self, cn, valid, self_signed, basic_constraints=None,
        key_usage=None, ext_key_usage=None, key=None, cert_req=None,
        organization=None, country=None, state=None, locality=None,
        ou=None, email=None, key_len=None, sign_algo=None,
        timezone=None, run_policies=True, _caller="API",
        callback=default_callback, **kwargs):
        """ Create cert for the given common name. """
        if run_policies:
            try:
                self.run_policies("create_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if key_len is None:
            key_len = self.get_config_parameter("cert_key_len")

        if sign_algo is None:
            sign_algo = self.get_config_parameter("cert_sign_algo")

        # Create serial number.
        sn = self.gen_serial()

        # Set default values.
        if country is None:
            country = self.country
        if state is None:
            state = self.state
        if locality is None:
            locality = self.locality
        if organization is None:
            organization = self.organization
        if ou is None:
            ou = self.ou
        if email is None:
            email = self.email
        if timezone is None:
            timezone = config.timezone

        try:
            cert, \
            key = utils.create_certificate(cn=cn,
                                        sn=sn,
                                        key=key,
                                        key_len=key_len,
                                        sign_algo=sign_algo,
                                        ext_key_usage=ext_key_usage,
                                        timezone=timezone,
                                        cert_req=cert_req,
                                        key_usage=key_usage,
                                        basic_constraints=basic_constraints,
                                        ca_cert=self.cert, ca_key=self.key,
                                        self_signed=self_signed, country=country,
                                        state=state, locality=locality, ou=ou,
                                        organization=organization,
                                        email=email, valid=valid)
        except Exception as e:
            config.raise_exception()
            msg = "Failed to create certificate: %s" % e
            return callback.error(msg)

        return cert, key

    @check_acls(['create_ca_cert'])
    @object_lock(full_lock=True)
    def create_ca_cert(self, cn, self_signed=False,
        key=None, key_len=None, cert_req=None, country=None,
        state=None, locality=None, organization=None,
        ou=None, email=None, valid=None, run_policies=True,
        verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Create CA cert for given common name. """
        if key_len is None:
            key_len = config.default_ca_key_len
        if valid is None:
            valid = config.default_ca_validity
        if run_policies:
            try:
                self.run_policies("create_ca_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # CA nsCertType should not be "critical" because not every client knows
        # all cert types.
        ext_key_usage = []

        # CA keyUsage should be "critical" as we dont want a CA cert to be used
        # for server or client authentication.
        key_usage = []
        key_usage.append("critical")
        key_usage.append("crl_sign")
        key_usage.append("key_cert_sign")

        # CA basicConstraints should also not be "critical".
        basic_constraints = []
        basic_constraints.append("CA:TRUE")

        # Create CA cert.
        if verbose_level > 0:
            callback.send(_("Generating CA certificate (%s bits).") % key_len)

        cert, \
        key = self.create_cert(cn=cn, valid=valid,
                            self_signed=self_signed, ext_key_usage=ext_key_usage,
                            key=key, key_len=key_len, key_usage=key_usage,
                            basic_constraints=basic_constraints, ou=ou,
                            cert_req=cert_req, organization=organization,
                            country=country, state=state, locality=locality,
                            email=email, callback=callback,
                            verify_acls=False)
        return cert, key

    @check_acls(['create_server_cert'])
    @object_lock(full_lock=True)
    def create_server_cert(self, cn, cert_req=None, key=None,
        organization=None, country=None, state=None, valid=None,
        ou=None, key_len=None, locality=None, email=None, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Create server cert for given common name. """
        if key_len is None:
            key_len = config.default_server_key_len
        if valid is None:
            valid = config.default_server_validity
        if run_policies:
            try:
                self.run_policies("create_server_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Set server nsCertType
        ext_key_usage = []
        ext_key_usage.append("critical")
        ext_key_usage.append("SERVER_AUTH")

        # Server keyUsage should be "critical" as we dont want a server cert
        # to be used for certificate signing etc.
        key_usage = []
        key_usage.append("critical")
        key_usage.append("digital_signature")
        key_usage.append("key_encipherment")
        key_usage.append("data_encipherment")

        # Set basicConstraints for non-CA certs should also be "critical" and
        # contain "CA:FALSE" to indicate this is not a CA certificate.
        basic_constraints = []
        basic_constraints.append("critical")
        basic_constraints.append("CA:FALSE")

        # Create cert and key
        cert, \
        key = self.create_cert(cn=cn, valid=valid,
                            self_signed=False, ext_key_usage=ext_key_usage,
                            key=key, key_len=key_len, key_usage=key_usage,
                            basic_constraints=basic_constraints, ou=ou,
                            cert_req=cert_req, organization=organization,
                            country=country, state=state, locality=locality,
                            email=email, callback=callback,
                            verify_acls=False)
        return cert, key

    @check_acls(['create_client_cert'])
    @object_lock(full_lock=True)
    def create_client_cert(self, cn, valid=None, key_len=None, cert_req=None,
        key=None, organization=None, country=None, state=None, ou=None,
        locality=None, email=None, run_policies=True, _caller="API",
        callback=default_callback, **kwargs):
        """ Create client cert for given common name. """
        if key_len is None:
            key_len = config.default_client_key_len
        if valid is None:
            valid = config.default_client_validity
        if run_policies:
            try:
                self.run_policies("create_client_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Client nsCertType should be critical as we verify this in
        # our daemons.
        ext_key_usage = []
        ext_key_usage.append("critical")
        ext_key_usage.append("CLIENT_AUTH")

        # Client keyUsage should be "critical" as we dont want a client
        # cert to be used for certificate signing etc.
        key_usage = []
        key_usage.append("critical")
        key_usage.append("digital_signature")
        key_usage.append("key_encipherment")
        key_usage.append("data_encipherment")

        # Set basicConstraints for non-CA certs should also be "critical"
        # and contain "CA:FALSE" to indicate this is not a CA certificate.
        basic_constraints = []
        basic_constraints.append("critical")
        basic_constraints.append("CA:FALSE")

        # Create cert and key
        cert, \
        key = self.create_cert(cn=cn, valid=valid,
                            self_signed=False, ext_key_usage=ext_key_usage,
                            key=key, key_len=key_len, key_usage=key_usage,
                            basic_constraints=basic_constraints, ou=ou,
                            cert_req=cert_req, organization=organization,
                            country=country, state=state, locality=locality,
                            email=email, callback=callback,
                            verify_acls=False)
        return cert, key

    @object_lock(full_lock=True)
    def create_host_cert(self, cn, host_type="host",
        country=None, state=None, locality=None, organization=None,
        ou=None, email=None, self_signed=False, ca_cert=None,
        ca_key=None, key=None, key_len=None, cert_req=None, valid=None,
        verify_acls=True, callback=default_callback, **kwargs):
        """ Create node/host cert for given common name. """
        if verify_acls:
            if host_type == "host":
                acl = "create_host_cert"
            else:
                acl = "create_node_cert"
            if not self.verify_acl(acl):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)

        # Set default values.
        if host_type == "host":
            if not key_len:
                key_len = config.default_host_key_len
            if not valid:
                valid = config.default_host_validity
        else:
            if not key_len:
                key_len = config.default_node_key_len
            if not valid:
                valid = config.default_node_validity

        # nsCertType should be critical as we verify this in our daemons.
        ext_key_usage = []
        ext_key_usage.append("critical")
        ext_key_usage.append("SERVER_AUTH")
        ext_key_usage.append("CLIENT_AUTH")

        # keyUsage should be "critical" as we dont want a host cert to be
        # used for certificate signing etc.
        key_usage = []
        key_usage.append("critical")
        key_usage.append("digital_signature")
        key_usage.append("key_encipherment")
        key_usage.append("data_encipherment")

        # Set basicConstraints for non-CA certs should also be "critical" and
        # contain "CA:FALSE" to indicate this is not a CA certificate.
        basic_constraints = []
        basic_constraints.append("critical")
        basic_constraints.append("CA:FALSE")

        # Create cert and key.
        cert, \
        key = self.create_cert(cn=cn, valid=valid,
                            self_signed=False, ext_key_usage=ext_key_usage,
                            key=key, key_len=key_len, key_usage=key_usage,
                            basic_constraints=basic_constraints, ou=ou,
                            cert_req=cert_req, organization=organization,
                            country=country, state=state, locality=locality,
                            email=email, callback=callback,
                            verify_acls=False)
        return cert, key

    def gen_serial(self):
        """ Generate uniq serial number. """
        # FIXME: how to make serial number uniq?
        sn = int(time.time() * 1000000)
        return sn

    @object_lock(full_lock=True)
    @backend.transaction
    def set_crl(self, crl, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Set site CRL. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("set_crl",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        # Set CRL
        self.crl = crl
        self.last_crl_update = time.time()

        # Save our config before updating realm CA data.
        self._cache(callback=callback)

        # Update realm CA data.
        try:
            self.update_realm_ca_data(callback=callback)
        except Exception as e:
            msg = str(e)
            return callback.error(msg)

        return callback.ok()

    @check_acls(['update_crl'])
    @object_lock(full_lock=True)
    @backend.transaction
    def update_crl(self, sign_algo=None, run_policies=True, timezone=None,
        _caller="API", callback=default_callback, **kwargs):
        """ Remove outdated revoked certs from CA's CRL. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("update_crl",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Temp dict to hold new revoked list (without outdated serials)
        revoked_certs = ['1']

        # Walk through list of revoked certs.
        for serial in self.revoked_certs:
            # Get cert expiry timestamp from dict.
            cert_expiry = self.revoked_certs[serial]

            # Build dict without outdated revoked certs.
            if cert_expiry > time.time():
                revoked_certs.append(serial)

        new_crl = self.crl

        if sign_algo is None:
            sign_algo = self.get_config_parameter("crl_sign_algo")
        if timezone is None:
            timezone = config.timezone

        logger.debug("Building new CRL.")
        for serial in revoked_certs:
            try:
                revoke_serial, \
                revoke_until, \
                new_crl = utils.revoke_certificate(ca_cert=self.cert,
                                                ca_key=self.key,
                                                sn=serial,
                                                sign_algo=sign_algo,
                                                timezone=timezone,
                                                ca_crl=new_crl,
                                                crl_update=True,
                                                next_update=self.crl_validity)
            except Exception as e:
                config.raise_exception()
                msg = (_("Problem adding cert '%s' to CRL: %s")
                        % (serial, e))
                return callback.error(msg)

        self.set_crl(new_crl, callback=callback)

        return callback.ok()

    def update_realm_ca_data(self, callback=default_callback):
        """ Update realm CA data. """
        realm = backend.get_object(uuid=config.realm_uuid,
                                    object_type="realm")
        try:
            realm.update_ca_data(verify_acls=False,
                                callback=callback)
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to update realm CA data: %s") % e)
            raise OTPmeException(msg)

    def get_crl(self, _caller="API", callback=default_callback, **kwargs):
        """ Get CA's CRL as base64 string """
        if not self.crl:
            msg = "CA does not have a CRL."
            return callback.error(msg)
        return callback.ok(self.crl)

    @check_acls(['revoke:cert'])
    @object_lock(full_lock=True)
    @backend.transaction
    def revoke_cert(self, cert, crl_sign_algo=None, timezone=None,
        run_policies=True, _caller="API", callback=default_callback, **kwargs):
        """ Revoke certificate. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("revoke_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if crl_sign_algo is None:
            crl_sign_algo = self.get_config_parameter("crl_sign_algo")
        if timezone is None:
            timezone = config.timezone

        # Make sure the cert was issued by ourselves.
        cert_issuer = utils.get_issuer(cert)
        if cert_issuer != self.path:
            msg = (_("Cert was not issued by this CA: ")
                        % cert_issuer)
            return callback.error(msg)

        # Try to revoke certificate.
        try:
            revoke_serial, \
            revoke_until, \
            new_crl = utils.revoke_certificate(ca_cert=self.cert,
                                                ca_key=self.key,
                                                cert=cert,
                                                ca_crl=self.crl,
                                                timezone=timezone,
                                                sign_algo=crl_sign_algo,
                                                next_update=self.crl_validity)
        except CertAlreadyRevoked:
            raise
        except Exception as e:
            config.raise_exception()
            msg = (_("Error generating CRL: %s") % e)
            return callback.error(msg)

        if revoke_until > time.time():
            self.revoked_certs[revoke_serial] = revoke_until

        # If certificate was revoked successful update CRL and call
        # Realm().update_ca_data()
        self.crl = new_crl
        self.update_crl(verify_acls=False, callback=callback)

        # Write our config before updating realm CA data.
        self._cache(callback=callback)

        # Update realm CA data.
        try:
            self.update_realm_ca_data(callback=callback)
        except Exception as e:
            config.raise_exception()
            msg = str(e)
            return callback.error(msg)

        return callback.ok()

    # FIXME: implement generic renew that read subject, ext_key_usage etc. from given cert
    #        and renews it!!!
    #def renew(self, uuid, callback=default_callback, **kwargs):
    #    """ Revokes and renews an object certificate """
    #    # Get object.
    #    o = backend.get_object(uuid=uuid, realm=self.realm)

    #    if not o:
    #        return callback.error("Object does not exist: " + uuid)

    #    if not self.verify_acl("renew:" + o.type):
    #        msg = ("Permission denied.")
    #        return callback.error(msg, exception=PermissionDenied)

    #    if not o.cert:
    #        return callback.error("Object does not have a certificate: "
    #                            + o.path)

    #    if not o.type in self.supported_objects:
    #        return callback.error("Unable to handle object type: " + o.type)

    #    # Make sure the cert was issued by ourselves.
    #    cert_issuer = utils.get_issuer(o.cert)
    #    if cert_issuer != self.path:
    #        return callback.error("Cert was not issued by this CA: "
    #                            + cert_issuer)

    #    self.revoke(uuid=o.uuid)
    #    cn = utils.get_cn(o.cert)

    #    # Create new cert.
    #    cert, key = self.create_host_cert(cn=cn, host_type=o.type)

    #    o.cert = cert
    #    o.key = key

    #    callback.send(o.cert)

    #    return o._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def set_cert(self, cert, key=None, callback=default_callback):
        """ Set CA cert/key """
        # Set new cert/key.
        self.cert = cert
        self.key = key

        # Set initial CRL if needed.
        if self.key and not self.crl:
            # Generate CRL with one revoked dummy cert.
            callback.disable()
            try:
                cert, key = self.create_host_cert(cn="dummy-cert",
                                                host_type="host",
                                                key_len=1024,
                                                valid=1,
                                                verify_acls=False,
                                                callback=callback)
                self.revoke_cert(cert=cert,
                                verify_acls=False,
                                callback=callback)
            except Exception as e:
                config.raise_exception()
                msg = (_("WARNING: Problem generating initial CRL: %s") % e)
                return callback.error(msg)
            finally:
                callback.enable()

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(self, cn=None, country=None, state=None,
        locality=None, organization=None, ou=None, email=None, cert=None,
        key=None, key_len=None, no_cert=False, valid=None,
        verbose_level=0, callback=default_callback, **kwargs):
        """ Add a CA. """
        if key_len is None:
            key_len = config.default_ca_key_len
        if valid is None:
            valid = config.default_ca_validity
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()

        # Make sure country code is of lenght 2.
        if country:
            if len(str(country)) > 2:
                return callback.error("Country code to long.")

        # Set SSL cert fields.
        self.country = country
        self.state = state
        self.locality = locality
        self.organization = organization
        self.ou = ou
        self.email = email
        # Update index.
        self.update_index("country", self.country)
        self.update_index("state", self.state)
        self.update_index("locality", self.locality)
        self.update_index("organization", self.organization)
        self.update_index("ou", self.ou)
        self.update_index("email", self.email)

        self.set_path()

        if not no_cert and not cert and not key:
            if not cn:
                cn = self.path
            # Create self signed CA cert if no cert/key is given.
            cert, \
            key = self.create_ca_cert(cn=cn,
                                    self_signed=True,
                                    key_len=key_len,
                                    valid=valid,
                                    verify_acls=False,
                                    verbose_level=verbose_level,
                                    callback=callback)
        if not no_cert:
            set_status = self.set_cert(cert=cert, key=key, callback=callback)
            if not set_status:
                return callback.error()

        # Add object using parent class
        return OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(self, force=False, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete CA. """
        if not self.exists():
            return callback.error(_("CA does not exist exists."))

        # Make sure we do not delete a base CA
        base_cas = config.get_base_objects("ca")
        if self.name in base_cas:
            return callback.error(_("Cannot delete base CA."))

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % parent_object.path)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        # xxxxxxxxxxxxxxxxx
        # TODO: revoke CA cert via parent CA!!!!
        if not force:
            if self.confirmation_policy != "force":
                if self.confirmation_policy == "paranoid":
                    msg = "Please type '%s' to delete object: " % self.name
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
                else:
                    answer = callback.ask(_("Delete CA '%s'?: ") % self.name)
                    if answer.lower() != "y":
                        return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

    def show_config(self, callback=default_callback, **kwargs):
        """ Show CA config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        country = ""
        if self.verify_acl("view:country") \
        or self.verify_acl("view_public"):
            if self.country:
                country = self.country
        lines.append('COUNTRY="%s"' % country)

        state = ""
        if self.verify_acl("view:state") \
        or self.verify_acl("view_public"):
            if self.state:
                state = self.state
        lines.append('STATE="%s"' % state)

        locality = ""
        if self.verify_acl("view:locality") \
        or self.verify_acl("view_public"):
            if self.locality:
                locality = self.locality
        lines.append('LOCALITY="%s"' % locality)

        organization = ""
        if self.verify_acl("view:organization") \
        or self.verify_acl("view_public"):
            if self.organization:
                organization = self.organization
        lines.append('ORGANIZATION="%s"' % organization)

        ou = ""
        if self.verify_acl("view:ou") \
        or self.verify_acl("view_public"):
            if self.ou:
                ou = self.ou
        lines.append('OU="%s"' % ou)

        email = ""
        if self.verify_acl("view:email") \
        or self.verify_acl("view_public"):
            if self.email:
                email = self.email
        lines.append('EMAIL="%s"' % email)

        crl_validity = ""
        if self.verify_acl("edit:crl_validity"):
            if self.crl_validity:
                crl_validity = self.crl_validity
        lines.append('CRL_VALIDITY="%s"' % crl_validity)

        last_crl_update = ""
        last_crl_update = self.last_crl_update
        last_crl_update = datetime.datetime.fromtimestamp(last_crl_update)
        last_crl_update = last_crl_update.strftime('%d.%m.%Y %H:%M:%S')
        lines.append('LAST_CRL_UPDATE="%s"' % last_crl_update)

        crl = ""
        if self.verify_acl("view:crl") \
        or self.verify_acl("view_public"):
            if self.crl:
                crl = self.crl
        lines.append('CRL="%s"' % crl)

        return OTPmeObject.show_config(self, config_lines=lines, callback=callback)

    def show(self, **kwargs):
        """ Show CA details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)

    def move(self, new_unit, callback=default_callback):
        """ Disable unit change. """
        return callback.error("Cannot change CA unit.")
