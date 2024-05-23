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
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.locking import object_lock
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

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"  : [
                        "policy_type",
                        ],
        }

write_value_acls = {}

default_acls = [
                'add:policy',
                'del:policy',
            ]

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['policy_type'],
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
                    'method'            : cli.show_getter("policy"),
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
                    'method'            : cli.list_getter("policy"),
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
                    'method'            : cli.list_getter("policy"),
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
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
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

DEFAULT_UNIT = "policies"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                ]

def register():
    register_oid()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("policy", commands)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("policy", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT, early=True)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    policy_name_re = '([0-9A-Za-z]([0-9A-Za-z_:.-]*[0-9A-Za-z]){0,})'
    policy_path_re = '%s[/]%s' % (unit_path_re, policy_name_re)
    policy_oid_re = 'policy|%s' % policy_path_re
    oid.register_oid_schema(object_type="policy",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=policy_name_re,
                            path_regex=policy_path_re,
                            oid_regex=policy_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="policy",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    from otpme.lib import policy
    policy_dir_extension = "policy"
    def path_getter(policy_oid):
        return backend.config_path_getter(policy_oid, policy_dir_extension)
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
                ]
        return backend.rebuild_object_index("policy", objects, after)
    # Register object to config.
    config.register_object_type(object_type="policy",
                            tree_object=True,
                            add_after=["unit", "revoked_signature"],
                            sync_after=["unit", "revoked_signature"],
                            uniq_name=True,
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register index attributes.
    config.register_index_attribute('policy_type')
    config.register_index_attribute('policy_uuid')
    # Register object to backend.
    class_getter = policy.get_class
    class_getter_args = {'POLICY_TYPE' : 'policy_type'}
    backend.register_object_type(object_type="policy",
                                dir_name_extension=policy_dir_extension,
                                class_getter=class_getter,
                                class_getter_args=class_getter_args,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="policy")
    config.register_object_sync(host_type="host", object_type="policy")

class Policy(OTPmeObject):
    """ Generic OTPme policy object. """
    commands = commands
    def __init__(self, object_id=None, name=None, path=None,
        realm=None, site=None, unit=None, **kwargs):
        # Set our type (used in parent class).
        self.type = "policy"
        # Call parent class init.
        super(Policy, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        unit=unit,
                                        name=name,
                                        path=path,
                                        **kwargs)
        # Policy type (e.g. autodisable).
        self.policy_type = None
        # Object types the policy is valid for.
        self.object_types = []
        # Allow only one policy of this type per object.
        self.allow_multiple = False
        # Default OTPme policy exception.
        self.policy_exception = PolicyException

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "POLICY_TYPE",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "POLICY_TYPE",
                            ]
                        },
                    }

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = str(name).lower()

    def _get_object_config(self, policy_config=None):
        """ Get object config dict """
        policy_base_config = {
                        'POLICY_TYPE'                : {
                                                        'var_name'  : 'policy_type',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        }

        object_config = {}
        # Merge policy config with base policy config.
        for i in policy_base_config:
            if i in policy_config:
                conf = policy_config[i]
                policy_config.pop(i)
            else:
                conf = policy_base_config[i]
                object_config[i] = conf

        for i in policy_config:
            object_config[i] = policy_config[i]

        return object_config

    def set_variables(self):
        """ Set instance variables """
        # Set OID.
        self.set_oid()

    def activate(self):
        """ Activate policy by returning per object policy data """
        return {}

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(self, verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Add a policy. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()

        # Update index.
        self.add_index('policy_type', self.policy_type)

        # Call child class method (to do token specific stuff):
        self._add(_caller=_caller,
                callback=callback,
                verbose_level=verbose_level,
                **kwargs)

        # Add object using parent class.
        return OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def rename(self, new_name, callback=default_callback, _caller="API", **kwargs):
        """ Rename a token. """
        # Build new OID.
        new_oid = oid.get(object_type="policy",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(self, force=False, run_policies=True, verify_acls=True,
        verbose_level=0, callback=default_callback, _caller="API", **kwargs):
        """ Delete policy. """
        if not self.exists():
            return callback.error("Policy does not exist.")

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

        if not force:
            exception = []
            if self.confirmation_policy != "force":
                policy_users = backend.search(attribute="policy",
                                            value=self.uuid,
                                            object_type="user",
                                            return_type="name")
                policy_tokens = backend.search(attribute="policy",
                                            value=self.uuid,
                                            object_type="token",
                                            return_type="rel_path")
                if policy_users:
                     exception.append(_("Policy '%(policy_name)s' is assigned to "
                                        "the following users: %(policy_users)s")
                                        % {"policy_name":self.name,
                                        "policy_users":", ".join(policy_users)})

                if policy_tokens:
                     exception.append(_("Policy '%(policy_name)s' is assigned to "
                                        "the following tokens: %(policy_tokens)s")
                                        % {"policy_name":self.name,
                                        "policy_tokens":", ".join(policy_tokens)})

            if exception:
                if self.confirmation_policy == "paranoid":
                    msg = ("%s\nPlease type '%s' to delete object: "
                            % ("\n".join(exception), self.name))
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
            else:
                if self.confirmation_policy != "force":
                    if self.confirmation_policy == "paranoid":
                        msg = ("Please type '%s' to delete object: " % self.name)
                        answer = callback.ask(msg)
                        if answer != self.name:
                            return callback.abort()
                    else:
                        ask = callback.ask(_("Delete policy '%s'?: ") % self.name)
                        if str(ask).lower() != "y":
                            return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

    def show_config(self, config_lines="", callback=default_callback, **kwargs):
        """ Show policy config. """
        lines = []

        if self.verify_acl("view:policy_type"):
            lines.append('POLICY_TYPE="%s"' % self.policy_type)
        else:
            lines.append('POLICY_TYPE=""')

        # Append lines from child class.
        lines += config_lines

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)
