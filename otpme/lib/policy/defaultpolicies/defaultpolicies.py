# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.policy import Policy
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.unit import register_subtype_add_acl
from otpme.lib.classes.unit import register_subtype_del_acl

from otpme.lib.classes.policy \
            import get_acls \
            as _get_acls
from otpme.lib.classes.policy \
            import get_value_acls \
            as _get_value_acls
from otpme.lib.classes.policy \
            import get_default_acls \
            as _get_default_acls
from otpme.lib.classes.policy \
            import get_recursive_default_acls \
            as _get_recursive_default_acls

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

POLICY_TYPE = "defaultpolicies"
BASE_POLICY_NAME = "default_policies"
REGISTER_BEFORE = []
#REGISTER_AFTER = []
REGISTER_AFTER = ['otpme.lib.classes']

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "default_policies",
                            ],
            }

write_value_acls = {
                "add"       : [
                            "default_policy",
                            ],
                "remove"    : [
                            "default_policy",
                            ],
                }

default_acls = [
                'unit:add:policy:%s' % POLICY_TYPE,
                'unit:del:policy:%s' % POLICY_TYPE,
            ]

recursive_default_acls = default_acls

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_default_policy'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_default_policy',
                    'args'              : ['object_type', 'policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_default_policy'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_default_policy',
                    'args'              : ['object_type', 'policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    }

def get_acls(split=False, **kwargs):
    """ Get all supported object ACLs """
    if split:
        otpme_policy_read_acls, \
        otpme_policy_write_acls = _get_acls(split=split, **kwargs)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_policy_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_policy_write_acls)
        return _read_acls, _write_acls
    otpme_policy_acls = _get_acls(**kwargs)
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, otpme_policy_acls)
    return _acls

def get_value_acls(split=False, **kwargs):
    """ Get all supported object value ACLs """
    if split:
        otpme_policy_read_value_acls, \
        otpme_policy_write_value_acls = _get_value_acls(split=split, **kwargs)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                                    otpme_policy_read_value_acls)
        _write_value__acls = otpme_acl.merge_value_acls(write_value_acls,
                                                        otpme_policy_write_value_acls)
        return _read_value_acls, _write_value__acls
    otpme_policy_value_acls = _get_value_acls(**kwargs)
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, otpme_policy_value_acls)
    return _acls

def get_default_acls():
    """ Get all supported object default ACLs """
    policy_default_acls = _get_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, policy_default_acls)
    return _acls

def get_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    policy_recursive_default_acls = _get_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                policy_recursive_default_acls)
    return _acls

def register():
    """ Registger policy type. """
    register_hooks()
    register_policy_type()
    register_policy_object()
    register_commands("policy",
                    commands,
                    sub_type=POLICY_TYPE,
                    sub_type_attribute="policy_type")
    policy_acl = 'policy:%s' % POLICY_TYPE
    register_subtype_add_acl(policy_acl)
    register_subtype_del_acl(policy_acl)

def register_hooks():
    config.register_auth_on_action_hook("policy", "add_default_policy")
    config.register_auth_on_action_hook("policy", "remove_default_policy")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy object. """
    # Register policy as default policy for new objects.
    config.register_default_policy("site", BASE_POLICY_NAME)
    config.register_default_policy("unit", BASE_POLICY_NAME)
    call_methods = []
    # Get all registered default policies to add.
    for object_type in config.tree_object_types:
        for policy_name in config.get_default_policies(object_type):
            # Register base policy.
            method_kwargs = {
                        'add_default_policy' : {
                                            'object_type': object_type,
                                            'policy_name': policy_name,
                                            }
                        }
            call_methods.append((method_kwargs,))
    # Add policies.
    config.register_base_object(object_type="policy",
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE,
                                call_methods=call_methods,
                                pos=9999999)

class DefaultpoliciesPolicy(Policy):
    """ Class that implements OTPme policy inheritance. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(DefaultpoliciesPolicy, self).__init__(object_id=object_id,
                                                    realm=realm,
                                                    site=site,
                                                    name=name,
                                                    path=path,
                                                    **kwargs)
        # Set policy type.
        self.policy_type = POLICY_TYPE
        self.sub_type = POLICY_TYPE

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Set default values.
        self.hooks = {
                    'all'   : [
                            'add'
                            ],
                    }

        self.object_types = config.tree_object_types

        #self.default_policies = {}

        self._sub_sync_fields = {}
        #self._sub_sync_fields = {
        #            'host'  : {
        #                'trusted'  : [
        #                    #"EXTENSIONS",
        #                    #"OBJECT_CLASSES",
        #                    ]
        #                }
        #            }

    def _get_object_config(self):
        """ Merge policy config with config from parent class. """
        policy_config = {
            'DEFAULT_POLICIES'  : {
                                            'var_name'      : 'default_policies',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge policy configs.
        return Policy._get_object_config(self, policy_config=policy_config)

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Policy.set_variables(self)

    def test(self, force=False, verbose_level=0,
        _caller="API", callback=default_callback):
        """ Test the policy. """
        return callback.ok()

    def handle_hook(self, callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        msg = ("This policy is handled by OTPmeObject().add().")
        return callback.error(msg)

    @check_acls(['add:default_policy'])
    @object_lock()
    @backend.transaction
    def add_default_policy(self, object_type, policy_name,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Add default policy. """
        if object_type not in self.object_types:
            return callback.error("Invalid object type for this policy: %s"
                                    % object_type)
        # Get policy by name.
        result = backend.search(attribute="name",
                                value=policy_name,
                                object_type="policy",
                                return_type="instance",
                                realm=config.realm,
                                site=config.site)
        if not result:
            return callback.error(_("Unknown policy: %s") % policy_name)

        policy = result[0]

        if object_type in self.default_policies:
            if policy.uuid in self.default_policies[object_type]:
                return callback.error("Policy already added for "
                                        "this object type.")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_default_policy",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if object_type not in policy.object_types:
            msg = ("Policy not valid for object type: %s: %s"
                    % (object_type, policy))
            return callback.error(msg)

        if not object_type in self.default_policies:
            self.default_policies[object_type] = []

        self.default_policies[object_type].append(policy.uuid)

        return self._cache(callback=callback)

    @check_acls(['remove:default_policy'])
    @object_lock()
    @backend.transaction
    def remove_default_policy(self, object_type, policy_name,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Remove default policy. """
        if object_type not in self.object_types:
            return callback.error("Invalid object type for this policy: %s"
                                    % object_type)
        # Get policy by name.
        result = backend.search(attribute="name",
                                value=policy_name,
                                object_type="policy",
                                return_type="instance",
                                realm=config.realm,
                                site=config.site)
        if not result:
            return callback.error(_("Unknown policy: %s") % policy_name)

        policy = result[0]

        if object_type in self.default_policies:
            if policy.uuid not in self.default_policies[object_type]:
                return callback.error("Policy not added for this object type.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_default_policy",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.default_policies[object_type].remove(policy.uuid)

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    def _add(self, callback=default_callback, **kwargs):
        """ Add a policy. """
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show policy config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        default_policies = []
        if self.verify_acl("view:default_policies") \
        or self.verify_acl("add:default_policy") \
        or self.verify_acl("remove:default_policy"):
            for object_type in self.default_policies:
                policies = []
                for policy_uuid in self.default_policies[object_type]:
                    policy = backend.get_object(uuid=policy_uuid)
                    if not policy:
                        continue
                    policies.append(policy.name)
                policy_string = "%s:[%s]" % (object_type, ",".join(policies))
                default_policies.append(policy_string)
        lines.append('DEFAULT_POLICIES="%s"' % ",\n".join(default_policies))

        return Policy.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)

    def show(self, **kwargs):
        """ Show policy details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
