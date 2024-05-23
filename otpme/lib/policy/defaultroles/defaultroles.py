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

POLICY_TYPE = "defaultroles"
BASE_POLICY_NAME = "default_roles"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"          : [
                                "default_roles",
                                ],
            }

write_value_acls = {
                "add"           : [
                                "default_role",
                                ],
                "remove"        : [
                                "default_role",
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
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_default_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_default_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
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
    config.register_auth_on_action_hook("policy", "add_default_role")
    config.register_auth_on_action_hook("policy", "remove_default_role")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy object. """
    from otpme.lib.classes.user import DEFAULT_UNIT
    # Register base policy.
    post_methods = []
    method_kwargs = {
                'add_role' : {
                            'role_name': config.realm_user_role,
                            }
                }
    post_methods.append((method_kwargs,))
    config.register_base_object(object_type="policy",
                                post_methods=post_methods,
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE)
    config.register_default_policy("unit", BASE_POLICY_NAME, objects=[DEFAULT_UNIT])

class DefaultrolesPolicy(Policy):
    """ Class that implements OTPme policy inheritance. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(DefaultrolesPolicy, self).__init__(object_id=object_id,
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
                    'user'   : ['post_add_user'],
                    }

        self.object_types = ['realm', 'site', 'unit']

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
            'DEFAULT_ROLES'  : {
                                    'var_name'      : 'default_roles',
                                    'type'          : list,
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

    def handle_hook(self, hook_name=None, child_object=None,
        callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if hook_name == "post_add_user":
            # Handle default roles if user does have a default token.
            if self.default_roles and child_object.default_token:
                result = backend.search(object_type="token",
                                        attribute="uuid",
                                        value=child_object.default_token,
                                        return_attributes=['rel_path'])
                if result:
                    default_token = result[0]
                    for role_uuid in self.default_roles:
                        role = backend.get_object(object_type="role",
                                                    uuid=role_uuid)
                        if not role:
                            continue
                        try:
                            role.add_token(default_token, callback=callback)
                        except AlreadyExists:
                            continue
                        except Exception as e:
                            msg = ("Failed to add default token to role: %s: "
                                    "%s: %s" % (role.name, default_token, e))
                            config.raise_exception()
                            return callback.error(msg)
        else:
            msg = (_("Unknown policy hook: %s") % hook_name)
            return callback.error(msg, exception=self.policy_exception)
        return callback.ok()

    @check_acls(['add:default_role'])
    @object_lock()
    @backend.transaction
    def add_role(self, role_name, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add default role. """
        # Get role by name.
        result = backend.search(attribute="name",
                                value=role_name,
                                object_type="role",
                                return_type="uuid",
                                realm=config.realm,
                                site=config.site)
        if not result:
            return callback.error(_("Unknown role: %s") % role_name)

        role_uuid = result[0]

        if role_uuid in self.default_roles:
            msg = "Role already added to this policy."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_default_role",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.default_roles.append(role_uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:default_role'])
    @object_lock()
    @backend.transaction
    def remove_role(self, role_name, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Remove default role. """
        # Get role by name.
        result = backend.search(attribute="name",
                                value=role_name,
                                object_type="role",
                                return_type="uuid",
                                realm=config.realm,
                                site=config.site)
        if not result:
            return callback.error(_("Unknown role: %s") % role_name)

        role_uuid = result[0]

        if role_uuid not in self.default_roles:
            return callback.error("Role not added for this policy.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_default_role",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.default_roles.remove(role_uuid)

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
        default_roles = []
        if self.verify_acl("view:default_roles") \
        or self.verify_acl("add:default_role") \
        or self.verify_acl("remove:default_role"):
            defaultroles = []
            for role_uuid in self.default_roles:
                role = backend.get_object(uuid=role_uuid)
                if not role:
                    continue
                defaultroles.append(role.name)
            roles_string = "%s" % ",".join(defaultroles)
            default_roles.append(roles_string)
        lines.append('DEFAULT_ROLES="%s"' % ",".join(default_roles))

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
