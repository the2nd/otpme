# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.humanize import units
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

POLICY_TYPE="authonaction"
BASE_POLICY_NAME = "auth_on_action"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
# We need to register after all objects to be able to add this policy to all.
REGISTER_AFTER = ['otpme.lib.classes']


read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "hooks",
                            "whitelist",
                            "reauth_timeout",
                            "reauth_expiry",
                            ],
            }

write_value_acls = {
                "edit"      : [
                            "reauth_timeout",
                            "reauth_expiry",
                            ],
                "add"       : [
                            "hook",
                            "whitelist",
                            ],
                "remove"    : [
                            "hook",
                            "whitelist",
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
    'add_hook'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_hook',
                    'args'              : ['object_type', 'hook_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_hook'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_hook',
                    'args'              : ['object_type', 'hook_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'reauth_timeout'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_reauth_timeout',
                    'args'              : ['reauth_timeout'],
                    'job_type'          : 'process',
                    },
                },
            },
    'reauth_expiry'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_reauth_expiry',
                    'args'              : ['reauth_expiry'],
                    'job_type'          : 'process',
                    },
                },
            },
    'whitelist_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_whitelist',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'unwhitelist_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_whitelist',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'whitelist_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_whitelist',
                    'args'              : ['role_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'unwhitelist_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_whitelist',
                    'args'              : ['role_path'],
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
    register_shared_objects()
    register_config_properties()
    policy_acl = 'policy:%s' % POLICY_TYPE
    register_subtype_add_acl(policy_acl)
    register_subtype_del_acl(policy_acl)

def register_hooks():
    config.register_auth_on_action_hook("policy", "add_hook")
    config.register_auth_on_action_hook("policy", "remove_hook")
    config.register_auth_on_action_hook("policy", "change_reauth_expiry")
    config.register_auth_on_action_hook("policy", "change_reauth_timeout")

def register_shared_objects():
    from otpme.lib.multiprocessing import register_shared_dict
    register_shared_dict("first_reauth")
    register_shared_dict("last_reauth")

def register_config_properties():
    config.register_property(name="first_reauth", getx=first_reauth_getter)
    config.register_property(name="last_reauth", getx=last_reauth_getter)

def last_reauth_getter(self):
    """ Last re-auth done by auth_on_action() policy. """
    from otpme.lib.multiprocessing import last_reauth
    return last_reauth

def first_reauth_getter(self):
    """ First re-auth done by auth_on_action() policy. """
    from otpme.lib.multiprocessing import first_reauth
    return first_reauth

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)
    config.register_config_var("reauth_callback", object, None)

def register_policy_object():
    """ Register policy object. """
    # Register policy for all in-tree objects.
    for object_type in config.tree_object_types:
        # Register policy as default policy for new objects.
        config.register_default_policy(object_type, BASE_POLICY_NAME)
    # Register policy as base object.
    config.register_base_object(object_type="policy",
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE)

class AuthonactionPolicy(Policy):
    """ Class that implements OTPme auth on action policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(AuthonactionPolicy, self).__init__(object_id=object_id,
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
        #self.hooks = {}
        self.object_types = config.tree_object_types

        # For units we have to support the "add" hook for each in-tree object.
        for x in config.tree_object_types:
            hook = "pre_add_%s" % x
            config.register_auth_on_action_hook('unit', hook)
            hook = "post_add_%s" % x
            config.register_auth_on_action_hook('unit', hook)

        # Hooks that are valid for all object types we support.
        self.default_hooks = [
                            'add',
                            'modify',
                            'rename',
                            'delete',
                            'add_acl',
                            'del_acl',
                            'enable',
                            'disable',
                            'change_unit',
                            'add_policy',
                            'remove_policy',
                            'add_attribute',
                            'del_attribute',
                            'add_extension',
                            'remove_extension',
                            'add_object_class',
                            'del_object_class',
                            'remove_orphans',
                            'change_description',
                            'disable_acl_inheritance',
                            'enable_acl_inheritance',
                            # Non-modify hooks.
                            'export',
                            'get_acls',
                            ]

        for x in self.object_types:
            # Add default hooks.
            for hook in self.default_hooks:
                config.register_auth_on_action_hook(x, hook)

        # Timeout after a user is asked for reauth if no action was done which
        # normally requires a reauth. We use 30s by default to prevent repeatedly
        # reauth e.g. when adding ACLs recursive.
        self.reauth_timeout = 30
        # Timeout after a reauth is expired and the user is asked for reauth.
        self.reauth_expiry = 0

        # Whitelisted tokens/roles that are not required to reauth.
        #self.whitelist = {}

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
            'HOOKS'  : {
                                            'var_name'      : 'hooks',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            'WHITELIST'  : {
                                            'var_name'      : 'whitelist',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            'REAUTH_TIMEOUT'  : {
                                            'var_name'      : 'reauth_timeout',
                                            'type'          : int,
                                            'required'      : False,
                                        },
            'REAUTH_EXPIRY'  : {
                                            'var_name'      : 'reauth_expiry',
                                            'type'          : int,
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
        challenge = stuff.gen_secret(32)
        try:
            callback.auth_jwt(reason="authonaction",
                            challenge=challenge)
        except OTPmeException as e:
            return callback.error("JWT auth failed.")
        return callback.ok("JWT auth succeeded.")

    def handle_hook(self, hook_object, hook_name,
        callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if "interactive" in config.ignore_policy_tags:
            if config.debug_level() > 3:
                msg = ("AuthonactionPolicy disabled by "
                        "<config.ignore_policy_tags>.")
                logger.debug(msg)
            return callback.ok()

        if hook_object.type not in self.hooks:
            return callback.ok()

        if hook_name not in self.hooks[hook_object.type]:
            return callback.ok()

        if not config.auth_token:
            _caller = kwargs['_caller']
            if _caller == "API":
                return callback.ok()
            if config.use_api:
                return callback.ok()
            msg = (_("Cannot run policy without auth token: %s") % self.oid)
            raise self.policy_exception(msg)

        if '_caller' not in kwargs:
            msg = (_("AuthonactionPolicy needs <_caller>."))
            raise OTPmeException(msg)

        if callback.api_mode:
            if config.reauth_callback:
                callback = config.reauth_callback
                logger.debug("Using callback from previous call to do reauth.")

        if callback.api_mode:
            return

        config.reauth_callback = callback

        # Check if token is whitelisted.
        try:
            token_whitelist = self.whitelist['token']
        except:
            token_whitelist = []

        if token_whitelist:
            if config.auth_token.uuid in token_whitelist:
                return callback.ok()

        # Check if token is whitelisted by role.
        try:
            role_whitelist = self.whitelist['role']
        except:
            role_whitelist = []

        if role_whitelist:
            token_roles = config.auth_token.get_roles(return_type="uuid")
            for role_uuid in token_roles:
                if role_uuid in role_whitelist:
                    return callback.ok()

        do_reauth = True
        reauth_expired = False
        if self.reauth_expiry > 0:
            if config.auth_token.uuid in config.first_reauth:
                first_reauth = config.first_reauth[config.auth_token.uuid]
                reauth_age = time.time() - first_reauth
                if reauth_age > self.reauth_expiry:
                    reauth_expired = True
                    config.first_reauth.pop(config.auth_token.uuid)

        if not reauth_expired:
            if self.reauth_timeout > 0:
                if config.auth_token.uuid in config.last_reauth:
                    last_reauth = config.last_reauth[config.auth_token.uuid]
                    reauth_age = time.time() - last_reauth
                    if reauth_age < self.reauth_timeout:
                        do_reauth = False

        if config.use_api:
            do_reauth = False

        if do_reauth:
            msg = "You need to re-authenticate for this action."
            callback.send(msg)
            # Verify auth token.
            challenge = stuff.gen_secret(32)
            try:
                callback.auth_jwt(reason="authonaction",
                                challenge=challenge)
            except Exception as e:
                if config.auth_token.uuid in config.first_reauth:
                    config.first_reauth.pop(config.auth_token.uuid)
                if config.auth_token.uuid in config.last_reauth:
                    config.last_reauth.pop(config.auth_token.uuid)
                #config.raise_exception()
                raise self.policy_exception("Authentication failed.")

        # Set first re-auth time.
        if config.auth_token.uuid not in config.first_reauth:
            config.first_reauth[config.auth_token.uuid] = time.time()

        # Set last re-auth time.
        config.last_reauth[config.auth_token.uuid] = time.time()

    @check_acls(['edit:reauth_timeout'])
    @object_lock()
    @backend.transaction
    def change_reauth_timeout(self, reauth_timeout=0, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Change reauth timeout for this policy. """
        try:
            reauth_timeout = units.time2int(reauth_timeout, time_unit="s")
        except Exception as e:
            msg = (_("Invalid value for reauth timeout: %s") % e)
            return callback.error(msg)

        if self.reauth_expiry > 0:
            if reauth_timeout > self.reauth_expiry:
                msg =(_("Reauth timeout must be lower than reauth_expiry: %s")
                        % self.reauth_expiry)
                return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_reauth_timeout",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.reauth_timeout = reauth_timeout

        return self._cache(callback=callback)

    @check_acls(['edit:reauth_expiry'])
    @object_lock()
    @backend.transaction
    def change_reauth_expiry(self, reauth_expiry=0, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Change reauth expiry for this policy. """
        try:
            reauth_expiry = units.time2int(reauth_expiry, time_unit="s")
        except Exception as e:
            msg = (_("Invalid value for reauth expiry: %s") % e)
            return callback.error(msg)

        if self.reauth_timeout > 0:
            if self.reauth_timeout > reauth_expiry:
                msg =(_("Reauth expiry must be higher than reauth_timeout: %s")
                        % self.reauth_timeout)
                return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_reauth_expiry",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.reauth_expiry = reauth_expiry

        return self._cache(callback=callback)

    @check_acls(['add:hook'])
    @object_lock()
    @backend.transaction
    def add_hook(self, object_type, hook_name, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add hook. """
        if object_type not in self.object_types:
            msg = ("Invalid object type for this policy: %s" % object_type)
            return callback.error(msg)

        try:
            valid_hooks = config.auth_on_action_hooks[object_type]
        except:
            valid_hooks = []

        if hook_name not in valid_hooks:
            msg = (_("Unknown hook for this object type: %s: %s")
                    % (object_type, hook_name))
            return callback.error(msg)

        if object_type in self.hooks:
            if hook_name in self.hooks[object_type]:
                msg = ("Hook already added for this object type: %s: %s: %s"
                        % (object_type, hook_name, self.name))
                return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_hook",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not object_type in self.hooks:
            self.hooks[object_type] = []

        self.hooks[object_type].append(hook_name)

        return self._cache(callback=callback)

    @check_acls(['remove:hook'])
    @object_lock()
    @backend.transaction
    def remove_hook(self, object_type, hook_name, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Remove hook. """
        if object_type not in self.object_types:
            msg = ("Invalid object type for this policy: %s" % object_type)
            return callback.error(msg)

        try:
            valid_hooks = config.auth_on_action_hooks[object_type]
        except:
            valid_hooks = []

        if hook_name not in valid_hooks:
            msg = ("Unknown hook for this object type: %s" % hook_name)
            return callback.error(msg)

        if object_type in self.hooks:
            if hook_name not in self.hooks[object_type]:
                return callback.error("Hook not added for this object type.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_hook",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.hooks[object_type].remove(hook_name)

        return self._cache(callback=callback)

    @check_acls(['add:whitelist'])
    @object_lock()
    @backend.transaction
    def add_whitelist(self, token_path=None, role_path=None,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Add token/role to whitelist. """
        if token_path is not None:
            if not "/" in token_path:
                return callback.error("Invalid token path: %s" % token_path)

            # Get token.
            token_user = token_path.split("/")[0]
            token_name = token_path.split("/")[1]
            o = backend.get_object(object_type="token",
                                    realm=config.realm,
                                    user=token_user,
                                    name=token_name)
            if not o:
                return callback.error(_("Unknown token: %s") % token_path)

        elif role_path is not None:
            o = backend.get_object(object_type="role",
                                    realm=config.realm,
                                    site=config.site,
                                    name=role_path)
            if not o:
                return callback.error(_("Unknown role: %s") % role_path)
        else:
            raise Exception("Need <token> or <role>.")

        try:
            whitelist = self.whitelist[o.type]
        except:
            whitelist = []

        if o.uuid in whitelist:
            msg = (_("%s%s already whitelisted.")
                % (o.type[0].upper(), o.type[1:]))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_whitelist",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not o.type in self.whitelist:
            self.whitelist[o.type] = []

        self.whitelist[o.type].append(o.uuid)

        return self._cache(callback=callback)

    @check_acls(['remove:whitelist'])
    @object_lock()
    @backend.transaction
    def remove_whitelist(self, token_path=None, role_path=None,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Remove token/role to whitelist. """
        if token_path is not None:
            if not "/" in token_path:
                return callback.error("Invalid token path: %s" % token_path)

            # Get token.
            token_user = token_path.split("/")[0]
            token_name = token_path.split("/")[1]
            o = backend.get_object(object_type="token",
                                    realm=config.realm,
                                    user=token_user,
                                    name=token_name)
            if not o:
                return callback.error(_("Unknown token: %s") % token_path)

        elif role_path is not None:
            o = backend.get_object(object_type="role",
                                    realm=config.realm,
                                    site=config.site,
                                    name=role_path)
            if not o:
                return callback.error(_("Unknown role: %s") % role_path)
        else:
            raise Exception("Need <token> or <role>.")

        try:
            whitelist = self.whitelist[o.type]
        except:
            whitelist = []

        if o.uuid not in whitelist:
            msg = (_("%s%s not whitelisted.")
                % (o.type[0].upper(), o.type[1:]))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_whitelist",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.whitelist[o.type].remove(o.uuid)

        return self._cache(callback=callback)

    def _add(self, callback=default_callback, **kwargs):
        """ Add a policy. """
        for object_type in self.object_types:
            try:
                object_type_hooks = config.auth_on_action_hooks[object_type]
            except KeyError:
                continue
            for hook in object_type_hooks:
                self.add_hook(object_type=object_type,
                            hook_name=hook,
                            callback=callback)
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show policy config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        hooks = []
        if self.verify_acl("view:hook") \
        or self.verify_acl("add:hook") \
        or self.verify_acl("remove:hook"):
           for object_type in self.hooks:
                x_hooks = []
                for hook in self.hooks[object_type]:
                    x_hooks.append(hook)
                hook_string = "%s:[%s]" % (object_type, ",".join(x_hooks))
                hooks.append(hook_string)

        lines.append('HOOKS="%s"' % ",".join(hooks))

        whitelist = []
        if self.verify_acl("view:whitelist") \
        or self.verify_acl("add:whitelist") \
        or self.verify_acl("remove:whitelist"):
           for object_type in self.whitelist:
                x_list = []
                for x_uuid in self.whitelist[object_type]:
                    x_oid = backend.get_oid(x_uuid, instance=True)
                    x_list.append(x_oid.read_oid)
                whitelist_string = "%s:[%s]" % (object_type, ",".join(x_list))
                whitelist.append(whitelist_string)

        lines.append('WHITELIST="%s"' % ",".join(whitelist))

        reauth_timeout = "-"
        if self.verify_acl("view:reauth_timeout") \
        or self.verify_acl("edit:reauth_timeout"):
            reauth_timeout = self.reauth_timeout
        lines.append('REAUTH_TIMEOUT="%s"' % reauth_timeout)

        reauth_expiry = "-"
        if self.verify_acl("view:reauth_expiry") \
        or self.verify_acl("edit:reauth_expiry"):
            reauth_expiry = self.reauth_expiry
        lines.append('REAUTH_EXPIRY="%s"' % reauth_expiry)

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
