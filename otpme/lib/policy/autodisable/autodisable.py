# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

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

POLICY_TYPE = "autodisable"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "auto_disable",
                            "unused_disable",
                            ],
        }

write_value_acls = {
                "edit"      : [
                            "auto_disable",
                            "unused_disable",
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
    'auto_disable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : '_change_auto_disable',
                    'args'              : ['auto_disable'],
                    'oargs'             : ['unused'],
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
    config.register_auth_on_action_hook("policy", "change_auto_disable")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy type. """
    # Register base policy.
    call_methods = [
                    ({'_change_auto_disable': {'auto_disable': '+1h'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="auto_disable_hour",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)
    # Register base policy.
    call_methods = [
                    ({'_change_auto_disable': {'auto_disable': '+1D'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="auto_disable_day",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)
    # Register base policy.
    call_methods = [
                    ({'_change_auto_disable': {'auto_disable': '+1W'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="auto_disable_week",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)
    # Register base policy.
    call_methods = [
                    ({'_change_auto_disable': {'auto_disable': '+1M'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="auto_disable_month",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)
    # Register base policy.
    call_methods = [
                    ({'_change_auto_disable': {'auto_disable': '+1Y'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="auto_disable_year",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)

class AutodisablePolicy(Policy):
    """ Class that implements OTPme auto disable policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(AutodisablePolicy, self).__init__(object_id=object_id,
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
                            'exists',
                            'enable',
                            ],
                    }
        self.object_types = [
                            'role',
                            'user',
                            'token',
                            'host',
                            'node',
                            'unit',
                            'site',
                            'realm',
                            'group',
                            'client',
                            'policy',
                            'accessgroup',
                            ]

        self._auto_disable = "+1M"
        self._unused_disable = False

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "AUTO_DISABLE",
                            "UNUSED_DISABLE",
                            #"EXTENSIONS",
                            #"OBJECT_CLASSES",
                            ]
                        },
                    'node'  : {
                        'untrusted'  : [
                            "AUTO_DISABLE",
                            "UNUSED_DISABLE",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Merge policy config with config from parent class. """
        policy_config = {
            'AUTO_DISABLE'              : {
                                            'var_name'      : '_auto_disable',
                                            'type'          : str,
                                            'required'      : True,
                                        },
            'UNUSED_DISABLE'            : {
                                            'var_name'      : '_unused_disable',
                                            'type'          : bool,
                                            'required'      : True,
                                        },
            }

        # Use parent class method to merge policy configs.
        return Policy._get_object_config(self, policy_config=policy_config)

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Policy.set_variables(self)

    def activate(self):
        """ Activate policy by returning per object policy data """
        policy_data = {
                    'policy_add_time'   : time.time(),
                    }
        return policy_data

    def test(self, force=False, verbose_level=0,
        _caller="API", callback=default_callback):
        """ Test the policy. """
        return callback.ok(self._auto_disable)

    def handle_hook(self, hook_object, hook_name, force=False,
        callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if hook_name == "exists":
            return self._check_auto_disable(hook_object, **kwargs)
        if hook_name != "enable":
            return callback.error(_("Unknown policy hook: %s") % hook_name,
                                    exception=self.policy_exception)
        if not hook_object.enabled and not force:
            msg = (_("%s disabled by policy.") % hook_object.type)
            return callback.error(message=msg,
                                raise_exception=True,
                                exception=self.policy_exception)
        # If the object gets re-enabled we have to re-activate the policy.
        try:
            hook_object.update_policy(policy_name=self.name,
                                    verify_acls=False,
                                    callback=callback)
        except BackendUnavailable as e:
            msg = (_("Unable to update object policy: %s") % e)
            logger.warning(msg)
            callback.send(msg)
        except Exception as e:
            msg = ("Error updating object policy: %s" % e)
            logger.warning(msg)

    def _check_auto_disable(self, hook_object, policy_add_time=None, **kwargs):
        """ Handle auto disable. """
        if not policy_add_time:
            return True
        if self._unused_disable:
            check_time = hook_object.get_last_used_time()
        else:
            check_time = policy_add_time
        disable_time = units.string2unixtime(self._auto_disable, check_time)
        now = time.time()
        if now >= disable_time:
            if hook_object.enabled:
                try:
                    hook_object.disable(force=True, verify_acls=False)
                    object_disabled = True
                    hook_object._write()
                except Exception as e:
                    exception = e
                    object_disabled = False
                if object_disabled:
                    msg = (_("%s disabled by policy: %s: %s")
                            % (hook_object.type, self.name, hook_object.name))
                    logger.warning(msg)
                else:
                    msg = (_("Cannot disable object by policy: %s: %s: %s")
                            % (self.name, hook_object.rel_path, exception))
                    logger.critical(msg)
                    return False
        return True

    @check_acls(['edit:auto_disable'])
    @object_lock()
    @backend.transaction
    def _change_auto_disable(self, auto_disable, unused=False,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Change auto disable value. """
        try:
            # Check if given date string is valid.
            units.string2unixtime(auto_disable, time.time())
        except Exception as e:
            msg = "Invalid date string: %s" % e
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_auto_disable",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self._auto_disable = auto_disable
        self._unused_disable = unused
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    def _add(self, callback=default_callback, **kwargs):
        """ Add a policy """
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show policy config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        auto_disable = ""
        if self.verify_acl("view:auto_disable") \
        or self.verify_acl("edit:auto_disable"):
            auto_disable = self._auto_disable
        lines.append('AUTO_DISABLE="%s"' % auto_disable)

        unused_disable = ""
        if self.verify_acl("view:unused_disable") \
        or self.verify_acl("edit:unused_disable"):
            unused_disable = self._unused_disable
        lines.append('UNUSED_DISABLE="%s"' % unused_disable)

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
