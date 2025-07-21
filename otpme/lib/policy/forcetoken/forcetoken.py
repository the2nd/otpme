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

POLICY_TYPE = "forcetoken"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "force_token_types",
                            "force_pass_types",
                            ],
            }

write_value_acls = {
                "edit"      : [
                            "force_token_types",
                            "force_pass_types",
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
    'force_token_types'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_force_token_types',
                    'args'              : ['token_types'],
                    'job_type'          : 'process',
                    },
                },
            },
    'force_pass_types'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_force_pass_types',
                    'args'              : ['pass_types'],
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
    config.register_auth_on_action_hook("policy", "change_force_pass_types")
    config.register_auth_on_action_hook("policy", "change_force_token_types")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy type. """
    # Register policy to force OTP tokens.
    call_methods = [
                ({'change_force_pass_types': {'pass_types': 'otp,otp_push'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="force_token_otp",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)
    # Register policy to force non-static (password) tokens.
    call_methods = [
                ({'change_force_pass_types': {'pass_types': 'otp,otp_push,ssh_key,smartcard'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="force_token_non_static",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)

class ForcetokenPolicy(Policy):
    """ Class that implements OTPme force token policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(ForcetokenPolicy, self).__init__(object_id=object_id,
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
                            'authorize',
                            ],
                    }
        self.object_types = [
                    'role',
                    'host',
                    'node',
                    'group',
                    'client',
                    'accessgroup',
                    ]

        self.force_pass_types = [ 'otp', 'ssh_key', 'smartcard' ]

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "FORCE_TOKEN_TYPES",
                            "FORCE_PASS_TYPES",
                            #"EXTENSIONS",
                            #"OBJECT_CLASSES",
                            ]
                        }
                    }

    def _get_object_config(self):
        """ Merge policy config with config from parent class. """
        policy_config = {
            'FORCE_TOKEN_TYPES'              : {
                                            'var_name'      : 'force_token_types',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'FORCE_PASS_TYPES'              : {
                                            'var_name'      : 'force_pass_types',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge policy configs.
        return Policy._get_object_config(self, policy_config=policy_config)

    def set_variables(self):
        """ Set instance variables """
        # Run parent class method that may override default values with those
        # read from config.
        Policy.set_variables(self)

    def check_token(self, token, hook_object,
        callback=default_callback, **kwargs):
        """ Check for valid token/pass type """
        if token.destination_token:
            verify_token = token.get_destination_token()
        else:
            verify_token = token
        if self.force_token_types:
            if verify_token.token_type not in self.force_token_types:
                return callback.error(_("Token type denied by policy: %s: %s")
                                        % (self.name, hook_object.rel_path),
                                        exception=self.policy_exception)
        if self.force_pass_types:
            if verify_token.pass_type not in self.force_pass_types:
                return callback.error(_("Token pass type denied by policy: %s")
                                        % (self.name, hook_object.rel_path),
                                        exception=self.policy_exception)

    def test(self, force=False, verbose_level=0,
        _caller="API", callback=default_callback):
        """ Test the policy. """
        return callback.ok()

    def handle_hook(self, hook_object, token, hook_name,
        callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if not token:
            raise OTPmeException("Need token to handle 'authorize' hook.")
        if hook_name == "authorize":
            return self.check_token(token, hook_object, callback=callback)
        msg = (_("Unknown policy hook: %s") % hook_name)
        return callback.error(msg, exception=self.policy_exception)

    @check_acls(['edit:force_token_types'])
    @object_lock()
    @backend.transaction
    def change_force_token_types(self, token_types, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change list of allowed forced token types. """
        try:
            force_token_types = token_types.split(",")
        except:
            return callback.error(_("Invalid token types: %s") % token_types)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_force_token_types",
                                callback=callback,
                                _caller=_caller)
            except OTPmeException:
                return callback.error()

        self.force_token_types = force_token_types

        return self._cache(callback=callback)

    @check_acls(['edit:force_pass_types'])
    @object_lock()
    @backend.transaction
    def change_force_pass_types(self, pass_types, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change list of allowed pass types. """
        try:
            force_pass_types = pass_types.split(",")
        except:
            return callback.error(_("Invalid password types: %s") % pass_types)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_force_pass_types",
                                callback=callback,
                                _caller=_caller)
            except OTPmeException:
                return callback.error()

        self.force_pass_types = force_pass_types

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

        force_token_types = ""
        if self.force_token_types:
            if self.verify_acl("view:force_token_types") \
            or self.verify_acl("edit:force_token_types"):
                force_token_types = ",".join(self.force_token_types)
        lines.append('FORCE_TOKEN_TYPES="%s"' % force_token_types)

        force_pass_types = ""
        if self.force_pass_types:
            if self.verify_acl("view:force_pass_types") \
            or self.verify_acl("edit:force_pass_types"):
                force_pass_types = ",".join(self.force_pass_types)
        lines.append('FORCE_PASS_TYPES="%s"' % force_pass_types)

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
