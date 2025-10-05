# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib.spsc import SPSC
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.spsc import check_number
from otpme.lib.spsc import check_special
from otpme.lib.spsc import check_uppercase
from otpme.lib.spsc import check_lowercase
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

POLICY_TYPE = "password"
BASE_POLICY_NAME = "password_strength"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "pin_min_len",
                            "password_min_len",
                            "strength_checker",
                            "strength_checker_opts",
                            ],
            }

write_value_acls = {
                "edit"      : [
                            "pin_min_len",
                            "password_min_len",
                            "strength_checker",
                            "strength_checker_opts",
                            ],
                "enable"    : [
                            "number",
                            "uppercase",
                            "lowercase",
                            "special",
                            "strength_checker",
                            ],
                "disable"   : [
                            "number",
                            "uppercase",
                            "lowercase",
                            "special",
                            "strength_checker",
                            ],
                }

default_acls = [
                f'unit:add:policy:{POLICY_TYPE}',
                f'unit:del:policy:{POLICY_TYPE}',
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
    'strength_checker'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_strength_checker',
                    'args'              : ['strength_checker'],
                    'job_type'          : 'process',
                    },
                },
            },
    'strength_checker_opts'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_strength_checker_opts',
                    'args'              : ['options'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_require_number'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_require_number',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_require_number'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_require_number',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_require_upper'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_require_upper',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_require_upper'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_require_upper',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_require_lower'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_require_lower',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_require_lower'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_require_lower',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_require_special'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_require_special',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_require_special'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_require_special',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_strength_checker'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_strength_checker',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_strength_checker'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_strength_checker',
                    'job_type'          : 'process',
                    },
                },
            },
    'pin_min_len'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_pin_min_len',
                    'args'              : ['pin_min_len'],
                    'job_type'          : 'process',
                    },
                },
            },
    'password_min_len'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_password_min_len',
                    'args'              : ['password_min_len'],
                    'job_type'          : 'process',
                    },
                },
            },
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'oargs'             : ['password', 'pin'],
                    'job_type'          : 'process',
                    'extend'            : True,
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
    policy_acl = f'policy:{POLICY_TYPE}'
    register_subtype_add_acl(policy_acl)
    register_subtype_del_acl(policy_acl)

def register_hooks():
    config.register_auth_on_action_hook("policy", "enable_strength_checker")
    config.register_auth_on_action_hook("policy", "disable_strength_checker")
    config.register_auth_on_action_hook("policy", "change_password_min_len")
    config.register_auth_on_action_hook("policy", "change_pin_min_len")
    config.register_auth_on_action_hook("policy", "change_strength_checker")
    config.register_auth_on_action_hook("policy", "change_strength_checker_opts")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy type. """
    # Register as default policy.
    config.register_default_policy("node", BASE_POLICY_NAME)
    config.register_default_policy("host", BASE_POLICY_NAME)
    config.register_default_policy("user", BASE_POLICY_NAME)
    config.register_default_policy("token", BASE_POLICY_NAME)
    # Register as base policy.
    config.register_base_object(object_type="policy",
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE)
    config.register_config_var("default_pass_strength_checker", str, 'spsc')
    config.register_config_var("supported_pass_strength_checker", list, ['spsc'])
    # Allowed password characters.
    object_types = [
                        'site',
                        'unit',
                        'user',
                    ]
    config.register_config_parameter(name="password_allowed_chars",
                                    ctype=str,
                                    default_value="0-9A-Za-z!@#$%^&*()_+-={}[]|\:;<>.?/",
                                    object_types=object_types)

class PasswordPolicy(Policy):
    """ Class that implements OTPme password policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(PasswordPolicy, self).__init__(object_id=object_id,
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
                            'check_pin',
                            'check_password',
                            ]
                    }
        self.object_types = [ 'user', 'token', 'host', 'node' ]
        self.password_min_len = 8
        self.pin_min_len = 4
        self.require_number = True
        self.require_special = True
        self.require_lowercase = True
        self.require_uppercase = True
        self.strength_checker = config.default_pass_strength_checker
        self.strength_checker_enabled = True
        #self.strength_checker_opts = {}

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "PIN_MIN_LEN",
                            "PASSWORD_MIN_LEN",
                            "STRENGTH_CHECKER",
                            "STRENGTH_CHECKER_OPTS",
                            "STRENGTH_CHECKER_ENABLED",
                            #"EXTENSIONS",
                            #"OBJECT_CLASSES",
                            ]
                        }
                    }

    def _get_object_config(self):
        """ Merge policy config with config from parent class. """
        policy_config = {
            'PASSWORD_MIN_LEN'          : {
                                            'var_name'      : 'password_min_len',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'PIN_MIN_LEN'               : {
                                            'var_name'      : 'pin_min_len',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'REQUIRE_NUMBER'            : {
                                            'var_name'      : 'require_number',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'REQUIRE_UPPERCASE'         : {
                                            'var_name'      : 'require_uppercase',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'REQUIRE_LOWERCASE'         : {
                                            'var_name'      : 'require_lowercase',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'REQUIRE_SPECIAL'           : {
                                            'var_name'      : 'require_special',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'STRENGTH_CHECKER'          : {
                                            'var_name'      : 'strength_checker',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'STRENGTH_CHECKER_OPTS'     : {
                                            'var_name'      : 'strength_checker_opts',
                                            'type'          : dict,
                                            'required'      : False,
                                        },

            'STRENGTH_CHECKER_ENABLED'  : {
                                            'var_name'      : 'strength_checker_enabled',
                                            'type'          : bool,
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

    def test(self, password=None, pin=None, force=False,
        verbose_level=0, _caller="API",
        callback=default_callback):
        """ Test the policy. """
        if password:
            # Make sure password is string.
            password = str(password)
            return self.check_password(password,
                                    return_result=True,
                                    callback=callback,
                                    verbose_level=verbose_level)
        if pin:
            # Make sure pin is string.
            pin = str(pin)
            return self.check_pin(pin, callback=callback,
                                verbose_level=verbose_level)
        msg = _("Missing <password> or <pin>.")
        return callback.error(msg)

    def handle_hook(self, hook_object, hook_name,
        callback=default_callback, **kwargs):
        """ Handle policy hooks """
        if hook_name == "check_pin":
            return self.check_pin(callback=callback, **kwargs)
        if hook_name == "check_password":
            return self.check_password(return_score=False,
                                        callback=callback,
                                        **kwargs)
        msg = _("Unknown policy hook: {hook_name}")
        msg = msg.format(hook_name=hook_name)
        return callback.error(msg)

    def check_pin(self, pin, verbose_level=0, callback=default_callback):
        """ Check if the given PIN is in the correct format """
        # Make sure PIN is string.
        pin = str(pin)
        pin_regex = '^[0-9]*$'
        pin_re = re.compile(pin_regex)
        if not pin_re.match(pin):
            msg = _("PIN must only contain numbers.")
            return callback.error(msg, exception=self.policy_exception)
        if len(pin) < self.pin_min_len:
            msg = _("PIN must be at least {pin_min_len} digits long.")
            msg = msg.format(pin_min_len=self.pin_min_len)
            return callback.error(msg, exception=self.policy_exception)
        return callback.ok()

    def check_password(self, password, return_result=False, return_score=True,
        score_only=False, verbose_level=0, callback=default_callback):
        """ Check if the given password is in the correct format. """
        if not isinstance(password, str):
            msg = _("Expected <password> as <str> but got {password_type}.")
            msg = msg.format(password_type=type(password))
            return callback.error(msg)

        if len(password) == 0:
            msg = _("Received empty password.")
            return callback.error(msg)

        if not score_only:
            if len(password) < self.password_min_len:
                msg = _("Password must be at least {password_min_len} characters long.")
                msg = msg.format(password_min_len=self.password_min_len)
                return callback.error(msg, exception=self.policy_exception)
            password_allowed_chars = self.get_config_parameter("password_allowed_chars")
            password_regex = f'^[{password_allowed_chars}]*$'
            password_re = re.compile(password_regex)
            if not password_re.match(password):
                msg = _("Password contains invalid character(s). Allowed characters are: {password_allowed_chars}")
                msg = msg.format(password_allowed_chars=password_allowed_chars)
                return callback.error(msg, exception=self.policy_exception)
            if self.require_number:
                if not check_number(password):
                    msg = _("Password must contain a number.")
                    return callback.error(msg, exception=self.policy_exception)
            if self.require_lowercase:
                if not check_lowercase(password):
                    msg = _("Password must contain a lowercase character.")
                    return callback.error(msg, exception=self.policy_exception)
            if self.require_uppercase:
                if not check_uppercase(password):
                    msg = _("Password must contain a uppercase character.")
                    return callback.error(msg, exception=self.policy_exception)
            if self.require_special:
                if not check_special(password):
                    msg = _("Password must contain a special character.")
                    return callback.error(msg, exception=self.policy_exception)
            if not self.strength_checker_enabled:
                return callback.ok()

        if self.strength_checker == "spsc":
            if "dict_order" not in self.strength_checker_opts:
                return callback.error(_("Missing option 'dict_order'."))
            if "min_score" not in self.strength_checker_opts:
                return callback.error(_("Missing option 'min_score'."))
            # Get dictionaries in configured order.
            dict_order = []
            dictionaries = {}
            for x in self.strength_checker_opts['dict_order']:
                dict_uuid = x[1]
                dict_obj = backend.get_object(uuid=dict_uuid)
                if not dict_obj:
                    msg = _("Unknown dictionary: {dict_uuid}")
                    msg = msg.format(dict_uuid=dict_uuid)
                    return callback.error(msg)
                if not dict_obj.enabled:
                    continue
                dictionaries[dict_obj.name] = {
                                        'dict'      : dict_obj.dictionary,
                                        'dict_type' : dict_obj.dictionary_type,
                                        }
                dict_order.append(dict_obj.name)
            # Get strength checker options.
            strength_checker_opts = dict(self.strength_checker_opts)
            # Update dict order.
            strength_checker_opts['dict_order'] = dict_order
            # Get min score.
            min_score = strength_checker_opts.pop('min_score')
            # Check password strength.
            try:
                spsc = SPSC(dictionaries=dictionaries,
                            **strength_checker_opts)
                result = spsc.get_score(password)
            except Exception as e:
                return callback.error(str(e))

            if return_result:
                return callback.ok(result)

            score = result['score']
            if score_only:
                return callback.ok(score)

            if score < min_score:
                return callback.error(_("Password too weak!"),
                                    exception=self.policy_exception)
            if return_score:
                return callback.ok(score)

            return callback.ok()

    @check_acls(['edit:password_min_len'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_password_min_len(self, password_min_len, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change min password length. """
        if password_min_len < 3:
            return callback.error(_("Password min length too short."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_password_min_len",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.password_min_len = password_min_len

        return self._cache(callback=callback)

    @check_acls(['edit:pin_min_len'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_pin_min_len(self, pin_min_len, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change min PIN length. """
        if pin_min_len < 3:
            return callback.error(_("Password min length too short."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_pin_min_len",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.pin_min_len = pin_min_len

        return self._cache(callback=callback)

    @check_acls(['edit:strength_checker'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_strength_checker(self, strength_checker, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change strength checker. """
        if not strength_checker in config.supported_pass_strength_checker:
            msg = _("Unknown password strength checker: {strength_checker}")
            msg = msg.format(strength_checker=strength_checker)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_strength_checker",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.strength_checker = strength_checker

        return self._cache(callback=callback)

    @check_acls(['edit:strength_checker_opts'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_strength_checker_opts(self, options, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change strength checker options. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_strength_checker_opts",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.strength_checker_opts = {}
        for x in options.split(";"):
            try:
                opt = x.split("=")[0]
                val = x.split("=")[1]
            except:
                msg = _("Invalid option: {x}")
                msg = msg.format(x=x)
                return callback.error(msg)
            if opt == "dict_order":
                dict_order = val.split(",")
                if not isinstance(dict_order, list):
                    return callback.error(_("Need dict order as list."))
                dict_order_uuids = []
                for x in dict_order:
                    result = backend.search(object_type="dictionary",
                                                attribute="name",
                                                value=x,
                                                return_type="uuid",
                                                realm=self.realm,
                                                site=self.site)
                    if not result:
                        msg = _("Unknown dictionary: {x}")
                        msg = msg.format(x=x)
                        return callback.error(msg)
                    dict_uuid = result[0]
                    dict_order_uuids.append((x, dict_uuid))

                self.strength_checker_opts['dict_order'] = dict_order_uuids
            elif opt == "recent_years_past":
                try:
                    recent_years_past = int(val)
                except:
                    return callback.error(_("recent_years_past must to be of type integer."))
                self.strength_checker_opts['recent_years_past'] = recent_years_past
            elif opt == "recent_years_future":
                try:
                    recent_years_future = int(val)
                except:
                    return callback.error(_("recent_years_future must to be of type integer."))
                self.strength_checker_opts['recent_years_future'] = recent_years_future
            elif opt == "min_score":
                try:
                    min_score = int(val)
                except:
                    return callback.error(_("min_score must be of type integer."))
                self.strength_checker_opts['min_score'] = min_score
            else:
                msg = _("Unknown option: {opt}")
                msg = msg.format(opt=opt)
                return callback.error(msg)
        return self._cache(callback=callback)

    @check_acls(['enable:number'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_require_number(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for number in password. """
        if self.require_number:
            return callback.error(_("Require number already enabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_require_number",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require number?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_number = True

        return self._cache(callback=callback)

    @check_acls(['disable:number'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_require_number(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for number in password. """
        if not self.require_number:
            return callback.error(_("Require number already disabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_require_number",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require number?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_number = False

        return self._cache(callback=callback)

    @check_acls(['enable:uppercase'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_require_upper(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for uppercase character in password. """
        if self.require_uppercase:
            return callback.error(_("Require uppercase already enabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_require_upper",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require uppercase?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_uppercase = True

        return self._cache(callback=callback)

    @check_acls(['disable:uppercase'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_require_upper(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for uppercase character in password. """
        if not self.require_uppercase:
            return callback.error(_("Require uppercase already disabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_require_upper",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require uppercase?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_uppercase = False

        return self._cache(callback=callback)

    @check_acls(['enable:lowercase'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_require_lower(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for lowercase character in password. """
        if self.require_lowercase:
            return callback.error(_("Require lowercase already enabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_require_lower",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require lowercase?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_lowercase = True

        return self._cache(callback=callback)

    @check_acls(['disable:lowercase'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_require_lower(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for lowercase character in password. """
        if not self.require_lowercase:
            return callback.error(_("Require lowercase already disabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_require_lower",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require lowercase?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_lowercase = False

        return self._cache(callback=callback)

    @check_acls(['enable:special'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_require_special(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for special character in password. """
        if self.require_special:
            return callback.error(_("Require special character already enabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_require_special",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require special character?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_special = True

        return self._cache(callback=callback)

    @check_acls(['disable:special'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_require_special(self, force=True, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable check for special character in password. """
        if not self.require_special:
            return callback.error(_("Require special character already disabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_require_special",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable require special character?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.require_special = False

        return self._cache(callback=callback)

    @check_acls(['enable:strength_checker'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_strength_checker(self, force=False, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable strength checker. """
        if self.strength_checker_enabled:
            return callback.error(_("Strength checker already enabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_strength_checker",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable strength checker?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.strength_checker_enabled = True
        return self._cache(callback=callback)

    @check_acls(['disable:strength_checker'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_strength_checker(self, force=False, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable strength checker. """
        if not self.strength_checker_enabled:
            return callback.error(_("Strength checker already disabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_strength_checker",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Disable strength checker?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.strength_checker_enabled = False
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    def _add(self, callback=default_callback, **kwargs):
        """ Add a policy. """
        self.strength_checker = config.default_pass_strength_checker
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show policy config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        pin_min_len = ""
        if self.verify_acl("view:pin_min_len") \
        or self.verify_acl("edit:pin_min_len"):
            pin_min_len = self.pin_min_len
        lines.append(f'PIN_MIN_LEN="{pin_min_len}"')

        password_min_len = ""
        if self.verify_acl("view:password_min_len") \
        or self.verify_acl("edit:password_min_len"):
            password_min_len = self.password_min_len
        lines.append(f'PASSWORD_MIN_LEN="{password_min_len}"')

        number = ""
        if self.verify_acl("enable:number") \
        or self.verify_acl("disable:number"):
            number = self.require_number
        lines.append(f'NUMBER_CHECK="{number}"')

        uppercase = ""
        if self.verify_acl("enable:uppercase") \
        or self.verify_acl("disable:uppercase"):
            uppercase = self.require_uppercase
        lines.append(f'UPPERCASE_CHECK="{uppercase}"')

        lowercase = ""
        if self.verify_acl("enable:lowercase") \
        or self.verify_acl("disable:lowercase"):
            lowercase = self.require_lowercase
        lines.append(f'LOWERCASE_CHECK="{lowercase}"')

        special = ""
        if self.verify_acl("enable:special") \
        or self.verify_acl("disable:special"):
            special = self.require_special
        lines.append(f'SPECIAL_CHAR_CHECK="{special}"')

        strength_checker = ""
        if self.verify_acl("view:strength_checker") \
        or self.verify_acl("edit:strength_checker"):
            strength_checker = self.strength_checker
        lines.append(f'STRENGTH_CHECKER="{strength_checker}"')

        strength_checker_opts = []
        if self.verify_acl("view:strength_checker_opts") \
        or self.verify_acl("edit:strength_checker_opts"):
            for o in self.strength_checker_opts:
                if o == "dict_order":
                    dict_order = []
                    for x in self.strength_checker_opts[o]:
                        dict_order.append(x[0])
                    option = f"dict_order={','.join(dict_order)}"
                else:
                    option = f"{o}={self.strength_checker_opts[o]}"
                strength_checker_opts.append(option)
        lines.append(f'STRENGTH_CHECKER_OPTS="{";".join(strength_checker_opts)}"')

        strength_checker_enabled = ""
        if self.verify_acl("view:strength_checker") \
        or self.verify_acl("enable:strength_checker") \
        or self.verify_acl("disable:strength_checker"):
            strength_checker_enabled = self.strength_checker_enabled
        lines.append(f'STRENGTH_CHECKER_ENABLED="{strength_checker_enabled}"')

        return Policy.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)
    def show(self, **kwargs):
        """ Show policy details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = _("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
