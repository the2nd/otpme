# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import re
import datetime

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

POLICY_TYPE = "logintimes"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "login_times",
                            "ignore_empty",
                            ],
        }

write_value_acls = {
                "add"       : [
                            "token",
                            ],
                "remove"    : [
                            "token",
                            ],
                "edit"      : [
                            "login_times",
                            ],
                "enable"    : [
                            "ignore_empty",
                            ],
                "disable"   : [
                            "ignore_empty",
                            ],
                }

default_acls = [
                'unit:add:policy:%s' % POLICY_TYPE,
                'unit:del:policy:%s' % POLICY_TYPE,
            ]

recursive_default_acls = default_acls

commands = {
    'login_times'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_login_times',
                    'args'              : ['login_times'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_role'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_ignore_empty'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_ignore_empty',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_ignore_empty'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_ignore_empty',
                    'job_type'          : 'thread',
                    },
                },
            },
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'args'              : ['object_type', 'test_object', 'token'],
                    'job_type'          : 'thread',
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
    config.register_auth_on_action_hook("policy", "change_login_times")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy type. """
    # Register base policy.
    call_methods = [
                    ({'change_login_times': {'login_times': '* 6-18 * * 1-5'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="workhours_login",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)
    # Register base policy.
    call_methods = [
                    ({'change_login_times': {'login_times': '* * * * 6-7'}},),
                ]
    config.register_base_object(object_type="policy",
                                name="weekend_login",
                                stype=POLICY_TYPE,
                                call_methods=call_methods)

class LogintimesPolicy(Policy):
    """ Class that implements OTPme login times policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(LogintimesPolicy, self).__init__(object_id=object_id,
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
                    'user',
                    'token',
                    'role',
                    'host',
                    'node',
                    'client',
                    'accessgroup',
                    ]
        self.login_times = "* * * * *"

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "ROLES",
                            "TOKENS",
                            "LOGIN_TIMES",
                            "IGNORE_EMPTY",
                            #"EXTENSIONS",
                            #"OBJECT_CLASSES",
                            ]
                        },
                    }

        # Allow not more than one policy of this type per object.
        self.allow_multiple = False
        self.roles = []
        self.tokens = []
        self.token_options = {}
        self.token_login_interfaces = {}
        self.ignore_empty = False

    def _get_object_config(self):
        """ Merge policy config with config from parent class. """
        policy_config = {
            'ROLES'                     : {
                                            'var_name'      : 'roles',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'TOKENS'                    : {
                                            'var_name'      : 'tokens',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'LOGIN_TIMES'               : {
                                            'var_name'      : 'login_times',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'IGNORE_EMPTY'              : {
                                            'var_name'      : 'ignore_empty',
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

    def check_login_times(self, hook_object, login_times,
        callback=default_callback, **kwargs):
        """ Check for valid login time """
        _now = datetime.datetime.now()
        minute = int(_now.strftime("%M"))
        hour = int(_now.strftime("%H"))
        day = int(_now.strftime("%d"))
        month = int(_now.strftime("%m"))
        weekday = int(_now.strftime("%w"))

        now = {
                'minute'    : minute,
                'hour'      : hour,
                'day'       : day,
                'month'     : month,
                'weekday'   : weekday,
                }

        found_match = False
        for entry in login_times.split("|"):
            if entry.startswith("!"):
                entry = entry.replace("!", "")
                negated = True
            else:
                negated = False

            entry_times = {
                    'minute'    : entry.split()[0],
                    'hour'      : entry.split()[1],
                    'day'       : entry.split()[2],
                    'month'     : entry.split()[3],
                    'weekday'   : entry.split()[4],
                    }

            match_count = 0
            for x in now:
                now_entry = now[x]
                login_entry = entry_times[x]
                for i in login_entry.split(","):
                    if "-" in i:
                        start = int(i.split("-")[0])
                        end = int(i.split("-")[1])
                        values = list(range(start, end + 1))
                        if now_entry in values:
                            match_count += 1
                            break
                    elif i == '*':
                        match_count += 1
                        break
                    elif int(i) == now[x]:
                        match_count += 1
                        break
            if match_count == 5:
                found_match = True
                break

        if found_match:
            if not negated:
                return callback.ok()
        else:
            if negated:
                return callback.ok()

        msg = (_("Login times restricted by policy: %s: %s")
                            % (self.name, hook_object.rel_path))
        return callback.error(msg, exception=self.policy_exception)

    def test(self, object_type, test_object, token, force=False,
        verbose_level=0, _caller="API", callback=default_callback):
        """ Test the policy """
        # Get test object.
        search_attribute = "name"
        if object_type == "token":
            search_attribute = "rel_path"
        result = backend.search(object_type=object_type,
                                attribute=search_attribute,
                                value=test_object,
                                return_type="instance")
        if not result:
            msg = "Unknown object: %s" % test_object
            return callback.error(msg)
        hook_object = result[0]
        # Get token.
        result = backend.search(object_type="token",
                                attribute="rel_path",
                                value=token,
                                return_type="instance")
        if not result:
            msg = "Unknown token: %s" % token
            return callback.error(msg)
        _token = result[0]
        test_result = self.handle_hook(hook_object=hook_object,
                                        hook_name="authorize",
                                        token=_token,
                                        callback=callback)
        if test_result:
            msg = "Policy verfied successful."
            return callback.ok(msg)
        return test_result

    def handle_hook(self, hook_object, hook_name, token,
        callback=default_callback, **kwargs):
        """ Handle policy hooks """
        if hook_name == "authorize":
            if token.is_admin():
                return callback.ok()
            if self.ignore_empty:
                if not self.tokens:
                    if not self.roles:
                        return callback.ok()
            token_match = False
            role_match = False
            if self.tokens:
                if token.uuid in self.tokens:
                    token_match = True
            if not token_match:
                if self.roles:
                    token_roles = token.get_roles(return_type="uuid")
                    for role_uuid in token_roles:
                        if role_uuid not in self.roles:
                            continue
                        role_match = True
            if not token_match and not role_match:
                if self.ignore_empty:
                    return callback.ok()
            return self.check_login_times(hook_object=hook_object,
                                        login_times=self.login_times,
                                        callback=callback)
        msg = (_("Unknown policy hook: %s") % hook_name)
        return callback.error(msg)

    @check_acls(['edit:login_times'])
    @object_lock()
    @backend.transaction
    def change_login_times(self, login_times, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change login times. """
        if not login_times:
            return callback.error("Got empty login times.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_login_times",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        # Walk through all login times we got.
        for x in login_times.split("|"):
            # Check if we got a negated login times string.
            if x.startswith("!"):
                x = x.replace("!", "")
            # Check if given login times are valid.
            login_times_entries = x.split()
            if len(login_times_entries) != 5:
                return callback.error(_("Invalid login times: %s") % x)
            numbers_re = re.compile('^[0-9]*$')
            login_times_re = re.compile('^[0-9]*[-][0-9]*$')
            entry_count = 0
            for entry in login_times_entries:
                entry_count += 1
                # Minutes.
                if entry_count == 1:
                    lower_mark = 0
                    upper_mark = 59
                # Hours.
                if entry_count == 2:
                    lower_mark = 0
                    upper_mark = 23
                # Day of month.
                if entry_count == 3:
                    lower_mark = 1
                    upper_mark = 31
                # Month.
                if entry_count == 3:
                    lower_mark = 1
                    upper_mark = 12
                # Day of week.
                if entry_count == 4:
                    lower_mark = 1
                    upper_mark = 7
                for x in entry.split(","):
                    entry_valid = False
                    if x == "*":
                        entry_valid = True
                    elif numbers_re.match(x):
                        if int(x) >= lower_mark \
                        and int(x) <= upper_mark:
                            entry_valid = True
                    elif login_times_re.match(x):
                        start = int(x.split("-")[0])
                        if int(start) >= lower_mark and int(start) <= upper_mark:
                            end = int(x.split("-")[1])
                            if int(end) >= lower_mark and int(end) <= upper_mark:
                                entry_valid = True
                    if entry_valid:
                        continue
                    return callback.error(_("Invalid login times entry: %s")
                                            % entry)
        self.login_times = login_times
        return self._cache(callback=callback)

    @check_acls(['enable:ignore_empty'])
    @object_lock()
    @backend.transaction
    def enable_ignore_empty(self, callback=default_callback, **kwargs):
        """ Enable 'ignore if empty' feature. """
        if self.ignore_empty is True:
            msg = "Ignore empty already enabled."
            return callback.error(msg)
        self.ignore_empty = True
        return self._cache(callback=callback)

    @check_acls(['disable:ignore_empty'])
    @object_lock()
    @backend.transaction
    def disable_ignore_empty(self, callback=default_callback, **kwargs):
        """ Disable 'ignore if empty' feature. """
        if self.ignore_empty is False:
            msg = "Ignore empty already disabled."
            return callback.error(msg)
        self.ignore_empty = False
        return self._cache(callback=callback)

    @object_lock()
    def _add(self, callback=default_callback, **kwargs):
        """ Add a policy """
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show policy config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        login_times = ""
        if self.verify_acl("view:login_times") \
        or self.verify_acl("edit:login_times"):
            login_times = self.login_times
        lines.append('LOGIN_TIMES="%s"' % login_times)

        tokens = []
        if self.verify_acl("view:token") \
        or self.verify_acl("add:token") \
        or self.verify_acl("remove:token"):
            for token in self.get_tokens():
                tokens.append(token)
        tokens = ",".join(tokens)
        lines.append('TOKENS="%s"' % tokens)

        roles = []
        if self.verify_acl("view:role") \
        or self.verify_acl("add:role") \
        or self.verify_acl("remove:role"):
            for role in self.get_roles():
                roles.append(role)
        roles = ",".join(roles)
        lines.append('ROLES="%s"' % roles)

        ignore_empty = ""
        if self.verify_acl("view:ignore_empty") \
        or self.verify_acl("enable:ignore_empty") \
        or self.verify_acl("disable:ignore_empty"):
            ignore_empty = self.ignore_empty
        lines.append('IGNORE_EMPTY="%s"' % ignore_empty)
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
