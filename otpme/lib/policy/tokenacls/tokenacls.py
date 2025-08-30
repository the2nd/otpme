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
from otpme.lib.classes.user import User
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.policy import Policy
from otpme.lib.policy import one_time_policy_run
from otpme.lib.protocols.utils import register_commands
from otpme.lib.token.password.password import PasswordToken
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

POLICY_TYPE = "tokenacls"
BASE_POLICY_NAME = "token_acls"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "user_acl",
                            "token_acl",
                            "creator_acl",
                            ],
            }

write_value_acls = {
                "add"       : [
                            "user_acl",
                            "token_acl",
                            "creator_acl",
                            ],
                "del"    : [
                            "user_acl",
                            "token_acl",
                            "creator_acl",
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
    'add_user_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_user_acl',
                    'args'              : ['acl'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_user_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_user_acl',
                    'args'              : ['acl'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_token_acl',
                    'args'              : ['acl'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_token_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_token_acl',
                    'args'              : ['acl'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_creator_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_creator_acl',
                    'args'              : ['acl'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_creator_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_creator_acl',
                    'args'              : ['acl'],
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
    config.register_auth_on_action_hook("policy", "add_user_acl")
    config.register_auth_on_action_hook("policy", "del_user_acl")
    config.register_auth_on_action_hook("policy", "add_token_acl")
    config.register_auth_on_action_hook("policy", "del_token_acl")
    config.register_auth_on_action_hook("policy", "add_creator_acl")
    config.register_auth_on_action_hook("policy", "del_creator_acl")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)
    config.register_default_policy("user", BASE_POLICY_NAME)

def register_policy_object():
    """ Registger policy type. """
    # Register base policy.
    call_methods = [
                    ({'add_user_acl': {'acl': 'view_all'}},),
                    ({'add_user_acl': {'acl': 'encrypt'}},),
                    ({'add_user_acl': {'acl': 'decrypt'}},),
                    ({'add_user_acl': {'acl': 'gen_keys'}},),
                    ({'add_token_acl': {'acl': 'view'}},),
                    ({'add_token_acl': {'acl': 'edit'}},),
                    ({'add_token_acl': {'acl': 'delete'}},),
                    ({'add_creator_acl': {'acl': 'view'}},),
                    ({'add_creator_acl': {'acl': 'edit'}},),
                    ({'add_creator_acl': {'acl': 'delete'}},),
                ]
    config.register_base_object(object_type="policy",
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE,
                                call_methods=call_methods)

class TokenaclsPolicy(Policy):
    """ Token ACLs policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(TokenaclsPolicy, self).__init__(object_id=object_id,
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
                    'user'   : [
                            'post_del_token',
                            'post_add_token'
                            ],
                    }

        self.object_types = [
                    'user',
                    ]

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
            'USER_ACLS'  : {
                                            'var_name'      : 'user_acls',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'TOKEN_ACLS'  : {
                                            'var_name'      : 'token_acls',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'TOKEN_CREATOR_ACLS'  : {
                                            'var_name'      : 'creator_acls',
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

    @one_time_policy_run
    def handle_user_acls(self, action, hook_object, token,
        acl_method, callback=default_callback):
        """ Handle token ACLs. """
        # Get ACL method from token.
        user_acl_method = getattr(hook_object, acl_method)

        # Get user ACLs from policy and token itself.
        user_acls = self.user_acls + token.user_acls

        # Add user ACLs.
        for acl in user_acls:
            exception = "Failed to %s user ACL" % action
            try:
                acl_status = user_acl_method(acl=acl,
                                            owner_uuid=token.uuid,
                                            verify_acls=False,
                                            callback=callback)
            except Exception as e:
                acl_status = False
                exception = "%s: %s" % (exception, e)

            if not acl_status:
                return callback.error(exception)

        return callback.ok()

    @one_time_policy_run
    def handle_token_acls(self, action, hook_object, token,
        acl_method, callback=default_callback):
        """ Handle token ACLs. """
        # Get ACL method from token.
        token_acl_method = getattr(token, acl_method)

        # Get token ACLs from policy and token itself.
        token_acls = self.token_acls + token.token_acls

        # Add ACL to new token to access itself.
        for acl in token_acls:
            exception = "Failed to %s token ACL" % action
            try:
                acl_status = token_acl_method(acl=acl,
                                            owner_uuid=token.uuid,
                                            verify_acls=False,
                                            callback=callback)
            except Exception as e:
                acl_status = False
                exception = "%s: %s" % (exception, e)

            if not acl_status:
                return callback.error(exception)

        # Add token ACLs.
        if hook_object.default_token:
            x_token = backend.get_object(object_type="token",
                                    uuid=hook_object.default_token)
            if x_token:
                for acl in self.token_acls:
                    exception = "Failed to %s token ACL" % action
                    # Add ACL to new token to be accessed by existing token.
                    try:
                        token_acl_method(acl=acl,
                                        owner_uuid=x_token.uuid,
                                        verify_acls=False,
                                        callback=callback)
                    except Exception as e:
                        acl_status = False
                        exception = "%s: %s" % (exception, e)

                    if not acl_status:
                        return callback.error(exception)

                    # Get ACL method from token.
                    x_token_acl_method = getattr(x_token, acl_method)

                    # Add ACL to existing token to be accessed by new token.
                    try:
                        x_token_acl_method(acl=acl,
                                        owner_uuid=token.uuid,
                                        verify_acls=False,
                                        callback=callback)
                    except Exception as e:
                        acl_status = False
                        exception = "%s: %s" % (exception, e)

                    if not acl_status:
                        return callback.error(exception)

        return callback.ok()

    @one_time_policy_run
    def handle_creator_acls(self, action, token, acl_method,
        callback=default_callback, **kwargs):
        """ Handle token creator ACLs. """
        # Get ACL method from token.
        token_acl_method = getattr(token, acl_method)

        # Get user ACLs from policy and token itself.
        creator_acls = self.creator_acls + token.creator_acls

        # Add token creator ACLs.
        for acl in creator_acls:
            exception = "Failed to %s creator ACL" % action
            # Add ACL to new token to be accessed by token creator.
            try:
                token_acl_method(acl=acl,
                                owner_uuid=config.auth_token.uuid,
                                verify_acls=False,
                                callback=callback)
                acl_status = True
            except Exception as e:
                acl_status = False
                exception = "%s: %s" % (exception, e)

            if not acl_status:
                return callback.error(exception)

        return callback.ok()

    def handle_hook(self, hook_object=None, child_object=None, hook_name=None,
        force=False, callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if not child_object:
            msg = "Need <child_object>."
            raise OTPmeException(msg)

        if hook_name == "post_add_token":
            action = "add"
            acl_method = "add_acl"
        elif hook_name == "post_del_token":
            action = "delete"
            acl_method = "del_acl"
        else:
            msg = "Invalid hook: %s" % hook_name
            return callback.error(msg)

        # No need to handle user ACLs for TOKENSTORE user.
        handle_user_acls = True
        handle_token_acls = True
        if hook_object.name == config.token_store_user:
            handle_user_acls = False
            handle_token_acls = False

        if handle_user_acls:
            acl_status = self.handle_user_acls(action,
                                            hook_object=hook_object,
                                            token=child_object,
                                            acl_method=acl_method,
                                            callback=callback)
            if not acl_status:
                return acl_status

        if handle_token_acls:
            acl_status = self.handle_token_acls(action,
                                            hook_object=hook_object,
                                            token=child_object,
                                            acl_method=acl_method,
                                            callback=callback)
            if not acl_status:
                return acl_status

        # Add creator ACLs if creator is not token owner.
        handle_creator_acls = False
        if config.auth_token:
            if config.auth_token.owner_uuid != hook_object.uuid:
                handle_creator_acls = True

        if not handle_creator_acls:
            return callback.ok()

        acl_status = self.handle_creator_acls(action=action,
                                            token=child_object,
                                            acl_method=acl_method,
                                            callback=callback)
        return acl_status

    @check_acls(['add:user_acl'])
    @object_lock()
    @backend.transaction
    def add_user_acl(self, acl, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add user ACL. """
        if acl in self.user_acls:
            msg = "ACL already exists."
            return callback.error(msg)

        # Get supported ACLs from dummy user.
        user = User(realm=config.realm,
                    site=config.site,
                    name="dummyuser",
                    dummy=True)
        # Make sure ACL is suppoted.
        supported_acls = user.get_supported_acls()
        if acl not in supported_acls:
            msg = "Unknown ACL: %s" % acl
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.user_acls.append(acl)

        return self._cache(callback=callback)

    @check_acls(['del:user_acl'])
    @object_lock()
    @backend.transaction
    def del_user_acl(self, acl, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Del token ACL. """
        if not acl in self.user_acls:
            msg = "Unknown ACL."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.user_acls.remove(acl)

        return self._cache(callback=callback)

    @check_acls(['add:token_acl'])
    @object_lock()
    @backend.transaction
    def add_token_acl(self, acl, **kwargs):
        """ Add token ACL. """
        return self._add_token_acl(acl, acl_type="token", **kwargs)

    @check_acls(['del:token_acl'])
    @object_lock()
    @backend.transaction
    def del_token_acl(self, acl, **kwargs):
        """ Del token ACL. """
        return self._del_token_acl(acl, acl_type="token", **kwargs)

    @check_acls(['add:creator_acl'])
    @object_lock()
    @backend.transaction
    def add_creator_acl(self, acl, **kwargs):
        """ Add token creator ACL. """
        return self._add_token_acl(acl, acl_type="creator", **kwargs)

    @check_acls(['del:creator_acl'])
    @object_lock()
    @backend.transaction
    def del_creator_acl(self, acl, **kwargs):
        """ Del token creator ACL. """
        return self._del_token_acl(acl, acl_type="creator", **kwargs)

    @object_lock()
    def _add_token_acl(self, acl, acl_type, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add token ACL. """
        if acl_type != "token" and acl_type != "creator":
            msg = "Unknown ACL type: %s" % acl_type
            raise OTPmeException(msg)

        if acl_type == "token":
            acl_list = self.token_acls
        elif acl_type == "creator":
            acl_list = self.creator_acls

        if acl in acl_list:
            msg = "ACL already exists."
            return callback.error(msg)

        # Get supported ACLs from dummy token.
        token = PasswordToken(realm=config.realm,
                    site=config.site,
                    user="dummyuser",
                    name="dummytoken",
                    dummy=True)
        # Make sure ACL is suppoted.
        supported_acls = token.get_supported_acls()
        if acl not in supported_acls:
            msg = "Unknown ACL: %s" % acl
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        acl_list.append(acl)

        return self._cache(callback=callback)

    @object_lock()
    def _del_token_acl(self, acl, acl_type, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Del token ACL. """
        if acl_type != "token" and acl_type != "creator":
            msg = "Unknown ACL type: %s" % acl_type
            raise OTPmeException(msg)

        if acl_type == "token":
            acl_list = self.token_acls
        elif acl_type == "creator":
            acl_list = self.creator_acls

        if not acl in acl_list:
            msg = "Unknown ACL."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        acl_list.remove(acl)

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
        user_acls = []
        if self.verify_acl("view:user_acl") \
        or self.verify_acl("add:user_acl") \
        or self.verify_acl("del:user_acl"):
            for acl in self.user_acls:
                user_acls.append(acl)
        lines.append('USER_ACLS="%s"' % ",".join(user_acls))

        token_acls = []
        if self.verify_acl("view:token_acl") \
        or self.verify_acl("add:token_acl") \
        or self.verify_acl("del:token_acl"):
            for acl in self.token_acls:
                token_acls.append(acl)
        lines.append('TOKEN_ACLS="%s"' % ",".join(token_acls))

        creator_acls = []
        if self.verify_acl("view:creator_acl") \
        or self.verify_acl("add:creator_acl") \
        or self.verify_acl("del:creator_acl"):
            for acl in self.creator_acls:
                creator_acls.append(acl)
        lines.append('TOKEN_CREATOR_ACLS="%s"' % ",".join(creator_acls))

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
