# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pprint

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

POLICY_TYPE = "objecttemplates"
BASE_POLICY_NAME = "object_templates"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []

write_acls =  [
            'set_template',
            ]

read_value_acls = {
                    'view'  : ['templates'],
                    }

write_value_acls = {}

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
    'set_template'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_template',
                    'args'              : ['object_type', 'object_name'],
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
    config.register_auth_on_action_hook("policy", "set_template")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy object. """
    # Register base policy.
    post_methods = []
    for object_type in config.tree_object_types:
        object_name = config.get_object_template(object_type)
        if object_name is None:
            continue
        method_kwargs = {
                    'set_template' : {
                                        'object_type'   : object_type,
                                        'object_name'   : object_name,
                                        }
                    }
        post_methods.append((method_kwargs,))
    config.register_base_object(object_type="policy",
                                post_methods=post_methods,
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE)
    # Register policy as default policy for new objects.
    config.register_default_policy("unit", BASE_POLICY_NAME)

class ObjecttemplatesPolicy(Policy):
    """ Class that implements OTPme object templates policy. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(ObjecttemplatesPolicy, self).__init__(object_id=object_id,
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

        # Set hooks.
        self.hooks = {
                    'user'   : ['pre_add_user'],
                    'host'   : ['pre_add_host'],
                    }

        self.object_types = ['realm', 'site', 'unit']

        #self.object_templates = {}

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
            'OBJECT_TEMPLATES'  : {
                                    'var_name'      : 'object_templates',
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

    def get_object_template(self, object_type):
        """ Get object template. """
        try:
            template_uuid = self.object_templates[object_type]
        except:
            msg = "No template configured for type: %s" % object_type
            raise NotConfigured(msg)
        search_attrs = {
                        'uuid'      : {
                                    'value'     : template_uuid,
                                    },
                        'template'  : {
                                    'value'     : True,
                                    },
                        }
        result = backend.search(object_type=object_type,
                                attributes=search_attrs,
                                return_type="instance")
        if not result:
            msg = "Unknown %s template: %s" % (object_type, template_uuid)
            raise UnknownTemplate(msg)
        object_template = result[0]
        return object_template

    def handle_hook(self, hook_name=None, callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if hook_name == "pre_add_user":
            return self.handle_user_add(hook_name=hook_name,
                                    callback=callback, **kwargs)
        elif hook_name == "pre_add_host":
            return self.handle_host_add(hook_name=hook_name,
                                    callback=callback, **kwargs)
        else:
            msg = (_("Unknown policy hook: %s") % hook_name)
            return callback.error(msg, exception=self.policy_exception)

    def handle_user_add(self, hook_name=None, hook_object=None,
        child_object=None, callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if not child_object:
            return
        try:
            object_template = self.get_object_template("user")
        except NotConfigured:
            return callback.ok()
        except UnknownTemplate as e:
            return callback.error(str(e))
        if child_object.is_admin():
            msg = "Not using template for admin user."
            return callback.ok(msg)
        if child_object.is_template():
            msg = "Not using template for template user."
            return callback.ok(msg)
        if child_object.is_special_object():
            msg = "Not using template for special user."
            return callback.ok(msg)
        # Set object template.
        child_object.template_name = object_template.name
        msg = ("Using %s template: %s"
            % (child_object.type, child_object.template_name))
        callback.send(msg)
        return callback.ok()

    def handle_host_add(self, hook_name=None, hook_object=None,
        child_object=None, callback=default_callback, **kwargs):
        """ Handle policy hooks. """
        if not child_object:
            return
        try:
            object_template = self.get_object_template("host")
        except NotConfigured:
            return callback.ok()
        except UnknownTemplate as e:
            return callback.error(str(e))
        # Set object template.
        child_object.template_name = object_template.name
        msg = ("Using %s template: %s"
            % (child_object.type, child_object.template_name))
        callback.send(msg)
        return callback.ok()

    @check_acls(['set_template'])
    @object_lock()
    @backend.transaction
    def set_template(self, object_type, object_name=None, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Set object template. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("set_template",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        # Check if the given object type does support templating.
        if not config.get_object_template(object_type):
            msg = "Object type does not support templating: %s" % object_type
            return callback.error(msg)
        # Remove object template.
        if object_name is None:
            try:
                self.object_templates.pop(object_type)
            except KeyError:
                pass
            return self._cache(callback=callback)

        # Get template by name.
        result = backend.search(object_type=object_type,
                                attribute="name",
                                value=object_name,
                                return_type="uuid",
                                realm=config.realm,
                                site=config.site)
        if not result:
            msg = (_("Unknown %s template: %s") % (object_type, object_name))
            return callback.error(msg)

        template_uuid = result[0]
        try:
            current_template_uuid = self.object_templates[object_type]
        except:
            current_template_uuid = None

        if template_uuid == current_template_uuid:
            msg = "Template already set."
            return callback.error(msg)

        self.object_templates[object_type] = template_uuid
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
        object_templates = ""
        if self.verify_acl("view:templates"):
            if self.object_templates:
                object_templates = {}
                for object_type in self.object_templates:
                    object_template = self.get_object_template(object_type)
                    object_templates[object_type] = object_template.oid.full_oid
                object_templates = pprint.pformat(object_templates)

        lines.append('OBJECT_TEMPLATES="%s"' % object_templates)

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
