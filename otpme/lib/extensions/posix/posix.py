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
from otpme.lib import nsscache
from otpme.lib.extensions.ldif_handler import OTPmeLDIFHandler

from otpme.lib.exceptions import *

EXTENSION_NAME = "posix"
logger = config.logger
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.extensions.base.base"]

def register():
    register_backend()
    config.register_extension(EXTENSION_NAME)
    config.register_default_extension("user", EXTENSION_NAME)
    config.register_default_extension("group", EXTENSION_NAME)
    # Roles do need extensions to update e.g. groups (e.g. memberUid)
    # on token_add!
    config.register_default_extension("role", EXTENSION_NAME)

def register_backend():
    # Register index attributes.
    config.register_index_attribute('uidNumber', ldif=True)
    config.register_index_attribute('gidNumber', ldif=True)
    config.register_index_attribute('memberUid', ldif=True)

class OTPmeExtension(OTPmeLDIFHandler):
    def __init__(self):
        self.name = EXTENSION_NAME
        self.need_extensions = [ 'base' ]
        self.update_childs = {
                                'user'  : {
                                            'rename' : {
                                                    'group' : 'rename_user',
                                            },
                                        },
                                'role'  : {
                                        'update_members' : {
                                                'group' : 'update_members',
                                        },
                                        },
                            }

        self.valid_hooks = {
                            'all' : {
                                        'rename'        : 'rename',
                                        'add_attribute' : 'handle_attribute_add',
                                    },
                            'user' : {
                                        'change_group'    : 'change_group',
                                    },
                            'group' : {
                                        'update_members'    : 'update_members',
                                        'rename_user'       : 'rename_user',
                                    },
                            }

        self.schema_files = [ "nis.schema" ]
        #module_path = os.path.dirname(__file__)
        for f in list(self.schema_files):
            self.schema_files.append(os.path.join(config.schema_dir, f))
            #self.schema_files.append("%s/%s" % (module_path, f))
            self.schema_files.remove(f)

        self.object_types = [ 'user', 'group', 'role' ]

        self.object_classes = {
                            'user' : [ 'posixAccount', 'shadowAccount' ],
                            'group' : [ 'posixGroup' ],
                            'role' : [],
                        }

        self.default_classes = {
                            'user' : [ 'posixAccount' ],
                            'group' : [ 'posixGroup' ],
                            'role' : [],
                        }

        self.default_attributes = {
                            'user' : [ 'uidNumber', 'gidNumber', 'loginShell', 'homeDirectory' ],
                            'group' : [ 'cn', 'gidNumber' ],
                            'role' : [],
                        }

        self.attribute_mappings = {
                                'user' : {},
                                'group' : {
                                            'cn' : [ 'name' ],
                                        },
                                'role' : {},
                            }

        self.allow_reverse_mappings = {
                                'group' : {},
                                'role' : {},
                            }

        self.read_only_attributes = {
                            'user'  : [],
                            'group'  : [ 'cn' ],
                        }

        self.rename_no_update = [ 'uidNumber', 'gidNumber', 'memberUid' ]

        self.acls = []
        self.value_acls = {}

        # Call parent class init.
        OTPmeLDIFHandler.__init__(self)

    def _preload(self):
        """ Preload extension """
        return

    def get_free_id(self, o, attribute, assign=True, callback=default_callback):
        """ Get free ID for the given attribute via policy. """
        policies = None
        if o.unit_uuid:
            unit = backend.get_object(object_type="unit", uuid=o.unit_uuid)
            policies = unit.get_policies(policy_type="idrange",
                                        return_type="instance")
        if not policies:
            site = backend.get_object(object_type="site", uuid=o.site_uuid)
            policies = site.get_policies(policy_type="idrange",
                                        return_type="instance")
        if not policies:
            realm = backend.get_object(object_type="realm", uuid=o.realm_uuid)
            policies = realm.get_policies(policy_type="idrange",
                                        return_type="instance")
        if not policies:
            msg = ("No IDRange policy found to get %s." % attribute)
            raise OTPmeExtension(msg)

        # Get new free ID.
        lock_caller = "posix"
        idrange_policy = policies[0]
        idrange_policy.acquire_lock(lock_caller=lock_caller,
                                    write=True,
                                    full=True,
                                    callback=callback)
        try:
            new_id = idrange_policy.handle_hook(hook_name="get_next_free_id",
                                                object_type=o.type,
                                                hook_object=o,
                                                attribute=attribute,
                                                callback=callback)
        finally:
            idrange_policy.release_lock(lock_caller=lock_caller)
        return new_id

    def check_free_id(self, object_type, attribute, value, callback=default_callback):
        """ Check if the given ID is already used. """
        ldif_attribute = "ldif:%s" % attribute
        result = backend.search(attribute=ldif_attribute,
                                value=value,
                                object_type=object_type,
                                return_type="full_oid")
        if not result:
            return

        object_id = result[0]
        msg = ("%s %s already used by: %s" % (attribute, value, object_id))
        raise OTPmeException(msg)

    def verify_attribute_value(self, o, a, v, callback=default_callback):
        """ Check if the attribute value is valid for this object. """
        if o.type == "user":
            if a == "uidNumber":
                self.check_free_id(o.type, a, v, callback=callback)

        if o.type == "group":
            if a == "gidNumber":
                # Admin group may have duplicate gidNumber.
                if o.name == config.admin_group:
                    if str(v) == str(config.admin_group_gid):
                        return
                self.check_free_id(o.type, a, v, callback=callback)

    def gen_attribute_value(self, o, a, callback=default_callback):
        """ Generate new attribute value depending on object type. """
        if o.type == "user":
            if a == "uidNumber":
                if o.name == config.admin_user_name:
                    return config.admin_user_uid
                else:
                    try:
                        new_id = self.objects_default_attributes[o.oid.full_oid].pop(a)
                        msg = "Using uidNumber: %s" % new_id
                        callback.send(msg)
                    except KeyError:
                        new_id = self.get_free_id(o, attribute=a, callback=callback)
                    return new_id

            if a == "gidNumber":
                if o.group_uuid:
                    return_attrs = ['ldif:gidNumber']
                    result = backend.search(object_type="group",
                                            attribute="uuid",
                                            value=o.group_uuid,
                                            return_attributes=return_attrs)
                    if result:
                        return result[0]
                return None

            if a == "loginShell":
                return "/bin/bash"

            if a == "homeDirectory":
                home = "/home/%s" % o.name
                if o.name == config.admin_user_name:
                    home = config.admin_user_home
                return home

        if o.type == "group":
            if a == "gidNumber":
                if o.name == config.admin_group:
                    return config.admin_group_gid
                else:
                    try:
                        new_id = self.objects_default_attributes[o.oid.full_oid].pop(a)
                        msg = "Using gidNumber: %s" % new_id
                        callback.send(msg)
                    except KeyError:
                        new_id = self.get_free_id(o, attribute=a, callback=callback)
                    return new_id

    def change_group(self, o, callback=default_callback, **kwargs):
        """ Handle change_group hook. """
        attribute = "gidNumber"
        gid_number = self.gen_attribute_value(o=o, a=attribute)
        # Remove old attribute.
        self.del_attribute(o=o,
                        a=attribute,
                        ignore_ro=True,
                        ignore_deps=True,
                        ignore_missing=True,
                        callback=callback)
        # Add new attribute.
        self.add_attribute(o=o,
                        a=attribute,
                        v=gid_number,
                        ignore_ro=True,
                        verify=False,
                        verbose_level=0,
                        callback=callback)

    def update_members(self, o, callback=default_callback, **kwargs):
        """ Handle update_members hook. """
        # Get all group tokens.
        group_tokens = o.get_tokens(include_roles=True, return_type="rel_path")
        # Get group members.
        group_members = []
        for x in group_tokens:
            token_owner = x.split("/")[0]
            group_members.append(token_owner)
        # Get users with this group as primary group.
        if o.type == "group":
            search_attrs = {
                            'uuid'      : {
                                        'value'     : '*',
                                        },
                            'template'  : {
                                        'value'     : False,
                                        },
                            }
            group_members += backend.search(object_type="user",
                                    attributes=search_attrs,
                                    join_object_type="group",
                                    join_search_attr="uuid",
                                    join_search_val=o.uuid,
                                    join_attribute="user",
                                    return_type="name",
                                    realm=config.realm,
                                    site=config.site)
        # Remove duplicates.
        group_members = list(set(group_members))
        # Remove internal users.
        internal_users = config.get_internal_objects(object_type="user")
        group_members = list(set(group_members) - set(internal_users))
        # Remove members not assigend anymore.
        current_members = backend.search(object_type=o.type,
                                        attribute="uuid",
                                        value=o.uuid,
                                        return_attributes=['ldif:memberUid'])
        object_modified = False
        del_users = list(set(current_members) - set(group_members))
        new_users = list(set(group_members) - set(current_members))
        for token_owner in del_users:
            object_modified = True
            self.del_attribute_value(o=o,
                                attribute='memberUid',
                                value=token_owner,
                                callback=callback)
        # Add new members.
        for token_owner in new_users:
            object_modified = True
            self.add_attribute_value(o=o,
                                attribute="memberUid",
                                value=token_owner,
                                verify=True,
                                auto_value=True,
                                callback=callback)
        if object_modified:
            msg = "Updated group members: %s" % o.oid
            logger.info(msg)
            o._cache(callback=callback)

        # Make sure nsscache gets updated.
        nsscache.update_object(o.oid, "update")
        return True

    def rename_user(self, o, old_name, new_name, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Handle user rename hook. """
        if o.type == "group":
            self.del_attribute_value(o=o,
                                attribute='memberUid',
                                value=old_name,
                                callback=callback)
            try:
                self.add_attribute_value(o=o,
                                    attribute='memberUid',
                                    value=new_name,
                                    verify=True,
                                    auto_value=True,
                                    callback=callback)
            except AlreadyExists:
                pass
        else:
            msg = ("Hook <rename_user> not implemented for object type: %s"
                    % o.type)
            return callback.error(msg)

        return callback.ok()

    def handle_attribute_add(self, o, attribute, value, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Handle "add attribute" add hook. """
        update_group_members_gidnumber = False
        if attribute == "gidNumber":
            if o.type == "group":
                update_group_members_gidnumber = True

        if update_group_members_gidnumber:
            user_uuids = backend.search(object_type="user",
                                    attribute="group",
                                    value=o.uuid,
                                    return_type="uuid")
            for uuid in user_uuids:
                # Get user.
                user = backend.get_object(object_type="user", uuid=uuid)
                # Update attribute.
                user._del_extension_attribute(self.name, attribute)
                user._add_extension_attribute(self.name, attribute,
                                            value, auto_value=True,
                                            callback=callback)
                # Update user LDIF.
                user.load_extensions(verbose_level=verbose_level,
                                    callback=callback)
