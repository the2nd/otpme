# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.extensions.ldif_handler import OTPmeLDIFHandler

from otpme.lib.exceptions import *

EXTENSION_NAME = "base"
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.extensions.ldif_handler"]

WHITELIST_ATTRIBUTES = ['dn', 'objectClass', 'uid', 'cn', 'displayName', 'entryUUID']

def register():
    #register_backend()
    config.register_extension(EXTENSION_NAME)
    config.register_default_extension("realm", EXTENSION_NAME)
    config.register_default_extension("site", EXTENSION_NAME)
    config.register_default_extension("unit", EXTENSION_NAME)
    config.register_default_extension("user", EXTENSION_NAME)
    config.register_default_extension("group", EXTENSION_NAME)
    config.register_default_extension("role", EXTENSION_NAME)
    config.register_config_var("ldif_whitelist_attributes",
                                list, WHITELIST_ATTRIBUTES)

#def register_backend():
#    # Register index attributes.
#    config.register_index_attribute('cn', ldif=True)
#    config.register_index_attribute('sn', ldif=True)
#    config.register_index_attribute('uid', ldif=True)
#    config.register_index_attribute('mail', ldif=True)
#    config.register_index_attribute('entryUUID', ldif=True)
#    config.register_index_attribute('givenName', ldif=True)
#    config.register_index_attribute('employeeNumber', ldif=True)
#    config.register_index_attribute('createTimestamp', ldif=True)
#    config.register_index_attribute('modifyTimestamp', ldif=True)

class OTPmeExtension(OTPmeLDIFHandler):
    def __init__(self):
        self.name = EXTENSION_NAME
        self.need_extensions = []
        self.update_childs = {}

        self.valid_hooks = {
                            'all' : {
                                        'rename'                    : 'rename',
                                        'update_modified_timestamp' : 'update_modified_timestamp',
                                        'site_move'                 : 'site_move',
                                    },
                            'realm' : {
                                        'change_description'    : 'change_description',
                                    },
                            'site'  : {
                                        'change_description'    : 'change_description',
                                    },
                            'unit'  : {
                                        #'update_dn'             : 'update_dn',
                                        'change_unit'           : 'change_unit',
                                        'change_description'    : 'change_description',
                                    },
                            'user' : {
                                        #'update_dn'             : 'update_dn',
                                        'change_unit'           : 'change_unit',
                                        'change_description'    : 'change_description',
                                    },
                            'group' : {
                                        'change_unit'           : 'change_unit',
                                        'change_description'    : 'change_description',
                                    },
                            'role' : {
                                        'change_unit'           : 'change_unit',
                                        'change_description'    : 'change_description',
                                    },
                            }

        #module_path = os.path.dirname(__file__)
        self.schema_files = [
                            "core.schema",
                            "cosine.schema",
                            "inetorgperson.schema",
                            ]

        for f in list(self.schema_files):
            self.schema_files.append(os.path.join(config.schema_dir, f))
            #self.schema_files.append("%s/%s" % (module_path, f))
            self.schema_files.remove(f)

        self.object_types = [ 'realm', 'site', 'unit', 'user', 'group', 'role', 'host', 'node' ]

        self.object_classes = {
                            'realm' : [ 'dcObject', 'organization' ],
                            'site' : [ 'organizationalUnit' ],
                            'unit' : [ 'organizationalUnit' ],
                            'host' : [ 'account' ],
                            'node' : [ 'account' ],
                            'user' : [ 'organizationalPerson', 'person', 'inetOrgPerson' ],
                            'role' : [ 'organizationalRole' ],
                            'group' : [],
                        }


        self.default_classes = {
                            'realm' : [ 'dcObject', 'organization' ],
                            'site' : [ 'organizationalUnit' ],
                            'unit' : [ 'organizationalUnit' ],
                            'user' : [ 'organizationalPerson', 'person', 'inetOrgPerson' ],
                            'role' : [ 'organizationalRole' ],
                            'group' : [],
                        }

        # Attributes that are not deps of any object class.
        self.object_attributes = {
                                    'all' : [ 'entryUUID', 'createTimestamp', 'modifyTimestamp' ],
                                }

        self.default_attributes = {
                            # FIXME: description needs objectClass organization which needs attribute o
                            #'realm' : [ 'dc', 'description' ],
                            'realm' : [ 'dc' ],
                            'site' : [ 'ou', 'description' ],
                            'unit' : [ 'ou', 'description' ],
                            'user' : [ 'uid', 'sn', 'cn', 'l', 'description' ],
                            'role' : [ 'cn', 'description' ],
                            'group' : [],
                            'all' : [ 'entryUUID', 'createTimestamp', 'modifyTimestamp' ],
                        }

        self.attribute_mappings = {
                                'all' : {
                                            'entryUUID' : [ 'uuid' ],
                                            'description' : [ 'description' ],
                                            'createTimestamp' : [ 'create_time' ],
                                            'modifyTimestamp' : [ 'last_modified' ],
                                        },
                                'user' : {
                                            'uid' : [ 'name' ],
                                            'cn' : [ ('givenName', 'sn'), 'name' ],
                                            'displayName' : [ ('givenName', 'sn'), 'name' ],
                                        },
                                'role' : {
                                            'cn' : [ 'name' ],
                                        },
                            }

        self.allow_reverse_mappings = {
                                'all' : {
                                            'description' : [ 'description' ],
                                        },
                            }

        self.read_only_attributes = {
                            'realm' : [ 'dc' ],
                            'site'  : [ 'ou' ],
                            'unit'  : [ 'ou' ],
                            'user'  : [ 'uid' ],
                            'group' : [],
                            'role'  : [],
                        }

        self.rename_no_update = []

        self.acls = []
        self.value_acls = {}

        # Call parent class init.
        OTPmeLDIFHandler.__init__(self)

    def _preload(self):
        return

    def verify_attribute_value(self, o, a, v, callback=default_callback):
        """ Check if the attribute value is valid for this object. """
        return

    def gen_attribute_value(self, o, a, callback=default_callback):
        """ Generate new attribute value depending on object type """
        if o.type == "realm":
            if a == "dc":
                return o.name.split(".")[0]

        if o.type == "site":
            if a == "ou":
                return o.name
            if a == "l":
                return o.name
            if a == "description":
                if o.description:
                    return o.description

        if o.type == "unit":
            if a == "ou":
                return o.name
            if a == "description":
                if o.description:
                    return o.description

        if o.type == "user":
            if a == "sn":
                return o.name
            if a == "l":
                return o.site

    def rename(self, o, old_name, new_name, callback=default_callback, **kwargs):
        """ Handle rename hook. """
        # Get current DN attribute.
        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()

        modified_attributes = super(OTPmeExtension, self).rename(o, old_name,
                                                                new_name,
                                                                callback=callback,
                                                                **kwargs)
        if dn_attribute not in modified_attributes:
            return callback.ok()

        # Get current DN.
        current_dn = o.get_attribute("dn")
        if not current_dn:
            msg = ("Unable to rename object: Cannot get DN: %s > %s"
                    % (old_name, new_name))
            return callback.error(msg)
        current_dn = current_dn[0]

        # Remove current DN.
        o.del_ldif([("dn", current_dn)])

        # Build new DN.
        dn = self.build_dn(o, dn_attribute)
        if not dn:
            msg = ("Unable to rename object: Cannot build DN: %s > %s"
                    % (old_name, new_name))
            return callback.error(msg)
        # Add new DN.
        o.add_ldif([["dn", dn]], position=0)

        return callback.ok()

    def change_description(self, o, callback=default_callback, **kwargs):
        """ Handle change_description hook. """
        if o.description:
            try:
                self.add_attribute_value(o=o,
                                    attribute='description',
                                    value=o.description,
                                    verify=True,
                                    auto_value=True,
                                    callback=callback)
            except AlreadyExists:
                pass
        else:
            self.del_attribute(o=o, a="description", callback=callback)
        return callback.ok()

    def site_move(self, o, callback=default_callback, **kwargs):
        """ Handle site_move hook. """
        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()
        # Remove old DN attribute.
        current_dn = o.get_attribute("dn")[0]
        o.del_ldif([("dn", current_dn)])
        # Add new DN attribute
        dn = self.build_dn(o, dn_attribute)
        o.add_ldif([["dn", dn]], position=0)
        # Update location.
        if o.type == "user":
            self.del_attribute(o=o, a="l", callback=callback)
            self.add_attribute_value(o=o,
                                attribute="l",
                                value=o.site,
                                verify=True,
                                auto_value=True,
                                callback=callback)
        return callback.ok()

    def update_modified_timestamp(self, o, callback=default_callback, **kwargs):
        """ Handle update_modified_timestamp hook. """
        # Remove old timestamp attribute.
        self.del_attribute(o=o,
                    a="modifyTimestamp",
                    ignore_missing=True,
                    callback=callback)
        if o.last_modified:
            self.add_attribute_value(o=o,
                                attribute="modifyTimestamp",
                                value=o.last_modified,
                                verify=True,
                                auto_value=True,
                                callback=callback)
        return callback.ok()
