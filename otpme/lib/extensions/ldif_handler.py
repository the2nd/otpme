# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import re
from otpme.lib import config
from otpme.lib.ldap import schema

from otpme.lib.exceptions import *

default_callback = config.get_callback()
logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = [
                'otpme.lib.ldap.schema',
                ]

def register():
    register_backend()

def register_backend():
    # Register index attributes.
    config.register_index_attribute('dn', ldif=True)
    config.register_index_attribute('ou', ldif=True)
    config.register_index_attribute('objectClass', ldif=True)
    config.register_index_attribute('subschemaSubentry', ldif=True)

class OTPmeLDIFHandler(object):
    """ Handle LDAP attributes for OTPme objects etc. """
    def __init__(self):
        self.objects_default_attributes = {}

    def init(self, o, default_attributes={}, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Add needed attributes to object. """
        # Add object default attributes to be added by gen_attribute_value().
        self.objects_default_attributes[o.oid.full_oid] = default_attributes

        # Add DN attribute if missing.
        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()

        if dn_attribute not in o.ldif_attributes:
            x_attrs = config.get_ldif_attributes(self.name, o.type)
            if dn_attribute in x_attrs:
                if not self.add_attribute(o=o,
                                        a=dn_attribute,
                                        auto_value=True,
                                        ignore_ro=True,
                                        verify=False,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs):
                    msg = _("Extension {extension_name}: Error adding 'dn' attribute")
                    msg = msg.format(extension_name=self.name)
                    raise OTPmeException(msg)

        # Add non default attributes.
        for at in dict(default_attributes):
            v = default_attributes.pop(at)
            add_result = self.add_attribute(o=o,
                                    a=at,
                                    v=v,
                                    auto_value=False,
                                    ignore_ro=True,
                                    verify=True,
                                    verbose_level=verbose_level,
                                    callback=callback,
                                    **kwargs)
            if not add_result:
                msg = _("Extension {extension_name}: Error adding attribute: {attribute}")
                msg = msg.format(extension_name=self.name, attribute=at)
                raise OTPmeException(msg)

        # Try to add default attributes.
        for at in self.get_default_attributes(o.type):
            if o.get_extension_attribute(extension=self.name, attribute=at):
                continue
            if at in default_attributes:
                v = default_attributes.pop(at)
            else:
                try:
                    v = self.get_attribute_values(o=o, attribute=at)[0]
                except:
                    v = None
            add_result = self.add_attribute(o=o,
                                    a=at,
                                    v=v,
                                    auto_value=True,
                                    ignore_ro=True,
                                    verify=True,
                                    verbose_level=verbose_level,
                                    callback=callback,
                                    **kwargs)
            if not add_result:
                msg = _("Extension {extension_name}: Error adding default attribute: {attribute}")
                msg = msg.format(extension_name=self.name, attribute=at)
                raise OTPmeException(msg)

        self.load(o=o,
                verbose_level=verbose_level,
                callback=callback)

        return callback.ok()

    def get_default_attributes(self, object_type):
        """ Get default attributes of the given object type. """
        try:
            attrs_type = self.default_attributes[object_type]
        except:
            attrs_type = []
        try:
            attrs_all = self.default_attributes['all']
        except:
            attrs_all = []
        attrs = attrs_type + attrs_all
        return attrs

    def build_dn(self, o, dn_attribute):
        """ Build DN. """
        # Domain context.
        dc = None
        # Site OU.
        sou = None
        # Object OU's.
        ous = None

        if o.type == "realm":
            dc = re.sub('[\.]', ',dc=', ".".join(o.name.split(".")[1:]))
        else:
            dc = re.sub('[\.]', ',dc=', o.realm)
        dc = re.sub('^', 'dc=', dc)

        if o.site:
            sou = re.sub('^', 'ou=', o.site)
        if o.unit:
            ous = reversed(o.unit.split("/"))
            ous = "/".join(ous)
            ous = re.sub('[/]', ',ou=', ous)
            ous = re.sub('^', 'ou=', ous)

        # Check if we got the required DN attribute (e.g. cn).
        # The DN attribute may be missing because of a required
        # extension (e.g. posix).
        dn_attr_val = self.get_attribute(o, dn_attribute)
        if len(dn_attr_val) == 0:
            return

        dn_attr_val = dn_attr_val[0]
        dn = f"{dn_attribute}={dn_attr_val}"
        if ous:
            dn = f"{dn},{ous}"
        if sou:
            dn = f"{dn},{sou}"

        dn = f"{dn},{dc}"

        return dn

    def preload(self, o=None):
        """ Preload extension e.g. load schema files. """
        # Load schema files.
        self.load_schema()
        # Add ACL types to object.
        if o:
            # Get ACLs.
            acls = self.get_acls(o.type)
            for acl in acls:
                if acl in o._acls:
                    continue
                o._acls.append(acl)
            # Get value ACLs.
            value_acls = self.get_value_acls(o.type)
            for acl_type in value_acls:
                if acl_type not in o._value_acls:
                    o._value_acls[acl_type] = []
                for attribute in value_acls[acl_type]:
                    if attribute not in o._value_acls[acl_type]:
                        o._value_acls[acl_type].append(attribute)
        # Call child class method to do extension specific stuff.
        return self._preload()

    def load_schema(self, verbose_level=0, callback=default_callback):
        """ Load extension schema files. """
        # Load schema files.
        ocs = []
        ats = []
        for f in self.schema_files:
            f_ocs, f_ats = schema.load(f)
            ocs += f_ocs
            ats += f_ats

        # Register attribute types to config.
        for object_type in self.object_types:
            if object_type not in self.object_classes:
                continue
            # Walk through all object classes for this object type.
            for oc in self.object_classes[object_type]:
                # Register each MAY and MUST attribute to config.
                oc_attributes = config.ldap_object_classes[oc].must \
                                + config.ldap_object_classes[oc].may
                for at in oc_attributes:
                    # Get already registered LDIF attributes.
                    x_attrs = config.get_ldif_attributes(self.name, object_type)
                    if at in x_attrs:
                        continue
                    config.register_ldif_attribute(self.name, object_type, at)
                    try:
                        config.register_index_attribute(at, ldif=True)
                    except AlreadyRegistered:
                        pass

            # Add object attributes that are no deps of any object class.
            try:
                all_object_attributes = self.object_attributes['all']
            except:
                all_object_attributes = []
            try:
                object_attributes = self.object_attributes[object_type]
            except:
                object_attributes = []

            object_attributes = set(all_object_attributes + object_attributes)
            for at in object_attributes:
                if at not in ats:
                    msg = _("Attribute defined in extension {extension_name} not found in schema files: {attribute}")
                    msg = msg.format(extension_name=self.name, attribute=at)
                    raise OTPmeException(msg)
                if at in x_attrs:
                    continue
                config.register_ldif_attribute(self.name, object_type, at)
                try:
                    config.register_index_attribute(at, ldif=True)
                except AlreadyRegistered:
                    pass

    def load(self, o, verify=True, log_errors=False,
        verbose_level=0, callback=default_callback):
        """ Load extension. """
        processed_attributes = []
        # Load schema files if needed.
        self.load_schema(verbose_level=verbose_level, callback=callback)

        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()

        ldif = []
        # Try to get DN.
        if "dn" not in o.ldif_attributes:
            if dn_attribute in o.ldif_attributes:
                dn = self.build_dn(o, dn_attribute)
                if not dn:
                    msg = _("Unable to build DN: {obj}")
                    msg = msg.format(obj=o)
                    return callback.error(msg)
                dn_ldif = [['dn', dn]]
                o.add_ldif(dn_ldif, position=0)

        # Try to add all mandatory attributes to LDIF.
        for oc in o.object_classes:
            # Do not handle object classes that this extension is not
            # responsible for.
            if oc not in self.object_classes[o.type]:
                continue
            try:
                mandatory_attrs = config.ldap_object_classes[oc].must
            except:
                mandatory_attrs = []

            for at in mandatory_attrs:
                if at in processed_attributes:
                    continue
                cur_val = self.get_attribute(o, at)
                if cur_val:
                    continue
                new_val = self.gen_attribute_value(o, at, callback=callback)
                if not new_val:
                    msg = _("Unable to generate attribute value: {obj}: {attribute}")
                    msg = msg.format(obj=o, attribute=at)
                    return callback.error(msg)
                x_ldif = [at, new_val]
                if x_ldif in ldif:
                    continue
                ldif.append(x_ldif)
                processed_attributes.append(at)

        # Add object classes to LDIF.
        for oc in o.object_classes:
            if oc in self.object_classes[o.type]:
                ldif.append(['objectClass', oc])

        # Add all object attributes of this extension to LDIF.
        for at in o.get_extension_attributes(extension=self.name):
            if at in processed_attributes:
                continue
            cur_val = self.get_attribute(o, at)
            if cur_val:
                continue
            new_val = self.gen_attribute_value(o, at, callback=callback)
            x_ldif = [at, new_val]
            if x_ldif in ldif:
                continue
            ldif.append(x_ldif)
            processed_attributes.append(at)

            try:
                at_deps = config.ldap_attribute_deps[at]
            except:
                at_deps = []

            if len(at_deps) > 0:
                at_deps_ok = False
                for oc in at_deps:
                    if oc in o.object_classes:
                        at_deps_ok = True
                        break
                if not at_deps_ok:
                    msg = _("Unable to add object classes: {obj}: {dependencies}")
                    msg = msg.format(obj=o, dependencies=at_deps)
                    return callback.error(msg)

        if o.type == "realm":
            ldif.append(['subschemaSubentry', 'cn=Subschema'])

        # Add LDIF to object.
        o.add_ldif(ldif)

        if verify:
            return self.verify(o=o,
                            log_errors=log_errors,
                            verbose_level=verbose_level,
                            callback=callback)
        return callback.ok()

    def verify(self, o, log_errors=False, verbose_level=0, callback=default_callback):
        """ Verify object_class <> attribute dependencies. """
        if len(o.object_classes) == 0:
            return callback.ok()

        missing_attributes = []
        dn_attribute = config.dn_attributes[o.type]
        # Check if this extension is responsible for the DN attribute.
        if dn_attribute in self.default_attributes[o.type]:
            if not dn_attribute in o.ldif_attributes:
                missing_attributes.append(dn_attribute)
        for oc in o.object_classes:
            # Skip unneeded object classes.
            if not oc in self.object_classes[o.type]:
                continue
            try:
                mandatory_attrs = config.ldap_object_classes[oc].must
            except:
                mandatory_attrs = []

            for at in mandatory_attrs:
                if not at in o.ldif_attributes:
                    # xxxx
                    # FIXME: do we need the check below?
                    if at not in self.attribute_mappings[o.type]:
                        if at not in missing_attributes:
                            missing_attributes.append(at)

        if len(missing_attributes) > 0:
            if log_errors:
                log_msg = _("Object is missing attributes: {extension_name}: {obj}: {attributes}", log=True)[1]
                log_msg = log_msg.format(extension_name=self.name, obj=o, attributes=', '.join(missing_attributes))
                logger.warning(log_msg)
            msg = _("Object is missing the following attributes: {extension_name}: {obj}: {attributes}")
            msg = msg.format(extension_name=self.name, obj=o, attributes=', '.join(missing_attributes))
            return callback.error(msg)

        return callback.ok()

    def get_acls(self, object_type):
        acls = []
        # Merge object ACLs with extension ACLs.
        for a in self.acls:
            if a in acls:
                continue
            acls.append(a)
        return acls

    def get_value_acls(self, object_type):
        # Add ACLs for each objectClass/attribute.
        value_acls = {
                        'view'      : [],
                        'add'       : [],
                        'delete'    : [],
                    }

        # Add ACLs for each attribute.
        for acl_type in value_acls:
            for attribute in self.get_valid_attributes(object_type):
                if attribute in value_acls[acl_type]:
                    continue
                acl = f"attribute:{attribute}"
                value_acls[acl_type].append(acl)

        # Get value ACLs from extension.
        for acl_type in self.value_acls:
            if not acl_type in value_acls:
                value_acls[acl_type] = []
            for attribute in self.value_acls[acl_type]:
                if not attribute in value_acls[acl_type]:
                    value_acls[acl_type].append(attribute)

        return value_acls

    def get_valid_object_classes(self, o):
        """ Get list with all valid attributes for object. """
        ocs = []
        for oc in self.object_classes[o.type]:
            ocs.append(oc)
        return ocs

    def get_valid_attributes(self, object_type):
        """ Get list with all valid attributes for given object type. """
        attrs = config.get_ldif_attributes(self.name, object_type)
        return attrs

    def get_attribute_mappings(self, object_type, attribute=None):
        """ Get attributes mapping for object type. """
        if attribute is not None:
            try:
                o_mappings = self.attribute_mappings[object_type][attribute]
            except:
                o_mappings = []
            try:
                a_mappings = self.attribute_mappings['all'][attribute]
            except:
                a_mappings = []
            attribute_mappings = a_mappings + o_mappings
        else:
            try:
                o_mappings = dict(self.attribute_mappings[object_type])
            except:
                o_mappings = {}
            try:
                a_mappings = dict(self.attribute_mappings['all'])
            except:
                a_mappings = {}
            a_mappings.update(o_mappings)
            attribute_mappings = a_mappings

        return attribute_mappings

    def get_attribute_mapping(self, o, attribute):
        """ Get value of mapped attribute(s). """
        at = []

        try:
            o_mappings = self.attribute_mappings[o.type][attribute]
        except:
            o_mappings = []

        try:
            a_mappings = self.attribute_mappings['all'][attribute]
        except:
            a_mappings = []

        mappings = o_mappings + a_mappings

        for a in mappings:
            if isinstance(a, tuple):
                vals = []
                for attr in a:
                    try:
                        val = self.get_attribute_values(o=o, attribute=attr)[0]
                    except:
                        val = None
                    if val:
                        vals.append(val)
                if vals:
                    vals = " ".join(vals)
                    at.append(vals)
            else:
                try:
                    val = self.get_attribute_values(o=o, attribute=a)[0]
                except:
                    val = None
                if val:
                    at.append(val)

        return at

    def add_attribute_value(self, o, attribute, value, position=-1,
        auto_value=False, verify=True, callback=default_callback):
        """ Add attribute value to object config. """
        # Make sure we only add allowed attribute values.
        if verify:
            self.verify_attribute_value(o, attribute, value, callback=callback)
        # Get current attribute values from object.
        current_attr_values = o.get_attribute(attribute)
        current_attr_ext_values = o.get_extension_attribute(extension=self.name,
                                                            attribute=attribute)
        # No need to update object if value already exists.
        if value in current_attr_values:
            if value in current_attr_ext_values:
                msg = _("Attribute value already exists: {attr}={val}")
                msg = msg.format(attr=attribute, val=value)
                raise AlreadyExists(msg)

        # For single value attributes we override the current value.
        if config.ldap_attribute_types[attribute].single_value:
            for x in current_attr_ext_values:
                o._del_extension_attribute(extension=self.name,
                                            attribute=attribute,
                                            value=x,
                                            callback=callback)
            for x in current_attr_values:
                o.del_ldif([(attribute, x)])

        # Update attribute in object.
        o._add_extension_attribute(self.name, attribute, value,
                                    auto_value=auto_value,
                                    callback=callback)
        o.add_ldif([[attribute, value]], position=position)

    def del_attribute_value(self, o, attribute, value,
        callback=default_callback):
        """ Remove attribute value from object config. """
        if config.ldap_attribute_types[attribute].single_value:
            o.del_ldif([(attribute, value)])
            o._del_extension_attribute(extension=self.name,
                                        attribute=attribute,
                                        value=value,
                                        callback=callback)
            return
        # Get current attribute values from object.
        current_attr_values = o.get_attribute(attribute)
        current_attr_ext_values = o.get_extension_attribute(extension=self.name,
                                                            attribute=attribute)
        # No need to update object if value does not exist.
        if value not in current_attr_values:
            if value not in current_attr_ext_values:
                return

        # Remove attribute from LDIF.
        o.del_ldif([(attribute, value)])
        # Remove extension attribute.
        o._del_extension_attribute(extension=self.name,
                                    attribute=attribute,
                                    value=value,
                                    callback=callback)

    def get_attribute_values(self, o, attribute):
        """ Get attribute values from object. """
        values = []
        if hasattr(o, attribute):
            val = getattr(o, attribute)
            if val == "":
                val = None
            values.append(val)
            return values

        values = o.get_extension_attribute(extension=self.name,
                                            attribute=attribute)
        if values:
            return values

        values = o.get_attribute(attribute)
        if values:
            return values

        return values

    def get_attribute(self, o, attribute):
        """ Get attribute values of object. """
        values = o.get_extension_attribute(extension=self.name, attribute=attribute)
        if not values:
            # Try to get attribute values from object config.
            values = self.get_attribute_values(o=o, attribute=attribute)
        # If there is none check if we have a attribute mapping.
        if not values:
            values = self.get_attribute_mapping(o, attribute)

        val_list = []
        for v in values:
            if v is None:
                continue
            val_list.append(v)

        return val_list

    def modify_attribute(self, o, a, old_value, new_value, ignore_ro=False,
        verify=True, auto_value=False, verbose_level=0, callback=default_callback):
        """ Add attribute to object. """
        # FIXME: what are valid chars for attributes and values?
        if "\\" in str(a) or "\\" in str(new_value):
            msg = ("Invalid character in attribute.")
            return callback.error(msg)

        if not ignore_ro:
            if a in self.read_only_attributes[o.type]:
                msg = _("Attribute '{attr}' is readonly.")
                msg = msg.format(attr=a)
                return callback.error(msg)

        if not o.type in self.object_types:
            msg = _("Object type not supported by this extension: {obj_type}")
            msg = msg.format(obj_type=o.type)
            return callback.error(msg)

        x_attrs = config.get_ldif_attributes(self.name, o.type)
        if not a in x_attrs:
            msg = _("Cannot modify unknown attribute: {extension_name}: {attr}")
            msg = msg.format(extension_name=self.name, attr=a)
            return callback.error(msg)

        current_values = self.get_attribute(o, a)
        if old_value not in current_values:
            msg = _("No attribute value found: {attr}={old_val}")
            msg = msg.format(attr=a, old_val=old_value)
            return callback.error(msg)

        # Remove attribute value
        self.del_attribute(o, a, v=old_value, ignore_deps=True, ignore_ro=ignore_ro)

        # Add new attribute value.
        try:
            self.add_attribute_value(o=o,
                                attribute=a,
                                value=new_value,
                                verify=verify,
                                auto_value=auto_value,
                                callback=callback)
        except Exception as e:
            config.raise_exception()
            msg = _("Unable to add attribute: {attr}: {error}")
            msg = msg.format(attr=a, error=e)
            return callback.error(msg)

        return callback.ok()

    def add_attribute(self, o, a, v=None, position=-1, ignore_ro=False,
        verify=True, auto_value=False, verbose_level=0,
        callback=default_callback):
        """ Add attribute to object. """
        found_object_class = True
        # FIXME: what are valid chars for attributes and values?
        if "\\" in str(a) or "\\" in str(v):
            msg = ("Invalid character in attribute.")
            return callback.error(msg)

        if not ignore_ro:
            if a in self.read_only_attributes[o.type]:
                msg = _("Attribute '{attr}' is readonly.")
                msg = msg.format(attr=a)
                return callback.error(msg)

        if o.type not in self.object_types:
            msg = _("Object type not supported by this extension: {obj_type}")
            msg = msg.format(obj_type=o.type)
            return callback.error(msg)

        x_attrs = config.get_ldif_attributes(self.name, o.type)
        if a not in x_attrs:
            msg = _("Cannot add unknown attribute: {extension_name}: {attr}")
            msg = msg.format(extension_name=self.name, attr=a)
            return callback.error(msg)

        attribute_mappings = self.get_attribute_mappings(o.type, a)
        if attribute_mappings:
            attribute_mapping = self.get_attribute_mapping(o, a)
            if v is None:
                try:
                    v = attribute_mapping[0]
                except:
                    v = None
        try:
            allow_rev_mapping = self.allow_reverse_mappings[o.type][a]
        except:
            allow_rev_mapping = []

        if v is None:
            if not attribute_mappings:
                auto_value = True
                try:
                    v = self.gen_attribute_value(o, a, callback=callback)
                except Exception as e:
                    msg = _("Unable to get attribute value: {attr}: {error}")
                    msg = msg.format(attr=a, error=e)
                    config.raise_exception()
                    raise OTPmeException(msg)

                if v is None:
                    msg = _("Missing value for attribute: {extension_name}: {obj_oid}: {attr}")
                    msg = msg.format(extension_name=self.name, obj_oid=o.oid, attr=a)
                    return callback.error(msg)

        if v is not None:
            try:
                self.add_attribute_value(o=o,
                                    attribute=a,
                                    value=v,
                                    verify=verify,
                                    auto_value=auto_value,
                                    position=position,
                                    callback=callback)
            except Exception as e:
                #config.raise_exception()
                msg = _("Unable to add attribute: {obj_name}: {attr}: {error}")
                msg = msg.format(obj_name=o.name, attr=a, error=e)
                raise OTPmeException(msg)

            if attribute_mappings and v:
                for x in attribute_mappings:
                    if x in allow_rev_mapping:
                        if hasattr(o, x):
                            setattr(o, x, v)

        # Check if user has one of the required object classes assigend.
        if len(config.ldap_attribute_deps[a]) > 0:
            found_object_class = False
            for oc in o.object_classes:
                if oc in config.ldap_attribute_deps[a]:
                    found_object_class = True
                    break

        # Check if one of our default classes is sufficient to met attribute
        # deps.
        if not found_object_class:
            for oc in self.default_classes[o.type]:
                if oc in config.ldap_attribute_deps[a]:
                    if verbose_level > 0:
                        msg = _("Adding needed object class: {object_class}")
                        msg = msg.format(object_class=oc)
                        callback.send(msg)
                    self.add_object_class(o=o,
                                        oc=oc,
                                        verbose_level=verbose_level,
                                        callback=callback)
                    found_object_class = True
                    break

        if not found_object_class:
            # If we found no valid object class for the attribute we have to
            # remove it from the object.
            o._del_extension_attribute(extension=self.name,
                                        attribute=a,
                                        callback=callback)
            msg = _("Attribute '{attr}' needs one of the following object classes: {classes}")
            msg = msg.format(attr=a, classes=', '.join(config.ldap_attribute_deps[a]))
            return callback.error(msg)

        return callback.ok()

    def del_attribute(self, o, a, v=None, ignore_deps=False, ignore_ro=False,
        ignore_missing=False, verbose_level=0, callback=default_callback):
        """ Delete attribute from object. """
        remove_attribute = False

        if not ignore_ro:
            if a in self.read_only_attributes[o.type]:
                msg = _("Attribute '{attr}' is readonly.")
                msg = msg.format(attr=a)
                return callback.send(msg)

        if o.type not in self.object_types:
            msg = _("Unable to delete attribute from object type '{obj_type}'.")
            msg = msg.format(obj_type=o.type)
            return callback.error(msg)

        x_attrs = config.get_ldif_attributes(self.name, o.type)
        if a not in x_attrs:
            if a != config.dn_attributes[o.type]:
                msg = _("Cannot delete unknown attribute: {extension_name}: {attr}")
                msg = msg.format(extension_name=self.name, attr=a)
                return callback.error(msg)

        x_val = o.get_extension_attribute(extension=self.name, attribute=a)
        if not x_val:
            if not ignore_missing:
                msg = _("Object does not have attribute '{attr}'.")
                msg = msg.format(attr=a)
                return callback.error(msg)

        # Check if there are mappings for this attribute.
        mappings = self.get_attribute_mapping(o, a)
        if len(mappings) == 0:
            mappings = False

        # Get allowed reverse mappings.
        try:
            allow_rev_mapping = self.allow_reverse_mappings[o.type][a]
        except:
            allow_rev_mapping = []

        # Check if attribute is DN attribute.
        if a == config.dn_attributes[o.type]:
            mandatory_attribute = "OTPme"
        else:
            mandatory_attribute = False

        # Check if attribute is mandatory for one or more object classes of the
        # object.
        for oc in o.object_classes:
            try:
                mandatory_attrs = config.ldap_object_classes[oc].must
            except:
                mandatory_attrs = []
            if a in mandatory_attrs:
                if mandatory_attribute:
                    mandatory_attribute = f"{mandatory_attribute}, {oc}"
                else:
                    mandatory_attribute = oc

        # If the user has not given a special attribute value remove it.
        if v is None:
            remove_attribute = True
        elif config.ldap_attribute_types[a].single_value:
            # If this a mandatory attribute.
            if mandatory_attribute:
                # And if there is no mapping for this attribute, we
                # should NOT remove it.
                if not mappings:
                    if not ignore_deps:
                        msg = _("Cannot remove single value attribute '{attr}' needed by object class: {mandatory_attr}")
                        msg = msg.format(attr=a, mandatory_attr=mandatory_attribute)
                        return callback.error(msg, exception=MandatoryAttribute)

            # Check if we have a value for this attribute.
            x = self.get_attribute(o, a)
            if x:
                val = x[0]
                # If the value matches, remove the attribute.
                if val == v:
                    remove_attribute = True
                else:
                    msg = _("Unknown attribute value: {attr}: {value}")
                    msg = msg.format(attr=a, value=v)
                    return callback.error(msg)
            else:
                # If we have not value for the attribute delete it.
                remove_attribute = True
        else:
            # Get attribute values.
            value_list = self.get_attribute_values(o=o, attribute=a)
            # Count attribute values.
            value_count = len(value_list)

            # If values for the attribute exists.
            if value_count > 0:
                # Check if the given value exists.
                if v not in value_list:
                    raise OTPmeException("Unknown 'attribute=value' pair.")
                # If this is a mandatory attribute and the last one of this
                # type.
                if mandatory_attribute and value_count < 2:
                    # And if there is no mapping for this attribute, we
                    # should NOT remove it.
                    if not mappings:
                        if not ignore_deps:
                            msg = _("Cannot remove attribute '{attr}' needed by object class: {mandatory_attr}")
                            msg = msg.format(attr=a, mandatory_attr=mandatory_attribute)
                            return callback.error(msg, exception=MandatoryAttribute)
                # Remove attribute value.
                self.del_attribute_value(o=o,
                                    attribute=a,
                                    value=v,
                                    callback=callback)
                # Remove value from list.
                value_list.remove(v)
                # Count of remaining values.
                value_count = len(value_list)

            # If there is no more attribute of this type remaining the attribute
            # can be removed.
            if value_count == 0:
                remove_attribute = True

        # Make sure we do not remove a mandatory attribute.
        if remove_attribute:
            if mandatory_attribute:
                if not mappings and not ignore_deps:
                    msg = _("Cannot remove attribute '{attr}' needed by object class: {mandatory_attr}")
                    msg = msg.format(attr=a, mandatory_attr=mandatory_attribute)
                    return callback.error(msg, exception=MandatoryAttribute)
                if not ignore_deps:
                    remove_attribute = False

        if not remove_attribute:
            return callback.ok()

        ext_attr = o.get_extension_attribute(extension=self.name, attribute=a)
        if ext_attr:
            o._del_extension_attribute(extension=self.name, attribute=a)
        ldif_attrs = o.get_attribute(a)
        for x in ldif_attrs:
            o.del_ldif([(a, x)])

        if a in allow_rev_mapping:
            if hasattr(o, a):
                setattr(o, a, None)

        return callback.ok()

    def add_object_class(self, o, oc, verbose_level=0,
        callback=default_callback):
        """ Add object class to object. """
        if oc in o.object_classes:
            return callback.error("Object class already assigned.")

        if oc not in self.object_classes[o.type]:
            msg = _("Object class not known to this extension: {object_class}")
            msg = msg.format(object_class=oc)
            return callback.error(msg)

        o.object_classes.append(oc)

        for at in self.get_default_attributes(o.type):
            add_attribute = False
            if at in config.ldap_object_classes[oc].must:
                add_attribute = True
            elif at in config.ldap_object_classes[oc].may:
                add_attribute = True
            if not add_attribute:
                continue
            if o.get_extension_attribute(extension=self.name, attribute=at):
                continue
            if verbose_level > 0:
                msg = _("Adding default attribute: {attribute}")
                msg = msg.format(attribute=at)
                callback.send(msg)
            self.add_attribute(o=o,
                            a=at,
                            auto_value=True,
                            ignore_ro=True,
                            verify=True,
                            verbose_level=0,
                            callback=callback)
        return callback.ok()

    def clear_extension(self, o, callback=default_callback):
        """ Clear all extension OCs and attributes. """
        # Get extension attributes.
        attributes = config.get_ldif_attributes(self.name, o.type)
        # Get object DN attribute.
        dn_attribute = config.dn_attributes[o.type]
        # If DN attribute would be remove return error.
        if dn_attribute in attributes:
            msg = _("Cannot remove extension with DN attribute: {extension_name}: {dn_attr}")
            msg = msg.format(extension_name=self.name, dn_attr=dn_attribute)
            return callback.error(msg)
        # Get object classes of extension.
        object_classes = self.object_classes[o.type]
        # Remove object classes.
        for oc in object_classes:
            self.clear_object_class(o, oc, callback=callback, force=True)
        # Remove attributes.
        for at in attributes:
            self.del_attribute(o=o, a=at,
                            ignore_deps=True,
                            ignore_missing=True,
                            callback=callback)
        return callback.ok()

    def clear_object_class(self, o, oc, callback=default_callback, force=False):
        """ Remove all attributes that belong to object class from object. """
        dependent_attributes = []

        # Get MUST and MAY attributes of object class to remove.
        oc_attributes = config.ldap_object_classes[oc].must \
                        + config.ldap_object_classes[oc].may
        for at in oc_attributes:
            if not o.get_extension_attribute(extension=self.name, attribute=at):
                continue
            dependent_attributes.append(at)

        # Remove DN attribute from dependent attributes.
        dn_attribute = config.dn_attributes[o.type]
        if dn_attribute in dependent_attributes:
            dependent_attributes.remove(dn_attribute)

        # Remove all attributes from dependent attributes list that are still
        # needed by any other object class.
        for c in o.object_classes:
            if c == oc:
                continue
            for at in list(dependent_attributes):
                if at not in config.ldap_object_classes[c].must:
                    continue
                dependent_attributes.remove(at)

        # Only remove attributes the object has.
        for at in list(dependent_attributes):
            at_val = self.get_attribute(o, at)
            if at_val:
                continue
            dependent_attributes.remove(at)

        if len(dependent_attributes) > 0 and not force:
            msg = _("{extension_name}: The following attributes depend on the object class and will also be removed: {attributes}")
            msg = msg.format(extension_name=self.name, attributes=', '.join(dependent_attributes))
            return callback.error(msg)

        if len(dependent_attributes) > 0 and force:
            for at in dependent_attributes:
                self.del_attribute(o=o, a=at, ignore_deps=True, callback=callback)

        return callback.ok()

    def get_hook(self, o, hook, **kwargs):
        """ Handle given hook. """
        try:
            hook_method = self.valid_hooks[o.type][hook]
            hook_method = getattr(self, hook_method)
        except:
            try:
                hook_method = self.valid_hooks['all'][hook]
                hook_method = getattr(self, hook_method)
            except:
                return
        return hook_method

    def rename(self, o, old_name, new_name, callback=default_callback, **kwargs):
        """ Handle rename hook. """
        # Update attributes.
        modified_attributes = []
        for a in o.get_extension_attributes(extension=self.name, auto_value=True):
            if a in self.rename_no_update:
                continue
            values = o.get_extension_attribute(extension=self.name,
                                                attribute=a,
                                                auto_value=True)
            for v in values:
                self.del_attribute(o=o,
                                a=a,
                                v=v,
                                ignore_ro=True,
                                ignore_deps=True,
                                ignore_missing=True,
                                callback=callback)
            self.add_attribute(o=o,
                            a=a,
                            verify=True,
                            ignore_ro=True,
                            auto_value=True,
                            verbose_level=0,
                            callback=callback)
            modified_attributes.append(a)

        return modified_attributes

    def change_unit(self, o, new_unit, callback=default_callback, **kwargs):
        """ Handle change unit hook. """
        # Get current DN attribute.
        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()
        # Get current DN.
        current_dn = o.get_attribute("dn")
        if not current_dn:
            msg = _("Unable to change objects unit: Cannot get DN: {obj}")
            msg = msg.format(obj=o)
            raise OTPmeException(msg)
        current_dn = current_dn[0]

        # Remove current DN.
        o.del_ldif([("dn", current_dn)])

        # Build new DN.
        dn = self.build_dn(o, dn_attribute)
        if not dn:
            msg = _("Unable to change objects unit: Cannot build DN: {old_obj_name} > {new_obj_name}")
            msg = msg.format(old_obj_name=old_name, new_obj_name=new_name)
            raise OTPmeException(msg)
        # Add new DN.
        o.add_ldif([["dn", dn]], position=0)

        return callback.ok()
