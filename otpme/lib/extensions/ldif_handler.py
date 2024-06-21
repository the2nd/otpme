# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
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
    def init(self, o, default_attributes={}, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Add needed attributes to object. """
        # Add DN attribute if missing.
        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()

        if not dn_attribute in o.ldif_attributes:
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
                    msg = (_("Extension %s: Error adding 'dn' attribute")
                            % self.name)
                    raise OTPmeException(msg)

        # Get non default attributes.
        non_default_attributes = dict(default_attributes)
        for at in self.get_default_attributes(o.type):
            try:
                non_default_attributes.pop(at)
            except KeyError:
                pass

        # Add non default attributes.
        for at in dict(non_default_attributes):
            v = non_default_attributes.pop(at)
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
                msg = (_("Extension %s: Error adding attribute: %s")
                        % (self.name, at))
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
                msg = (_("Extension %s: Error adding default attribute: %s")
                        % (self.name, at))
                raise OTPmeException(msg)

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
        dn = "%s=%s" % (dn_attribute, dn_attr_val)
        if ous:
            dn = "%s,%s" % (dn, ous)
        if sou:
            dn = "%s,%s" % (dn, sou)

        dn = "%s,%s" % (dn, dc)

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
                if not acl_type in o._value_acls:
                    o._value_acls[acl_type] = []
                for attribute in value_acls[acl_type]:
                    if not attribute in o._value_acls[acl_type]:
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
                    msg = ("Attribute defined in extension %s not found in "
                            "schema files: %s" % (self.name, at))
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
        ldif_incomplete = False
        # Try to get DN.
        if not dn_attribute in o.ldif_attributes:
            dn = self.build_dn(o, dn_attribute)
            if dn:
                ldif.append(('dn', dn))

        # We can only continue if DN is complete.
        if not ldif_incomplete:
            # Try to add all mandatory attributes to LDIF.
            for oc in o.object_classes:
                # Do not handle object classes that this extension is not
                # responsible for.
                if not oc in self.object_classes[o.type]:
                    continue
                try:
                    mandatory_attrs = config.ldap_object_classes[oc].must
                except:
                    mandatory_attrs = []

                for at in mandatory_attrs:
                    if at in processed_attributes:
                        continue
                    at_val = self.get_attribute(o, at)
                    if not at_val:
                        if at in o.ldif_attributes:
                            continue
                        else:
                            ldif_incomplete = True
                            break
                    if config.ldap_attribute_types[at].single_value:
                        if len(at_val) > 1:
                            msg = ("Got multiple values for single value "
                                    "attribute: %s: %s" % (at, at_val))
                            raise OTPmeException(msg)
                        x_ldif = (at, at_val[0])
                        if x_ldif in ldif:
                            continue
                        ldif.append(x_ldif)
                    else:
                        for v in at_val:
                            x_ldif = (at, v)
                            if x_ldif in ldif:
                                continue
                            ldif.append(x_ldif)
                    processed_attributes.append(at)

            # Add object classes to LDIF.
            for oc in o.object_classes:
                if oc in self.object_classes[o.type]:
                    ldif.append(('objectClass', oc))

            # Add all object attributes of this extension to LDIF.
            for at in o.get_extension_attributes(extension=self.name):
                if at in processed_attributes:
                    continue
                at_val = self.get_attribute(o, at)
                if not at_val:
                    continue
                if config.ldap_attribute_types[at].single_value:
                    if len(at_val) > 1:
                        msg = ("Got multiple values for single value "
                                "attribute: %s: %s" % (at, at_val))
                        raise OTPmeException(msg)
                    x_ldif = (at, at_val[0])
                    if x_ldif in ldif:
                        continue
                    ldif.append(x_ldif)
                else:
                    for v in at_val:
                        x_ldif = (at, v)
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
                        ldif_incomplete = True

            if o.type == "realm":
                ldif.append(('subschemaSubentry', 'cn=Subschema'))

        # Only add LDIF stuff if its complete.
        if not ldif_incomplete:
            o.add_ldif(ldif)
        else:
            o.add_ldif_attributes(ldif)

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
                msg = ("Object is missing attributes: %s: %s: %s"
                    % (self.name, o, ", ".join(missing_attributes)))
                logger.warning(msg)
            msg = (_("Object is missing the following attributes: %s: %s: %s")
                    % (self.name, o, ", ".join(missing_attributes)))
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
                acl = "attribute:%s" % attribute
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

    def add_attribute_value(self, o, attribute, value,
        auto_value=False, verify=True, callback=default_callback):
        """ Add attribute value to object config. """
        # Make sure we only add allowed attribute values.
        if verify:
            self.verify_attribute_value(o, attribute, value)
        # Get current attribute values from object.
        current_attr_values = o.get_attribute(attribute)
        current_attr_ext_values = o.get_extension_attribute(extension=self.name,
                                                            attribute=attribute)
        # No need to update object if value already exists.
        if value in current_attr_values:
            if value in current_attr_ext_values:
                return

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
        o.add_ldif([(attribute, value)])

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
                msg = (_("Attribute '%s' is readonly.") % a)
                return callback.error(msg)

        if not o.type in self.object_types:
            msg = (_("Object type not supported by this extension: %s")
                    % o.type)
            return callback.error(msg)

        x_attrs = config.get_ldif_attributes(self.name, o.type)
        if not a in x_attrs:
            msg = (_("Cannot modify unknown attribute: %s: %s") % (self.name, a))
            return callback.error(msg)

        current_values = self.get_attribute(o, a)
        if old_value not in current_values:
            msg = "No attribute value found: %s=%s" % (a, old_value)
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
            msg = (_("Unable to add attribute: %s: %s") % (a, e))
            return callback.error(msg)

        # Reload extension.
        if verify:
            return self.load(o=o,
                            verify=verify,
                            verbose_level=verbose_level,
                            callback=callback)
        return callback.ok()

    def add_attribute(self, o, a, v=None, ignore_ro=False, verify=True,
        auto_value=False, verbose_level=0, callback=default_callback):
        """ Add attribute to object. """
        found_object_class = True
        # FIXME: what are valid chars for attributes and values?
        if "\\" in str(a) or "\\" in str(v):
            msg = ("Invalid character in attribute.")
            return callback.error(msg)

        if not ignore_ro:
            if a in self.read_only_attributes[o.type]:
                msg = (_("Attribute '%s' is readonly.") % a)
                return callback.error(msg)

        if not o.type in self.object_types:
            msg = (_("Object type not supported by this extension: %s")
                    % o.type)
            return callback.error(msg)

        x_attrs = config.get_ldif_attributes(self.name, o.type)
        if not a in x_attrs:
            msg = (_("Cannot add unknown attribute: %s: %s") % (self.name, a))
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
                    msg = (_("Unable to get attribute value: %s: %s") % (a, e))
                    config.raise_exception()
                    raise OTPmeException(msg)

                if v is None:
                    msg = (_("Missing value for attribute: %s: %s: %s")
                            % (self.name, o.oid, a))
                    return callback.error(msg)

        if v is not None:
            try:
                self.add_attribute_value(o=o,
                                    attribute=a,
                                    value=v,
                                    verify=verify,
                                    auto_value=auto_value,
                                    callback=callback)
            except Exception as e:
                config.raise_exception()
                msg = (_("Unable to add attribute: %s: %s") % (a, e))
                return callback.error(msg)

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
                        callback.send(_("Adding needed object class: %s") % oc)
                    self.add_object_class(o=o,
                                        oc=oc,
                                        verify=False,
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
            msg = (_("Attribute '%s' needs one of the following "
                    "object classes: %s")
                    % (a, ", ".join(config.ldap_attribute_deps[a])))
            return callback.error(msg)

        # Reload extension.
        if verify:
            return self.load(o=o,
                            verify=verify,
                            verbose_level=verbose_level,
                            callback=callback)
        return callback.ok()

    def del_attribute(self, o, a, v=None, ignore_deps=False, ignore_ro=False,
        ignore_missing=False, verbose_level=0, callback=default_callback):
        """ Delete attribute from object. """
        remove_attribute = False

        if not ignore_ro:
            if a in self.read_only_attributes[o.type]:
                msg = (_("Attribute '%s' is readonly.") % a)
                return callback.send(msg)

        if not o.type in self.object_types:
            msg = (_("Unable to delete attribute from object type '%s'.")
                    % o.type)
            return callback.error(msg)

        x_attrs = config.get_ldif_attributes(self.name, o.type)
        if not a in x_attrs:
            msg = (_("Cannot delete unknown attribute: %s: %s")
                    % (self.name, a))
            return callback.error(msg)

        x_val = o.get_extension_attribute(extension=self.name, attribute=a)
        if not x_val:
            if ignore_missing:
                return callback.ok()
            msg = (_("Object does not have attribute '%s'.") % a)
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
                    mandatory_attribute = "%s, %s" % (mandatory_attribute, oc)
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
                        msg = (_("Cannot remove single value attribute '%s' needed by "
                            "object class: %s") % (a, mandatory_attribute))
                        return callback.error(msg, exception=MandatoryAttribute)

            # Check if we have a value for this attribute.
            x = self.get_attribute(o, a)
            if x:
                val = x[0]
                # If the value matches, remove the attribute.
                if val == v:
                    remove_attribute = True
                else:
                    msg = (_("Unknown attribute value: %s: %s") % (a, v))
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
                    return callback.error("Unknown 'attribute=value' pair.")
                # If this is a mandatory attribute and the last one of this
                # type.
                if mandatory_attribute and value_count < 2:
                    # And if there is no mapping for this attribute, we
                    # should NOT remove it.
                    if not mappings:
                        if not ignore_deps:
                            msg = (_("Cannot remove attribute '%s' needed by "
                                "object class: %s") % (a, mandatory_attribute))
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
                    msg = (_("Cannot remove attribute '%s' needed by object "
                            "class: %s") % (a, mandatory_attribute))
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

    def add_object_class(self, o, oc, verify=True,
        verbose_level=0, callback=default_callback):
        """ Add object class to object. """
        if oc in o.object_classes:
            return callback.error("Object class already assigned.")

        if not oc in self.object_classes[o.type]:
            raise Exception(_("Object class not known to this extension: %s")
                            % oc)

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
                callback.send(_("Adding default attribute: %s") % at)
            self.add_attribute(o=o,
                            a=at,
                            auto_value=True,
                            ignore_ro=True,
                            verify=False,
                            verbose_level=0,
                            callback=callback)
        # Reload extension.
        if verify:
            return self.load(o=o,
                            verify=verify,
                            verbose_level=verbose_level,
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
                dependent_attributes.append(at)

        # Remove DN attribute from dependent attributes.
        dn_attribute = config.dn_attributes[o.type]
        if dn_attribute in dependent_attributes:
            dependent_attributes.remove(dn_attribute)

        # Remove all attributes from dependent attributes list that are still
        # needed by any other object class.
        for c in o.object_classes:
            if c != oc:
                for at in dependent_attributes:
                    if at in config.ldap_object_classes[c].must:
                        dependent_attributes.remove(at)

        if len(dependent_attributes) > 0 and not force:
            return callback.error(_("%s: The following attributes depend on "
                                    "the object class and will also be "
                                    "removed: %s")
                                    % (self.name,
                                    ", ".join(dependent_attributes)))

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

    def change_unit(self, o, old_unit, new_unit, callback=default_callback, **kwargs):
        """ Handle change unit hook. """
        # Get current DN attribute.
        try:
            dn_attribute = config.dn_attributes[o.type]
        except:
            return callback.ok()
        # Get current DN.
        current_dn = o.get_attribute("dn")
        if not current_dn:
            msg = ("Unable to change objects unit: Cannot get DN: %s" % o)
            raise OTPmeException(msg)
        current_dn = current_dn[0]

        # Remove current DN.
        o.del_ldif([("dn", current_dn)])

        # Build new DN.
        dn = self.build_dn(o, dn_attribute)
        if not dn:
            msg = ("Unable to change objects unit: Cannot build DN: %s > %s"
                    % (old_name, new_name))
            raise OTPmeException(msg)
        # Add new DN.
        o.add_ldif([("dn", dn)])

        return callback.ok()
