# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import ldap.schema

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import config
from otpme.lib.cache import ldap_schema_cache

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    register_config()

def register_config():
    """ Register config stuff. """
    # LDAP schema stuff.
    config.register_config_var("ldap_schema_files_loaded", dict, {})
    config.register_config_var("ldap_object_classes", dict, {})
    config.register_config_var("ldap_attribute_types", dict, {})
    config.register_config_var("ldap_attribute_deps", dict, {})
    config.register_config_var("ldap_attribute_type_mappings", dict, {})
    config.register_config_var("ldap_object_class_mappings", dict, {})

class SchemaElement(object):
    """ Schema element parser """
    def __init__(self, schema_string):
        self.oid = None
        self.name = None
        self.names = []
        self.sup = []
        self.desc = None
        self.obsolete = False
        self.load_schema_string(schema_string)

    def load_schema_string(self, schema_string):
        """ Load schema string """
        cur = None
        prev = None
        for x in schema_string.split():
            #print("TEST: %s" % x)
            if x == "(":
                continue
            if x == "$":
                continue
            if x == ")":
                continue

            if x == "NAME":
                cur = "NAME"
                continue
            if x == "DESC":
                cur = "DESC"
                continue
            if x == "USAGE":
                cur = "USAGE"
                continue
            if x == "SUP":
                cur = "SUP"
                continue
            if x == "SYNTAX":
                cur = "SYNTAX"
                continue
            if x == "SUBSTR":
                cur = "SUBSTR"
                continue
            if x == "ORDERING":
                cur = "ORDERING"
                continue
            if x == "OBSOLETE":
                cur = "OBSOLETE"
                self.obsolete = True
                continue
            if x == "COLLECTIVE":
                cur = "COLLECTIVE"
                self.collective = True
                continue
            if x == "EQUALITY":
                cur = "EQUALITY"
                continue
            if x == "STRUCTURAL":
                cur = "STRUCTURAL"
                self.kind = x
                continue
            if x == "ABSTRACT":
                cur = "ABSTRACT"
                self.kind = x
                continue
            if x == "AUXILIARY":
                cur = "AUXILIARY"
                self.kind = x
                continue
            if x == "SINGLE-VALUE":
                cur = "SINGLE-VALUE"
                self.single_value = True
                continue
            if x == "MUST":
                cur = "MUST"
                continue
            if x == "MAY":
                cur = "MAY"
                continue

            if cur == "NAME":
                if not self.name:
                    self.name = x.replace("'", "")
                if not self.oid:
                    self.oid = prev
                self.names.append(x.replace("'", ""))

            if cur == "DESC":
                if self.desc:
                    self.desc = "%s %s" % (self.desc, x)
                else:
                    self.desc = x

            if cur == "USAGE":
                self.usage = x

            if cur == "SUP":
                self.sup.append(x)

            if cur == "SYNTAX":
                self.syntax = x

            if cur == "SUBSTR":
                self.substr = x

            if cur == "EQUALITY":
                self.equality = x

            if cur == "ORDERING":
                self.ordering = x

            if cur == "MUST":
                self.must.append(x)

            if cur == "MAY":
                self.may.append(x)

            prev = x

class ObjectClass(SchemaElement):
    """
    oid
      OID assigned to the object class
    names
      This list of strings contains all NAMEs of the object class
    desc
      This string contains description text (DESC) of the object class
    obsolete
      Integer flag (0 or 1) indicating whether the object class is marked
      as OBSOLETE in the schema
    must
      This list of strings contains NAMEs or OIDs of all attributes
      an entry of the object class must have
    may
      This list of strings contains NAMEs or OIDs of additional attributes
      an entry of the object class may have
    kind
      Kind of an object class:
      0 = ABSTRACT,
      1 = STRUCTURAL,
      2 = AUXILIARY
    sup
      This list of strings contains NAMEs or OIDs of object classes
      this object class is derived from
    """
    def __init__(self, schema_string):
        self.must = []
        self.may = []
        self.kind = None
        # Call parent class init.
        SchemaElement.__init__(self, schema_string)

class AttributeType(SchemaElement):
    """
    oid
      OID assigned to the attribute type
    names
      This list of strings contains all NAMEs of the attribute type
    desc
      This string contains description text (DESC) of the attribute type
    obsolete
      Integer flag (0 or 1) indicating whether the attribute type is marked
      as OBSOLETE in the schema
    single_value
      Integer flag (0 or 1) indicating whether the attribute must
      have only one value
    syntax
      String contains OID of the LDAP syntax assigned to the attribute type
    no_user_mod
      Integer flag (0 or 1) indicating whether the attribute is modifiable
      by a client application
    equality
      String contains NAME or OID of the matching rule used for
      checking whether attribute values are equal
    substr
      String contains NAME or OID of the matching rule used for
      checking whether an attribute value contains another value
    ordering
      String contains NAME or OID of the matching rule used for
      checking whether attribute values are lesser-equal than
    usage
      USAGE of an attribute type:
      0 = userApplications
      1 = directoryOperation,
      2 = distributedOperation,
      3 = dSAOperation
    sup
      This list of strings contains NAMEs or OIDs of attribute types
      this attribute type is derived from
    """
    def __init__(self, schema_string):
        self.syntax = None
        self.substr = None
        self.equality = None
        self.ordering = None
        self.collective = False
        self.single_value = False
        self.usage = "userApplications"
        # Call parent class init.
        SchemaElement.__init__(self, schema_string)

@ldap_schema_cache.cache_function()
def load(schema_file):
    """ Load LDAP schema file. """
    processing = False
    object_config = ""
    bracked_open = 0
    bracked_close = 0
    object_classes = []
    attribute_types = []

    # Check if this file is already loaded.
    try:
        object_classes, \
        attribute_types = config.ldap_schema_files_loaded[schema_file]
        return object_classes, attribute_types
    except:
        pass

    try:
        fd = open(schema_file, "r")
    except Exception as e:
        raise Exception(_("Error reading schema file: %s") % e)

    logger.debug("Loading schema file: %s" % schema_file)
    config.ldap_object_class_mappings['objectclass'] = 'objectClass'
    for line in fd:
        if line.startswith("objectclass") or line.startswith("attributetype"):
            if line.startswith("objectclass"):
                object_type = "objectclass"
            if line.startswith("attributetype"):
                object_type = "attributetype"
            object_config = ""
            bracked_open = 0
            bracked_close = 0
            processing = True

        if not processing:
            continue

        for c in line:
            if c == "(":
                bracked_open += 1
            if c == ")":
                bracked_close += 1

        object_config += line

        if bracked_open != bracked_close:
            continue
        object_config = object_config[len(object_type)+1:]
        object_config = object_config.replace('\n',' ')
        object_config = object_config.replace('\t', ' ')
        object_config = re.sub('(.*\))[^\)]*$', r'\1', object_config)

        if object_type == "objectclass":
            oc = ObjectClass(object_config)
            for name in oc.names:
                try:
                    config.ldap_object_classes[name]
                    oc_exists = True
                except:
                    oc_exists = False
                if oc_exists:
                    msg = (_("Error loading file: %s: ObjectClass "
                            "'%s' already exists.") % (schema_file, name))
                    logger.critical(msg)
                else:
                    object_classes.append(name)
                    config.ldap_object_classes[name] = oc
                    # Add object class name mapping (case insensitive).
                    config.ldap_object_class_mappings[name.lower()] = name

        if object_type == "attributetype":
            at = AttributeType(object_config)
            for name in at.names:
                try:
                    config.ldap_attribute_types[name]
                    at_exists = True
                except:
                    at_exists = False
                if at_exists:
                    msg = (_("Error loading file: %s: AttributeType '%s' "
                            "already exists.") % (schema_file, name))
                    logger.critical(msg)
                else:
                    attribute_types.append(name)
                    config.ldap_attribute_types[name] = at
                    # Add object attribute name mapping (case insensitive).
                    config.ldap_attribute_type_mappings[name.lower()] = name
                try:
                    config.ldap_attribute_deps[name]
                except:
                    config.ldap_attribute_deps[name] = []

        processing = False
        object_config = ""
        bracked_open = 0
        bracked_close = 0

    # Close schema file.
    fd.close()

    # Add attribute -> objectClass deps.
    for oc in object_classes:
        must_may = config.ldap_object_classes[oc].must \
                + config.ldap_object_classes[oc].may
        for a in must_may:
            for n in config.ldap_attribute_types[a].names:
                if not oc in config.ldap_attribute_deps[n]:
                    config.ldap_attribute_deps[n].append(oc)

    # Add schema file to list of loaded files.
    config.ldap_schema_files_loaded[schema_file] = [object_classes,
                                                    attribute_types]
    return object_classes, attribute_types
