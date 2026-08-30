# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import ldap.schema

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
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

# Names of the LDAP syntaxes our schema files reference. Only used to put
# a DESC into the "ldapSyntaxes" we publish in cn=Subschema. RFC 4512
# makes DESC optional, so a syntax that is missing here is still
# published, just without a name.
#
# Taken from the subschema an OpenLDAP 2.5 slapd publishes, plus the ones
# it has dropped over the years while our core/cosine copies still use
# them. Those carry their source, they cannot be re-read from a current
# slapd.
LDAP_SYNTAXES = {
        '1.2.36.79672281.1.5.0'             : 'RDN',
        '1.2.840.113549.1.8.1.1'            : 'PKCS#8 PrivateKeyInfo',
        '1.3.6.1.1.1.0.0'                   : 'RFC2307 NIS Netgroup Triple',
        '1.3.6.1.1.1.0.1'                   : 'RFC2307 Boot Parameter',
        '1.3.6.1.1.16.1'                    : 'UUID',
        '1.3.6.1.4.1.1466.115.121.1.4'      : 'Audio',
        '1.3.6.1.4.1.1466.115.121.1.5'      : 'Binary',
        '1.3.6.1.4.1.1466.115.121.1.6'      : 'Bit String',
        '1.3.6.1.4.1.1466.115.121.1.7'      : 'Boolean',
        '1.3.6.1.4.1.1466.115.121.1.8'      : 'Certificate',
        '1.3.6.1.4.1.1466.115.121.1.9'      : 'Certificate List',
        '1.3.6.1.4.1.1466.115.121.1.10'     : 'Certificate Pair',
        '1.3.6.1.4.1.1466.115.121.1.11'     : 'Country String',
        '1.3.6.1.4.1.1466.115.121.1.12'     : 'Distinguished Name',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.13'     : 'Data Quality Syntax',
        '1.3.6.1.4.1.1466.115.121.1.14'     : 'Delivery Method',
        '1.3.6.1.4.1.1466.115.121.1.15'     : 'Directory String',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.19'     : 'DSA Quality Syntax',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.21'     : 'Enhanced Guide',
        '1.3.6.1.4.1.1466.115.121.1.22'     : 'Facsimile Telephone Number',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.23'     : 'Fax',
        '1.3.6.1.4.1.1466.115.121.1.24'     : 'Generalized Time',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.25'     : 'Guide',
        '1.3.6.1.4.1.1466.115.121.1.26'     : 'IA5 String',
        '1.3.6.1.4.1.1466.115.121.1.27'     : 'Integer',
        '1.3.6.1.4.1.1466.115.121.1.28'     : 'JPEG',
        '1.3.6.1.4.1.1466.115.121.1.34'     : 'Name And Optional UID',
        '1.3.6.1.4.1.1466.115.121.1.36'     : 'Numeric String',
        '1.3.6.1.4.1.1466.115.121.1.38'     : 'OID',
        '1.3.6.1.4.1.1466.115.121.1.39'     : 'Other Mailbox',
        '1.3.6.1.4.1.1466.115.121.1.40'     : 'Octet String',
        '1.3.6.1.4.1.1466.115.121.1.41'     : 'Postal Address',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.42'     : 'Protocol Information',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.43'     : 'Presentation Address',
        '1.3.6.1.4.1.1466.115.121.1.44'     : 'Printable String',
        '1.3.6.1.4.1.1466.115.121.1.45'     : 'SubtreeSpecification',
        '1.3.6.1.4.1.1466.115.121.1.49'     : 'Supported Algorithm',
        '1.3.6.1.4.1.1466.115.121.1.50'     : 'Telephone Number',
        # RFC 2252.
        '1.3.6.1.4.1.1466.115.121.1.51'     : 'Teletex Terminal Identifier',
        '1.3.6.1.4.1.1466.115.121.1.52'     : 'Telex Number',
        # RFC 4517. No attribute type uses it, but it is the syntax of
        # every substrings matching rule we publish.
        '1.3.6.1.4.1.1466.115.121.1.58'     : 'Substring Assertion',
        '1.3.6.1.4.1.4203.666.11.10.2.1'    : 'X.509 AttributeCertificate',
        }

# OID and assertion syntax of the matching rules our schema files
# reference. A schema file names its EQUALITY/ORDERING/SUBSTR rule, but
# "matchingRules" of cn=Subschema is keyed by OID, so a rule that is
# missing here cannot be published and is left out.
#
# Same source as LDAP_SYNTAXES above.
LDAP_MATCHING_RULES = {
        'rdnMatch'                          : ('1.2.36.79672281.1.13.3', '1.2.36.79672281.1.5.0'),
        'integerBitAndMatch'                : ('1.2.840.113556.1.4.803', '1.3.6.1.4.1.1466.115.121.1.27'),
        'integerBitOrMatch'                 : ('1.2.840.113556.1.4.804', '1.3.6.1.4.1.1466.115.121.1.27'),
        'UUIDMatch'                         : ('1.3.6.1.1.16.2', '1.3.6.1.1.16.1'),
        'UUIDOrderingMatch'                 : ('1.3.6.1.1.16.3', '1.3.6.1.1.16.1'),
        'caseExactIA5Match'                 : ('1.3.6.1.4.1.1466.109.114.1', '1.3.6.1.4.1.1466.115.121.1.26'),
        'caseIgnoreIA5Match'                : ('1.3.6.1.4.1.1466.109.114.2', '1.3.6.1.4.1.1466.115.121.1.26'),
        'caseIgnoreIA5SubstringsMatch'      : ('1.3.6.1.4.1.1466.109.114.3', '1.3.6.1.4.1.1466.115.121.1.26'),
        'caseExactIA5SubstringsMatch'       : ('1.3.6.1.4.1.4203.1.2.1', '1.3.6.1.4.1.1466.115.121.1.26'),
        'objectIdentifierMatch'             : ('2.5.13.0', '1.3.6.1.4.1.1466.115.121.1.38'),
        'distinguishedNameMatch'            : ('2.5.13.1', '1.3.6.1.4.1.1466.115.121.1.12'),
        'caseIgnoreMatch'                   : ('2.5.13.2', '1.3.6.1.4.1.1466.115.121.1.15'),
        'caseIgnoreOrderingMatch'           : ('2.5.13.3', '1.3.6.1.4.1.1466.115.121.1.15'),
        'caseIgnoreSubstringsMatch'         : ('2.5.13.4', '1.3.6.1.4.1.1466.115.121.1.58'),
        'caseExactMatch'                    : ('2.5.13.5', '1.3.6.1.4.1.1466.115.121.1.15'),
        'caseExactOrderingMatch'            : ('2.5.13.6', '1.3.6.1.4.1.1466.115.121.1.15'),
        'caseExactSubstringsMatch'          : ('2.5.13.7', '1.3.6.1.4.1.1466.115.121.1.58'),
        'numericStringMatch'                : ('2.5.13.8', '1.3.6.1.4.1.1466.115.121.1.36'),
        'numericStringOrderingMatch'        : ('2.5.13.9', '1.3.6.1.4.1.1466.115.121.1.36'),
        'numericStringSubstringsMatch'      : ('2.5.13.10', '1.3.6.1.4.1.1466.115.121.1.58'),
        'caseIgnoreListMatch'               : ('2.5.13.11', '1.3.6.1.4.1.1466.115.121.1.41'),
        'caseIgnoreListSubstringsMatch'     : ('2.5.13.12', '1.3.6.1.4.1.1466.115.121.1.58'),
        'booleanMatch'                      : ('2.5.13.13', '1.3.6.1.4.1.1466.115.121.1.7'),
        'integerMatch'                      : ('2.5.13.14', '1.3.6.1.4.1.1466.115.121.1.27'),
        'integerOrderingMatch'              : ('2.5.13.15', '1.3.6.1.4.1.1466.115.121.1.27'),
        'bitStringMatch'                    : ('2.5.13.16', '1.3.6.1.4.1.1466.115.121.1.6'),
        'octetStringMatch'                  : ('2.5.13.17', '1.3.6.1.4.1.1466.115.121.1.40'),
        'octetStringOrderingMatch'          : ('2.5.13.18', '1.3.6.1.4.1.1466.115.121.1.40'),
        'octetStringSubstringsMatch'        : ('2.5.13.19', '1.3.6.1.4.1.1466.115.121.1.40'),
        'telephoneNumberMatch'              : ('2.5.13.20', '1.3.6.1.4.1.1466.115.121.1.50'),
        'telephoneNumberSubstringsMatch'    : ('2.5.13.21', '1.3.6.1.4.1.1466.115.121.1.58'),
        # RFC 2252.
        'presentationAddressMatch'          : ('2.5.13.22', '1.3.6.1.4.1.1466.115.121.1.43'),
        'uniqueMemberMatch'                 : ('2.5.13.23', '1.3.6.1.4.1.1466.115.121.1.34'),
        # RFC 2252.
        'protocolInformationMatch'          : ('2.5.13.24', '1.3.6.1.4.1.1466.115.121.1.42'),
        'generalizedTimeMatch'              : ('2.5.13.27', '1.3.6.1.4.1.1466.115.121.1.24'),
        'generalizedTimeOrderingMatch'      : ('2.5.13.28', '1.3.6.1.4.1.1466.115.121.1.24'),
        'integerFirstComponentMatch'        : ('2.5.13.29', '1.3.6.1.4.1.1466.115.121.1.27'),
        'objectIdentifierFirstComponentMatch': ('2.5.13.30', '1.3.6.1.4.1.1466.115.121.1.38'),
        'certificateExactMatch'             : ('2.5.13.34', '1.3.6.1.1.15.1'),
        'certificateListExactMatch'         : ('2.5.13.38', '1.3.6.1.1.15.5'),
        }

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
            if x == "NO-USER-MODIFICATION":
                cur = "NO-USER-MODIFICATION"
                self.no_user_mod = True
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
                    self.desc = f"{self.desc} {x}"
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

    def format_names(self):
        """ Our NAMEs as a RFC 4512 qdescrs.

        A single name goes out bare, more than one in brackets. That is
        not cosmetics: a client parses "NAME ( 'cn' 'commonName' )" as
        two names and "NAME 'cn'" as one.
        """
        if not self.names:
            return None
        names = [x.replace("'", "") for x in self.names]
        if len(names) == 1:
            return f"'{names[0]}'"
        names = " ".join([f"'{x}'" for x in names])
        return f"( {names} )"

    def format_desc(self):
        """ Our DESC as a RFC 4512 qdstring.

        The parser keeps the quotes the schema file had, so a normal
        description already comes quoted and goes out unchanged.
        """
        desc = self.desc
        if desc.startswith("'") and desc.endswith("'"):
            return desc
        desc = desc.replace("'", "")
        return f"'{desc}'"

    def format_oids(self, oids):
        """ A list of attribute or class names as a RFC 4512 oids.

        Same rule as for the names: a single one bare, more than one
        "$" separated in brackets.
        """
        oids = [x.replace("'", "") for x in oids]
        if len(oids) == 1:
            return oids[0]
        return f"( {' $ '.join(oids)} )"

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

    def __str__(self):
        """ Our definition as a RFC 4512 ObjectClassDescription.

        This is what a client reads from "objectClasses" of the
        cn=Subschema entry, so the order of the parts is the one the RFC
        prescribes, not the one the schema file happened to use.
        """
        parts = ["(", self.oid]
        names = self.format_names()
        if names:
            parts.append(f"NAME {names}")
        if self.desc:
            parts.append(f"DESC {self.format_desc()}")
        if self.obsolete:
            parts.append("OBSOLETE")
        if self.sup:
            parts.append(f"SUP {self.format_oids(self.sup)}")
        # An object class without a kind is STRUCTURAL. Say it instead of
        # leaving the client to know the default.
        parts.append(self.kind or "STRUCTURAL")
        if self.must:
            parts.append(f"MUST {self.format_oids(self.must)}")
        if self.may:
            parts.append(f"MAY {self.format_oids(self.may)}")
        parts.append(")")
        return " ".join(parts)

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
        self.no_user_mod = False
        self.single_value = False
        self.usage = "userApplications"
        # Call parent class init.
        SchemaElement.__init__(self, schema_string)

    def __str__(self):
        """ Our definition as a RFC 4512 AttributeTypeDescription.

        This is what a client reads from "attributeTypes" of the
        cn=Subschema entry, so the order of the parts is the one the RFC
        prescribes, not the one the schema file happened to use.
        """
        parts = ["(", self.oid]
        names = self.format_names()
        if names:
            parts.append(f"NAME {names}")
        if self.desc:
            parts.append(f"DESC {self.format_desc()}")
        if self.obsolete:
            parts.append("OBSOLETE")
        if self.sup:
            parts.append(f"SUP {self.format_oids(self.sup)}")
        if self.equality:
            parts.append(f"EQUALITY {self.equality}")
        if self.ordering:
            parts.append(f"ORDERING {self.ordering}")
        if self.substr:
            parts.append(f"SUBSTR {self.substr}")
        if self.syntax:
            parts.append(f"SYNTAX {self.syntax}")
        if self.single_value:
            parts.append("SINGLE-VALUE")
        if self.collective:
            parts.append("COLLECTIVE")
        if self.no_user_mod:
            parts.append("NO-USER-MODIFICATION")
        # userApplications is the default and stays implicit, the same
        # way the schema files write it.
        if self.usage and self.usage != "userApplications":
            parts.append(f"USAGE {self.usage}")
        parts.append(")")
        return " ".join(parts)

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
    except Exception:
        pass

    try:
        fd = open(schema_file, "r")
    except Exception as e:
        msg = _("Error reading schema file: {e}")
        msg = msg.format(e=e)
        raise Exception(msg) from e

    log_msg = _("Loading schema file: {schema_file}", log=True)[1]
    log_msg = log_msg.format(schema_file=schema_file)
    logger.debug(log_msg)
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
        object_config = re.sub(r'(.*\))[^\)]*$', r'\1', object_config)

        if object_type == "objectclass":
            oc = ObjectClass(object_config)
            for name in oc.names:
                try:
                    config.ldap_object_classes[name]
                    oc_exists = True
                except Exception:
                    oc_exists = False
                if oc_exists:
                    log_msg = _("Error loading file: {schema_file}: ObjectClass '{name}' already exists.", log=True)[1]
                    log_msg = log_msg.format(schema_file=schema_file, name=name)
                    logger.critical(log_msg)
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
                except Exception:
                    at_exists = False
                if at_exists:
                    log_msg = _("Error loading file: {schema_file}: AttributeType '{name}' already exists.", log=True)[1]
                    log_msg = log_msg.format(schema_file=schema_file, name=name)
                    logger.critical(log_msg)
                else:
                    attribute_types.append(name)
                    config.ldap_attribute_types[name] = at
                    # Add object attribute name mapping (case insensitive).
                    config.ldap_attribute_type_mappings[name.lower()] = name
                try:
                    config.ldap_attribute_deps[name]
                except Exception:
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
                if oc in config.ldap_attribute_deps[n]:
                    continue
                config.ldap_attribute_deps[n].append(oc)

    # Add schema file to list of loaded files.
    config.ldap_schema_files_loaded[schema_file] = [object_classes,
                                                    attribute_types]
    return object_classes, attribute_types

def get_attribute_type(name):
    """ Get a loaded attribute type by name. """
    name = name.replace("'", "")
    try:
        name = config.ldap_attribute_type_mappings[name.lower()]
    except KeyError:
        return None
    try:
        return config.ldap_attribute_types[name]
    except KeyError:
        return None

def get_inherited(attribute_type, attribute):
    """ Get an attribute type property, following SUP if it has none.

    An attribute type may leave its syntax or its matching rules to the
    one it derives from ("cn" has nothing but "SUP name"), so asking the
    type itself is not enough to tell which syntax it really uses.
    """
    seen = []
    while attribute_type is not None:
        value = getattr(attribute_type, attribute, None)
        if value:
            return value
        if not attribute_type.sup:
            return None
        sup_name = attribute_type.sup[0].replace("'", "")
        # A schema that derives in a circle would keep us here forever.
        if sup_name in seen:
            return None
        seen.append(sup_name)
        attribute_type = get_attribute_type(sup_name)
    return None

def get_loaded_elements():
    """ Get the loaded object classes and attribute types, each one once.

    config.ldap_object_classes and config.ldap_attribute_types are keyed
    by every NAME an element carries, so one with an alias (e.g. "cn" and
    "commonName") sits in there more than once. Publishing it twice would
    hand the client two definitions for the same OID.
    """
    object_classes = []
    attribute_types = []
    seen_classes = []
    seen_attributes = []
    for name in config.ldap_object_classes:
        object_class = config.ldap_object_classes[name]
        if object_class.oid in seen_classes:
            continue
        seen_classes.append(object_class.oid)
        object_classes.append(object_class)
    for name in config.ldap_attribute_types:
        attribute_type = config.ldap_attribute_types[name]
        if attribute_type.oid in seen_attributes:
            continue
        seen_attributes.append(attribute_type.oid)
        attribute_types.append(attribute_type)
    return object_classes, attribute_types

def get_subschema_ldif():
    """ Build the schema attributes of the cn=Subschema entry.

    RFC 4512 has a DSA publish its schema so a client can find out what
    it may ask for. We publish what we actually loaded: the object
    classes and attribute types of our schema files and the syntaxes and
    matching rules they reference.

    No "matchingRuleUse": that attribute does not describe the schema,
    it tells a client which extensible match assertions it may send --
    e.g. "(cn:caseExactMatch:=Meier)". Our search filter has no
    extensible match (see LDIFTreeEntry.decode_ldap_filter()), so
    publishing it would advertise something every client trying it would
    fail on.
    """
    object_classes, attribute_types = get_loaded_elements()

    syntaxes = []
    matching_rules = []

    for attribute_type in attribute_types:
        syntax = get_inherited(attribute_type, "syntax")
        if syntax:
            # The length limit ("{256}") belongs to the attribute type,
            # the syntax itself is just the OID.
            syntax_oid = syntax.split("{")[0]
            if syntax_oid not in syntaxes:
                syntaxes.append(syntax_oid)
        for rule_type in ["equality", "ordering", "substr"]:
            rule = get_inherited(attribute_type, rule_type)
            if not rule:
                continue
            rule = rule.replace("'", "")
            if rule not in matching_rules:
                matching_rules.append(rule)

    # A rule we cannot name an OID for cannot be published.
    for rule in list(matching_rules):
        try:
            rule_syntax = LDAP_MATCHING_RULES[rule][1]
        except KeyError:
            log_msg = _("Unknown matching rule, not publishing it: {rule}", log=True)[1]
            log_msg = log_msg.format(rule=rule)
            logger.debug(log_msg)
            matching_rules.remove(rule)
            continue
        # The assertion syntax of a rule is usually not one an attribute
        # type uses, so it is missing from what we collected above.
        if rule_syntax in syntaxes:
            continue
        syntaxes.append(rule_syntax)

    ldif = ""
    for object_class in object_classes:
        ldif = f"{ldif}objectClasses: {object_class}\n"
    for attribute_type in attribute_types:
        ldif = f"{ldif}attributeTypes: {attribute_type}\n"
    for syntax_oid in syntaxes:
        try:
            syntax_desc = LDAP_SYNTAXES[syntax_oid]
        except KeyError:
            # DESC is optional, so a syntax we have no name for is still
            # a valid definition.
            ldif = f"{ldif}ldapSyntaxes: ( {syntax_oid} )\n"
            continue
        ldif = f"{ldif}ldapSyntaxes: ( {syntax_oid} DESC '{syntax_desc}' )\n"
    for rule in matching_rules:
        rule_oid, rule_syntax = LDAP_MATCHING_RULES[rule]
        ldif = f"{ldif}matchingRules: ( {rule_oid} NAME '{rule}' SYNTAX {rule_syntax} )\n"

    return ldif
