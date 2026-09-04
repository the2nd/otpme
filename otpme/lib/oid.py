# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.typing import match_class_typing

from otpme.lib.exceptions import *

# Regex used to check that object names/paths are correct.
# Names may contain chars "_.-" but must start and end with :alnum:
# e.g. "otpme.org" is okay but "otpme." is not okay.
site_getter = {}
unit_getter = {}
object_regex = {}
oid_resolver = {}
name_checker = {}
full_oid_schema = {}
read_oid_schema = {}
rel_path_getter = {}
valid_object_owners = {}

# Some useful default regex.
int_re = '[0-9]*'
# Without the trailing \Z. Every user of this puts it in the middle of a
# larger OID pattern, and \Z anchors to the end of the string -- nothing
# behind it could ever match. Whoever needs the anchor adds it, which is
# what the OID checks do anyway (they compile "^<pattern>$").
#uuid_re = r'[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z'
uuid_re = r'[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}'

def register_site_getter(object_type, getter):
    """ Register function to get site of object. """
    global site_getter
    try:
        x_getter = site_getter[object_type]
    except Exception:
        x_getter = None
    if x_getter:
        msg = _("Site getter already registered: {object_type}: {x_getter}")
        msg = msg.format(object_type=object_type, x_getter=x_getter)
        raise OTPmeException(msg)
    site_getter[object_type] = getter

def register_unit_getter(object_type, getter):
    """ Register function to get unit of object. """
    global unit_getter
    try:
        x_getter = unit_getter[object_type]
    except Exception:
        x_getter = None
    if x_getter:
        msg = _("Unit getter already registered: {object_type}: {x_getter}")
        msg = msg.format(object_type=object_type, x_getter=x_getter)
        raise OTPmeException(msg)
    unit_getter[object_type] = getter

def register_name_checker(object_type, getter):
    """ Register function to check name of object. """
    global name_checker
    try:
        x_checker = name_checker[object_type]
    except Exception:
        x_checker = None
    if  x_checker:
        msg = _("Name checker already registered: {object_type}: {x_checker}")
        msg = msg.format(object_type=object_type, x_checker=x_checker)
        raise OTPmeException(msg)
    name_checker[object_type] = getter

def register_oid_resolver(object_type, resolver):
    """ Register function to resolve read OID to full OID. """
    global oid_resolver
    try:
        x_resolver = oid_resolver[object_type]
    except Exception:
        x_resolver = None
    if x_resolver:
        msg = _("Resolver already registered: {object_type}: {x_resolver}")
        msg = msg.format(object_type=object_type, x_resolver=x_resolver)
        raise OTPmeException(msg)
    oid_resolver[object_type] = resolver

def register_rel_path_getter(object_type, getter):
    """ Register function to get rel path of object. """
    global rel_path_getter
    try:
        x_getter = rel_path_getter[object_type]
    except Exception:
        x_getter = None
    if x_getter:
        msg = _("Relpath getter already registered: {object_type}: {x_getter}")
        msg = msg.format(object_type=object_type, x_getter=x_getter)
        raise OTPmeException(msg)
    rel_path_getter[object_type] = getter

def register_oid_schema(object_type, full_schema, read_schema=None,
    valid_owners=None, name_regex=None, path_regex=None, oid_regex=None):
    """ Register OID schema used by OTPmeOid(). """
    global object_regex
    global full_oid_schema
    global read_oid_schema
    global valid_object_owners

    if object_type not in object_regex:
        object_regex[object_type] = {}

    if name_regex:
        if 'name' in object_regex[object_type]:
            msg = _("Name regex alreaddy registered: {object_type}: {name_regex}")
            msg = msg.format(object_type=object_type, name_regex=name_regex)
            raise OTPmeException(msg)
        object_regex[object_type]['name'] = name_regex

    if path_regex:
        if 'path' in object_regex[object_type]:
            msg = _("Path regex alreaddy registered: {object_type}: {path_regex}")
            msg = msg.format(object_type=object_type, path_regex=path_regex)
            raise OTPmeException(msg)
        object_regex[object_type]['path'] = path_regex

    if oid_regex:
        if 'oid' in object_regex[object_type]:
            msg = _("OID regex alreaddy registered: {object_type}: {oid_regex}")
            msg = msg.format(object_type=object_type, oid_regex=oid_regex)
            raise OTPmeException(msg)
        object_regex[object_type]['oid'] = oid_regex

    try:
        x_schema = full_oid_schema[object_type]
    except Exception:
        x_schema = None
    if x_schema:
        msg = _("Full OID schema already registered: {object_type}: {x_schema}")
        msg = msg.format(object_type=object_type, x_schema=x_schema)
        raise OTPmeException(msg)

    full_oid_schema[object_type] = full_schema

    if valid_owners:
        valid_object_owners[object_type] = valid_owners
    else:
        valid_object_owners[object_type] = []

    if not read_schema:
        return

    try:
        x_schema = read_oid_schema[object_type]
    except Exception:
        x_schema = None
    if x_schema:
        msg = _("Read OID schema already registered: {object_type}: {x_schema}")
        msg = msg.format(object_type=object_type, x_schema=x_schema)
        raise OTPmeException(msg)

    read_oid_schema[object_type] = read_schema

def get_object_type(object_id):
    """ Get object type from ID. """
    try:
        object_type = object_id.split("|")[0]
    except Exception as e:
        msg = _("Invalid OID: {object_id}: {e}")
        msg = msg.format(object_id=object_id, e=e)
        raise InvalidOID(msg) from e
    return object_type

def get_object_realm(object_id):
    """ Get object realm from ID. """
    try:
        object_realm = object_id.split("|")[1].split("/")[0]
    except Exception:
        raise InvalidOID() from None
    return object_realm

def get_object_site(object_id):
    object_type = get_object_type(object_id)
    try:
        getter = site_getter[object_type]
    except Exception:
        getter = default_site_getter
    return getter(object_id)

def default_site_getter(object_id):
    """ Get object site from ID. """
    object_site = None
    oid_parts = object_id.split("|")[1].split("/")
    if len(oid_parts) > 2:
        object_site = oid_parts[1]
    return object_site

def get_object_name(object_id):
    """ Get object name from ID """
    if not object_id:
        raise Exception(_("Got no object_id"))
    try:
        object_name = object_id.split("|")[1].split("/")[-1]
    except Exception:
        raise InvalidOID() from None
    return object_name

def get_object_unit(object_id):
    """ Get object unit from ID. """
    object_type = get_object_type(object_id)
    try:
        getter = unit_getter[object_type]
    except Exception:
        getter = default_unit_getter
    return getter(object_id)

def default_unit_getter(object_id):
    """ Get object unit from ID. """
    object_path = get_object_rel_path(object_id)
    if not object_path:
        return None
    if not "/" in object_path:
        return None
    object_unit = "/".join(object_path.split("/")[:-1])
    return object_unit

def get_object_path(object_id):
    """ Get object path from ID. """
    try:
        object_path = f"/{object_id.split('|')[1:][0]}"
    except Exception:
        raise InvalidOID() from None
    return object_path

def resolve_oid(object_id):
    """ Resolve read OID to full OID using index.. """
    object_type = get_object_type(object_id)
    try:
        resolver = oid_resolver[object_type]
    except Exception:
        resolver = default_oid_resolver
    full_oid = resolver(object_id)
    return full_oid

def get_object_rel_path(object_id):
    """ Get object relative path from ID. """
    object_type = get_object_type(object_id)
    try:
        getter = rel_path_getter[object_type]
    except Exception:
        return
    object_path = object_id.split("/")
    object_path = getter(object_id.split("/"))
    object_path = "/".join(object_path)
    return object_path

def default_oid_resolver(object_id):
    from otpme.lib.backend import search
    object_type = get_object_type(object_id)
    object_realm = get_object_realm(object_id)
    object_site = get_object_site(object_id)
    object_name = get_object_name(object_id)
    _full_oid_schema = list(full_oid_schema[object_type])
    attribute = _full_oid_schema[-1]
    result = search(object_type=object_type,
                    realm=object_realm,
                    site=object_site,
                    attribute=attribute,
                    value=object_name,
                    return_type="full_oid")
    if not result:
        msg = _("Object does not exist: {object_id}")
        msg = msg.format(object_id=object_id)
        raise UnknownObject(msg)
    full_oid = result[0]
    return full_oid

#def default_oid_resolver(object_id):
#    from otpme.lib.backend import search
#    object_type = get_object_type(object_id)
#    object_realm = get_object_realm(object_id)
#    object_site = get_object_site(object_id)
#    object_name = get_object_name(object_id)
#    return_attrs = ['unit']
#    _full_oid_schema = list(full_oid_schema[object_type])
#    attribute = _full_oid_schema[-1]
#    result = search(object_type=object_type,
#                        realm=object_realm,
#                        site=object_site,
#                        attribute=attribute,
#                        value=object_name,
#                        return_attributes=return_attrs)
#    if not result:
#        msg = _("Unable to resolve OID: {object_id}")
#        msg = msg.format(object_id=object_id)
#        raise OTPmeException(msg)
#    unit_uuid = result[0]
#    uuid_path = [unit_uuid]
#    return_attrs = ['unit', 'realm', 'site']
#    while True:
#        result = search(object_type="unit",
#                        attribute="uuid",
#                        value=unit_uuid,
#                        return_attributes=return_attrs)
#        try:
#            unit_uuid = result[unit_uuid]['unit'][0]
#        except:
#            unit_uuid = None
#        if not unit_uuid:
#            object_path = [config.realm, config.site]
#            for uuid in reversed(uuid_path):
#                result = search(object_type="unit",
#                                attribute="uuid",
#                                value=uuid,
#                                return_type="name")
#                unit_name = result[0]
#                object_path.append(unit_name)
#            object_path = "/".join(object_path)
#            object_path = f"/{object_path}/{object_name}"
#            object_oid = get(object_type=object_type, path=object_path)
#            return object_oid.full_oid
#        uuid_path.append(unit_uuid)

def resolve_path(object_path, object_type):
    """ Resolve object path. """
    if object_type not in config.tree_object_types:
        msg = _("Unknown object type: {object_type}")
        msg = msg.format(object_type=object_type)
        raise OTPmeException(msg)

    path_start = 0
    split_start = 0
    full_path = False
    if object_path.startswith("/"):
        full_path = True
        path_start = 2
        split_start = 1
    split_path = object_path[split_start:].split("/")

    object_realm = None
    object_site = None
    object_unit = None
    object_rel_path = None
    object_owner = None
    object_name = split_path[-1]

    # Get object site/realm.
    if full_path:
        object_realm = split_path[0]
        if object_type != "realm":
            object_site = split_path[1]
    else:
        if object_type != "realm":
            object_realm = config.realm
            if object_type != "site":
                object_site = config.site

    if "user" in valid_object_owners[object_type]:
        user_object = True
    else:
        user_object = False
    if user_object:
        object_parts = 2
    else:
        object_parts = 1

    if len(split_path[path_start:-object_parts]) > 0:
        object_unit = split_path[path_start:-object_parts]
        object_unit = "/".join(object_unit)
    else:
        object_rel_path = object_name

    if user_object:
        object_rel_path = split_path[-object_parts:]
        object_owner = object_rel_path[-object_parts]
        object_rel_path = "/".join(object_rel_path)
    else:
        if len(split_path[path_start:-object_parts]) > 0:
            object_rel_path = split_path[path_start:]
            object_rel_path = "/".join(object_rel_path)
        else:
            object_rel_path = object_name

    result = {
            'realm'     : object_realm,
            'site'      : object_site,
            'unit'      : object_unit,
            'rel_path'  : object_rel_path,
            'owner'     : object_owner,
            'name'      : object_name,
            }
    return result

def oid_to_fs_name(read_oid):
    """ Convert read OID to fs compatible name. """
    #fs_name = read_oid.replace("/", ":")
    #fs_name = fs_name.replace("|", ":")
    fs_name = stuff.gen_md5(read_oid)
    return fs_name

def check_name(object_type, object_name):
    try:
        checker = name_checker[object_type]
    except Exception:
        checker = default_name_checker
    return checker(object_type, object_name)

def default_name_checker(object_type, object_name):
    """ Make sure object name is in correct format. """
    if object_type not in config.tree_object_types:
        return True
    regex_string = object_regex[object_type]['name']
    regex = re.compile(f"^{regex_string}$")
    if regex.match(object_name):
        return True
    return False

def check_path(object_type, object_path):
    """ Make sure object path is in correct format. """
    if object_type not in config.tree_object_types:
        return True
    regex_string = object_regex[object_type]['path']
    regex = re.compile(f"^{regex_string}$")
    if regex.match(object_path):
        return True
    return False

def is_oid(object_id):
    """ Check if object ID is in correct format. """
    object_type = get_object_type(object_id)
    if object_type not in config.object_types:
        return False
    regex_string = object_regex[object_type]['oid']
    regex = re.compile(f"^{regex_string}$")
    if regex.match(object_id):
        return True
    return False

def get(object_id=None, **kwargs):
    """ Get OID object from string. """
    oid = OTPmeOid(object_id=object_id, **kwargs)
    return oid

@match_class_typing
class OTPmeOid(object):
    """ OTPme OID class. """
    def __init__(
        self,
        object_type: Union[str,None]=None,
        object_id: Union[str,None]=None,
        realm: Union[str,None]=None,
        path: Union[str,None]=None,
        resolve: bool=False,
        full: bool=False,
        verify: bool=False,
        **kwargs
        ):

        self.path = path
        self.realm = realm
        self.object_type = object_type

        self.site = None
        self.unit = None
        self.name= None
        self.rel_path = None

        self.read_oid = None
        self.full_oid = None
        self.need_full = full

        self.resolve = resolve

        if not object_type and not object_id:
            msg = _("Need <object_type> or <object_id>.")
            raise OTPmeException(msg)

        if path:
            if not isinstance(path, str):
                msg = _("<path> must be of type <str>.")
                raise OTPmeException(msg)
            if not path.startswith("/"):
                msg = _("<path> must be with leading slash.")
                raise OTPmeException(msg)

        if object_id:
            if not is_oid(object_id):
                msg = _("Invalid OID: {object_id}")
                msg = msg.format(object_id=object_id)
                raise OTPmeException(msg)
            self.decode_oid(object_id)
        else:
            if path:
                x = resolve_path(path, object_type=object_type)
                self.realm = x['realm']
                self.site = x['site']
                self.unit = x['unit']
                self.rel_path = x['rel_path']
                self.name = x['name']
            self.gen_oid(**kwargs)

        if object_type and not object_type in full_oid_schema:
            msg = _("Unknown object type: {object_type}")
            msg = msg.format(object_type=object_type)
            raise OTPmeException(msg)

        if self.object_type is None:
            msg = _("Need <object_type>.")
            raise OTPmeException(msg)

        if verify:
            self.verify()

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        """ Our hash, over the OID string.

        Over __str__(), so it is the hash of the full OID whenever we
        have one. That is what the rest of the tree needs: dicts and
        sets of OIDs are keyed by the full OID *string* and looked up
        with one of us -- the sync list is (backend.get_sync_list()
        keys by full_oid, sync1.get_object_command() asks
        "object_id not in self.sync_list"). Hashing anything else puts
        us in another bucket and the lookup silently misses.

        Note this is not consistent with __eq__() for one pair: an OID
        that carries only the read form and its resolved twin compare
        equal but hash differently. Both forms cannot hash alike and
        still match their own string. So do not mix a resolved and an
        unresolved OID of the same object as keys of the same dict --
        compare them with == instead.
        """
        return hash(self.__str__())

    def __str__(self):
        if self.full_oid:
            return self.full_oid
        if self.read_oid:
            return self.read_oid
        return "Empty OID."

    def __lt__(self, other):
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        return self.__str__() > other.__str__()

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)

    def __eq__(self, other):
        """ Do we name the same object as the given OID?

        The full OID is the exact one, but not every OID carries it: an
        OID built from a read OID has none. So we compare the full ones
        when both sides have them and fall back to the read OID, which
        names the same object without the site. That is safe here
        because names are realm wide, there are no two users of that
        name in different sites.

        Comparing __str__() instead, as we did, made a resolved and an
        unresolved OID of the same object come out unequal -- one is the
        full OID, the other the read OID.
        """
        other_full = getattr(other, "full_oid", None)
        other_read = getattr(other, "read_oid", None)
        if other_full is None and other_read is None:
            # Not an OID. Comparing against the OID string is done in a
            # few places, so that keeps working.
            if isinstance(other, str):
                return self.__str__() == other
            return NotImplemented
        if self.full_oid and other_full:
            return self.full_oid == other_full
        if self.read_oid and other_read:
            return self.read_oid == other_read
        return self.__str__() == str(other)

    def __ne__(self, other):
        # Out of __eq__(), so the two cannot say different things. The
        # version before this one compared a dict with itself and
        # therefore called every OID equal to every other.
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    @property
    def backend_object(self):
        """ Indicates that the object can be read from backend. """
        if self.object_type in config.backend_object_types:
            return True
        return False

    def replace(self, s, r):
        return self.__str__().replace(s, r)

    @property
    def dn(self):
        """ Object ldap DN. """
        from otpme.lib.extensions import utils
        if not self.full_oid:
            msg = _("Cannot build DN without full OID.")
            raise OTPmeException(msg)
        try:
            dn_attribute = config.dn_attributes[self.object_type]
        except Exception:
            return

        dn_attr = utils.get_dn_attribute(self.object_type, dn_attribute)
        if dn_attr:
            # Get DN attribute value
            dn_attr_val = getattr(self, dn_attr)
        else:
            # Realm, site and unit have no attribute mapping: the value
            # of their DN attribute is not taken from an attribute of
            # the object, it is made up. Kept in step with
            # gen_attribute_value() of the base extension.
            if self.object_type == "realm":
                dn_attr_val = self.name.split(".")[0]
            elif self.object_type in ("site", "unit"):
                dn_attr_val = self.name
            else:
                return
        if not dn_attr_val:
            return

        # Domain context.
        dc = None
        # Site OU.
        sou = None
        # Object OU's.
        ous = None

        if self.object_type == "realm":
            dc = re.sub(r'[\.]', ',dc=', ".".join(self.name.split(".")[1:]))
        else:
            dc = re.sub(r'[\.]', ',dc=', self.realm)
        dc = re.sub('^', 'dc=', dc)

        if self.object_type != "site" and self.site:
            sou = re.sub('^', 'ou=', self.site)
        if self.unit:
            ous = reversed(self.unit.split("/"))
            ous = "/".join(ous)
            ous = re.sub('[/]', ',ou=', ous)
            ous = re.sub('^', 'ou=', ous)

        dn = f"{dn_attribute}={dn_attr_val}"
        if ous:
            dn = f"{dn},{ous}"
        if sou:
            dn = f"{dn},{sou}"

        dn = f"{dn},{dc}"

        return dn

    def verify(self):
        """ Verify OID. """
        # Make sure we have a valid name.
        check_name(self.object_type, self.name)

        if self.full_oid:
            check_oid = self.full_oid
            check_path(self.object_type, self.path)
        else:
            check_oid = self.read_oid

        if not is_oid(check_oid):
            msg = _("Invalid OID: {check_oid}")
            msg = msg.format(check_oid=check_oid)
            raise OTPmeException(msg)

    def decode_oid(self, object_id: str):
        """ Decode object ID. """
        self.object_type = get_object_type(object_id)
        self.realm = get_object_realm(object_id)
        self.site = get_object_site(object_id)

        try:
            _full_oid_schema = list(full_oid_schema[self.object_type])
        except Exception:
            msg = _("Object type not registered: {self.object_type}")
            msg = msg.format(self=self)
            raise OTPmeException(msg) from None

        try:
            _read_oid_schema = list(read_oid_schema[self.object_type])
        except Exception:
            _read_oid_schema = None

        object_id_parts = object_id.split("|")[1].split("/")

        if len(object_id_parts) >= len(_full_oid_schema):
            is_read_oid = False
            oid_schema = list(_full_oid_schema)
        elif not self.resolve and (not _read_oid_schema or self.need_full):
            msg = _("OID too short: {object_id}")
            msg = msg.format(object_id=object_id)
            raise OTPmeException(msg)
        else:
            is_read_oid = True
            oid_schema = list(_read_oid_schema)
            if len(object_id_parts) <= len(oid_schema):
                for x in list(oid_schema):
                    if x.startswith("["):
                        oid_schema.remove(x)

        oid_pos = 0
        for attribute in oid_schema:
            oid_pos += 1
            if attribute == "realm":
                continue
            if attribute == "site":
                if "site" in oid_schema:
                    continue
            if len(object_id_parts) < len(oid_schema):
                msg = _("Invalid OID: {object_id}")
                msg = msg.format(object_id=object_id)
                raise OTPmeException(msg)
            value = object_id_parts[oid_pos-1]
            setattr(self, attribute, value)

        if self.object_type in config.tree_object_types:
            self.name = get_object_name(object_id)
            if not is_read_oid:
                self.unit = get_object_unit(object_id)
                self.path = get_object_path(object_id)
                self.rel_path = get_object_rel_path(object_id)

        # Generate OID.
        self.gen_oid()

    def gen_oid(self, **kwargs):
        """ Generate OID. """
        _full_oid_schema = list(full_oid_schema[self.object_type])
        try:
            _read_oid_schema = list(read_oid_schema[self.object_type])
        except Exception:
            _read_oid_schema = None

        read_oid_list = []
        full_oid_list = []
        is_read_oid = False
        attributes = dict(kwargs)
        for attribute in _full_oid_schema:
            if attribute in attributes:
                value = attributes[attribute]
                if value:
                    if attribute == "unit":
                        if value.startswith("/"):
                            value = "/".join(value.split("/")[3:])
                    if self.object_type == "unit":
                        if attribute == "rel_path":
                            if value.startswith("/"):
                                msg = _("Invalid <rel_path>: {value}")
                                msg = msg.format(value=value)
                                raise OTPmeException(msg)
                            x = value.split("/")
                            self.name = x[-1]
                            if len(x) > 1:
                                self.unit = "/".join(x[:-1])
                    setattr(self, attribute, value)
            else:
                try:
                    value = getattr(self, attribute)
                    attributes[attribute] = value
                except Exception:
                    value = None

            if value is None:
                is_read_oid = True
                if not _read_oid_schema or self.need_full:
                    if not self.resolve:
                        msg = _("{self.object_type} needs <{attribute}>.")
                        msg = msg.format(self=self, attribute=attribute)
                        raise OTPmeException(msg)

            if _read_oid_schema and value:
                add_value = False
                opt_attribute = f"[{attribute}]"
                if attribute in _read_oid_schema:
                    add_value = True
                if opt_attribute in _read_oid_schema:
                    add_value = True
                if is_read_oid and not add_value:
                    msg = _("Invalid attribute for read OID: {attribute}")
                    msg = msg.format(attribute=attribute)
                    raise OTPmeException(msg)
                if add_value:
                    read_oid_list.append(str(value))

            full_oid_list.append(str(value))

        if not _read_oid_schema:
            read_oid_list = full_oid_list

        # Check if got enough arguments to build the OID.
        if is_read_oid:
            check_schema = list(read_oid_schema[self.object_type])
            check_oid_list = read_oid_list
        else:
            check_schema = list(full_oid_schema[self.object_type])
            check_oid_list = full_oid_list

        is_len = len(check_oid_list)
        should_len = len(check_schema)
        if is_len != should_len:
            missing_args = []
            for x in check_schema:
                try:
                    x_val = attributes[x]
                except Exception:
                    x_val = None
                if not x_val:
                    missing_args.append(x)
            x = [f"<{x}>" for x in missing_args]
            x = " ".join(x)
            msg = _("Missing arguments: {x}")
            msg = msg.format(x=x)
            raise OTPmeException(msg)

        self.read_oid = f"{self.object_type}|{'/'.join(read_oid_list)}"

        if is_read_oid:
            if self.resolve:
                self.full_oid = resolve_oid(self.read_oid)
        else:
            self.full_oid = f"{self.object_type}|{'/'.join(full_oid_list)}"

        if self.full_oid and not self.realm:
            self.realm = get_object_realm(self.full_oid)

        if self.full_oid and not self.site:
            self.site = get_object_site(self.full_oid)

        if self.full_oid and not self.unit:
            self.unit = get_object_unit(self.full_oid)

        if self.full_oid and not self.path:
            self.path = get_object_path(self.full_oid)
            self.rel_path = get_object_rel_path(self.full_oid)
