# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import config

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
uuid_re = '[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z'

def register_site_getter(object_type, getter):
    """ Register function to get site of object. """
    global site_getter
    try:
        x_getter = site_getter[object_type]
    except:
        x_getter = None
    if x_getter:
        msg = ("Site getter already registered: %s: %s"
                % (object_type, x_getter))
        raise OTPmeException(msg)
    site_getter[object_type] = getter

def register_unit_getter(object_type, getter):
    """ Register function to get unit of object. """
    global unit_getter
    try:
        x_getter = unit_getter[object_type]
    except:
        x_getter = None
    if x_getter:
        msg = ("Unit getter already registered: %s: %s"
                % (object_type, x_getter))
        raise OTPmeException(msg)
    unit_getter[object_type] = getter

def register_name_checker(object_type, getter):
    """ Register function to check name of object. """
    global name_checker
    try:
        x_checker = name_checker[object_type]
    except:
        x_checker = None
    if  x_checker:
        msg = ("Name checker already registered: %s: %s"
                % (object_type, x_checker))
        raise OTPmeException(msg)
    name_checker[object_type] = getter

def register_oid_resolver(object_type, resolver):
    """ Register function to resolve read OID to full OID. """
    global oid_resolver
    try:
        x_resolver = oid_resolver[object_type]
    except:
        x_resolver = None
    if x_resolver:
        msg = ("Resolver already registered: %s: %s"
                % (object_type, x_resolver))
        raise OTPmeException(msg)
    oid_resolver[object_type] = resolver

def register_rel_path_getter(object_type, getter):
    """ Register function to get rel path of object. """
    global rel_path_getter
    try:
        x_getter = rel_path_getter[object_type]
    except:
        x_getter = None
    if x_getter:
        msg = ("Relpath getter already registered: %s: %s"
                % (object_type, x_getter))
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
            msg = ("Name regex alreaddy registered: %s: %s"
                    % (object_type, name_regex))
            raise OTPmeException(msg)
        object_regex[object_type]['name'] = name_regex

    if path_regex:
        if 'path' in object_regex[object_type]:
            msg = ("Path regex alreaddy registered: %s: %s"
                    % (object_type, path_regex))
            raise OTPmeException(msg)
        object_regex[object_type]['path'] = path_regex

    if oid_regex:
        if 'oid' in object_regex[object_type]:
            msg = ("OID regex alreaddy registered: %s: %s"
                    % (object_type, oid_regex))
            raise OTPmeException(msg)
        object_regex[object_type]['oid'] = oid_regex

    try:
        x_schema = full_oid_schema[object_type]
    except:
        x_schema = None
    if x_schema:
        msg = ("Full OID schema already registered: %s: %s"
                % (object_type, x_schema))
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
    except:
        x_schema = None
    if x_schema:
        msg = ("Read OID schema already registered: %s: %s"
                % (object_type, x_schema))
        raise OTPmeException(msg)

    read_oid_schema[object_type] = read_schema

def get_object_type(object_id):
    """ Get object type from ID. """
    try:
        object_type = object_id.split("|")[0]
    except:
        raise InvalidOID()
    return object_type

def get_object_realm(object_id):
    """ Get object realm from ID. """
    try:
        object_realm = object_id.split("|")[1].split("/")[0]
    except:
        raise InvalidOID()
    return object_realm

def get_object_site(object_id):
    object_type = get_object_type(object_id)
    try:
        getter = site_getter[object_type]
    except:
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
        raise Exception("Got no object_id")
    try:
        object_name = object_id.split("|")[1].split("/")[-1]
    except:
        raise InvalidOID()
    return object_name

def get_object_unit(object_id):
    """ Get object unit from ID. """
    object_type = get_object_type(object_id)
    try:
        getter = unit_getter[object_type]
    except:
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
        object_path = "/%s" % object_id.split("|")[1:][0]
    except:
        raise InvalidOID()
    return object_path

def resolve_oid(object_id):
    """ Resolve read OID to full OID using index.. """
    object_type = get_object_type(object_id)
    try:
        resolver = oid_resolver[object_type]
    except:
        resolver = default_oid_resolver
    full_oid = resolver(object_id)
    return full_oid

def get_object_rel_path(object_id):
    """ Get object relative path from ID. """
    object_type = get_object_type(object_id)
    try:
        getter = rel_path_getter[object_type]
    except:
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
        msg = ("Object does not exist: %s" % object_id)
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
#        msg = "Unable to resolve OID: %s" % object_id
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
#            object_path = "/%s/%s" % (object_path, object_name)
#            object_oid = get(object_type=object_type, path=object_path)
#            return object_oid.full_oid
#        uuid_path.append(unit_uuid)

def resolve_path(object_path, object_type):
    """ Resolve object path. """
    if object_type not in config.tree_object_types:
        msg = "Unknown object type: %s" % object_type
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
    except:
        checker = default_name_checker
    return checker(object_type, object_name)

def default_name_checker(object_type, object_name):
    """ Make sure object name is in correct format. """
    if object_type not in config.tree_object_types:
        return True
    regex_string = object_regex[object_type]['name']
    regex = re.compile("^%s$" % regex_string)
    if regex.match(object_name):
        return True
    return False

def check_path(object_type, object_path):
    """ Make sure object path is in correct format. """
    if object_type not in config.tree_object_types:
        return True
    regex_string = object_regex[object_type]['path']
    regex = re.compile("^%s$" % regex_string)
    if regex.match(object_path):
        return True
    return False

def is_oid(object_id):
    """ Check if object ID is in correct format. """
    object_type = get_object_type(object_id)
    if not object_type in config.object_types:
        return False
    regex_string = object_regex[object_type]['oid']
    regex = re.compile("^%s$" % regex_string)
    if regex.match(object_id):
        return True
    return False

def get(object_id=None, **kwargs):
    """ Get OID object from string. """
    oid = OTPmeOid(object_id=object_id, **kwargs)
    return oid

class OTPmeOid(object):
    """ OTPme OID class. """
    def __init__(self, object_type=None, object_id=None,
        realm=None, path=None, resolve=False, full=False,
        verify=False, **kwargs):

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
            msg = ("Need <object_type> or <object_id>.")
            raise OTPmeException(msg)

        if path:
            if not isinstance(path, str):
                msg = ("<path> must be of type <str>.")
                raise OTPmeException(msg)
            if not path.startswith("/"):
                msg = ("<path> must be with leading slash.")
                raise OTPmeException(msg)

        if object_id:
            if not is_oid(object_id):
                msg = ("Invalid OID: %s" % object_id)
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
            msg = ("Unknown object type: %s" % object_type)
            raise OTPmeException(msg)

        if self.object_type is None:
            msg = "Need <object_type>."
            raise OTPmeException(msg)

        if verify:
            self.verify()

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
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

    def __eq__(self, other):
        if hasattr(other, "__dict__"):
            own_dict = dict(self.__dict__)
            try:
                own_dict.pop('need_full')
            except KeyError:
                pass
            try:
                own_dict.pop('resolve')
            except KeyError:
                pass
            other_dict = dict(other.__dict__)
            try:
                other_dict.pop('need_full')
            except KeyError:
                pass
            try:
                other_dict.pop('resolve')
            except KeyError:
                pass
        return self.__str__() == other.__str__()

    def __ne__(self, other):
        if hasattr(other, "__dict__"):
            own_dict = dict(self.__dict__)
            own_dict.pop('need_full')
            own_dict.pop('resolve')
            other_dict = dict(other.__dict__)
            other_dict.pop('need_full')
            other_dict.pop('resolve')
            return own_dict != own_dict
        return self.__str__() != other.__str__()

    @property
    def backend_object(self):
        """ Indicates that the object can be read from backend. """
        if self.object_type in config.backend_object_types:
            return True
        return False

    def replace(self, s, r):
        return self.__str__().replace(s, r)

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
            msg = ("Invalid OID: %s" % check_oid)
            raise OTPmeException(msg)

    def decode_oid(self, object_id):
        """ Decode object ID. """
        self.object_type = get_object_type(object_id)
        self.realm = get_object_realm(object_id)
        self.site = get_object_site(object_id)

        try:
            _full_oid_schema = list(full_oid_schema[self.object_type])
        except:
            msg = "Object type not registered: %s" % self.object_type
            raise OTPmeException(msg)

        try:
            _read_oid_schema = list(read_oid_schema[self.object_type])
        except:
            _read_oid_schema = None

        object_id_parts = object_id.split("|")[1].split("/")

        if len(object_id_parts) >= len(_full_oid_schema):
            is_read_oid = False
            oid_schema = list(_full_oid_schema)
        elif not self.resolve and (not _read_oid_schema or self.need_full):
            msg = ("OID too short: %s" % object_id)
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
                msg = ("Invalid OID: %s" % object_id)
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
        except:
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
                                msg = "Invalid <rel_path>: %s" % value
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
                except:
                    value = None

            if value is None:
                is_read_oid = True
                if not _read_oid_schema or self.need_full:
                    if not self.resolve:
                        msg = ("%s needs <%s>." % (self.object_type, attribute))
                        raise OTPmeException(msg)

            if _read_oid_schema and value:
                add_value = False
                opt_attribute = "[%s]" % attribute
                if attribute in _read_oid_schema:
                    add_value = True
                if opt_attribute in _read_oid_schema:
                    add_value = True
                if is_read_oid and not add_value:
                    msg = ("Invalid attribute for read OID: %s" % attribute)
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
                except:
                    x_val = None
                if not x_val:
                    missing_args.append(x)
            x = ["<%s>" % x for x in missing_args]
            x = " ".join(x)
            msg = (_("Missing arguments: %s") % x)
            raise OTPmeException(msg)

        self.read_oid = "%s|%s" % (self.object_type, "/".join(read_oid_list))

        if is_read_oid:
            if self.resolve:
                self.full_oid = resolve_oid(self.read_oid)
        else:
            self.full_oid = "%s|%s" % (self.object_type, "/".join(full_oid_list))

        if self.full_oid and not self.realm:
            self.realm = get_object_realm(self.full_oid)

        if self.full_oid and not self.site:
            self.site = get_object_site(self.full_oid)

        if self.full_oid and not self.unit:
            self.unit = get_object_unit(self.full_oid)

        if self.full_oid and not self.path:
            self.path = get_object_path(self.full_oid)
            self.rel_path = get_object_rel_path(self.full_oid)
