# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Showing and searching the inventory of hosts (otpme-inventory).

The system a host runs is kept on the host object (os, os_version), its
packages and its hardware in its host_inventory object; confd on the
host reports all of it (see daemon/confd.py, confd/inventory.py and
confd/hardware.py). This is the side that reads them. Only hosts of our
own site: the inventory of a host is kept on the nodes of its site.

Reading the inventory of a host needs the token to be named in the
allow_inventory of that host -- see inventory_read_allowed(). A host the
caller may not see is left out of a search, the same way it would be if
it did not have the package.

Sizes are bytes in the index, so it can compare them, and are said as
"8.0G" here -- on the way out and on the way in, so that what is typed
looks like what is shown.
"""
import os
import time
import fnmatch

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.classes.otpme_object import token_role_list_allows
from otpme.lib.humanize.units import int2size
from otpme.lib.humanize.units import size2int
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.data_objects.host_inventory import get_host_inventory
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_INDEX_FIELDS
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_DISK_ATTRIBUTE
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_DISK_SIZE_ATTRIBUTE

from otpme.lib.exceptions import *

logger = config.logger
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.host"]

# What may be searched by, and how the value is read. A name here is
# the field without its "hw_" prefix, which is how it is shown.
HARDWARE_SEARCH_FIELDS = dict(HARDWARE_INDEX_FIELDS)
HARDWARE_SEARCH_FIELDS['disk'] = HARDWARE_DISK_ATTRIBUTE
HARDWARE_SEARCH_FIELDS['disk_size'] = HARDWARE_DISK_SIZE_ATTRIBUTE
# Dell writes the service tag into the system serial number, and every
# other vendor calls that field the serial. One value, two names for
# it, so that looking for the name on the sticker finds something.
HARDWARE_FIELD_ALIASES = {
                    'service_tag'   : "serial",
                    }
# The fields that are a number, and of those the ones that are a size.
# A size is typed and shown as "8G", a count as it is.
HARDWARE_INT_FIELDS = ["cpu_count", "memory", "disk_size"]
HARDWARE_SIZE_FIELDS = ["memory", "disk_size"]
HARDWARE_BOOL_FIELDS = ["virtual"]
# What counts as yes and as no for a field that is one or the other.
BOOL_VALUES = {
            'true'  : True,
            'yes'   : True,
            '1'     : True,
            'false' : False,
            'no'    : False,
            '0'     : False,
            }

commands = {
    'show'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['host'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'packages'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['host'],
                    'oargs'             : ['package_filter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'hardware'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['host'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'search'   : {
            'default'    : {
                'exists'    : {
                    'oargs'             : ['package', 'os_version',
                                            'hardware', 'host'],
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def register():
    register_commands("inventory", commands)

def inventory_read_allowed(host_object, token=None):
    """ Whether <token> may read the inventory of <host_object>.

    allow_inventory of the host, of its unit, of its site -- the most
    specific one wins, like every config parameter. It holds the UUIDs
    of tokens and of roles; a token counts as named when it is in a
    named role, however deep the role nesting goes. Unset means nobody.

    Nobody but an admin, that is: the admin token and the admin role
    pass without being named, which is the rule that already decides
    who is above an ACL (see otpme_acl.check_access()). Keeping one
    rule for that is worth more here than keeping none: reading an
    inventory takes nothing away, and an admin who is shut out would
    simply write themselves into the parameter.

    A site admin is not above a node, the same way they are not for an
    ACL on one, so for a node the admin role does not count -- only the
    realm admin, or being named.
    """
    if token is None:
        token = config.auth_token
    check_admin_role = host_object.type != "node"
    need_acls, access_granted = otpme_acl.check_access(
                                        auth_token=token,
                                        check_admin_role=check_admin_role)
    if not need_acls:
        return access_granted
    try:
        allowed = host_object.get_config_parameter("allow_inventory",
                                                apply_getter=False)
    except Exception:
        allowed = None
    return token_role_list_allows(allowed, token)

def get_host(host, callback=default_callback):
    """ A host or node of our site by its name, if the caller may see
    its inventory. """
    result = backend.search(object_types=["host", "node"],
                            attribute="name",
                            value=host,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    if not result:
        msg = _("Unknown host: {host}")
        msg = msg.format(host=host)
        return callback.error(msg)
    host_object = result[0]
    if not inventory_read_allowed(host_object):
        msg = _("Permission denied: {host}")
        msg = msg.format(host=host)
        return callback.error(msg, exception=PermissionDenied)
    return host_object

def resolve_hardware_field(name):
    """ The field a name means, whatever it is called. """
    name = str(name).strip().lower()
    name = HARDWARE_FIELD_ALIASES.get(name, name)
    if name not in HARDWARE_SEARCH_FIELDS:
        msg = _("Unknown hardware field: {name}")
        msg = msg.format(name=name)
        raise OTPmeException(msg)
    return name

def format_hardware_value(name, value):
    """ One hardware value, the way it is shown. """
    if name in HARDWARE_SIZE_FIELDS:
        try:
            return int2size(int(value))
        except (TypeError, ValueError):
            return str(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)

def parse_hardware_search(expression):
    """ What "--hardware" says, taken apart.

    Three ways to say it: "serial=ABC123" matches, with wildcards;
    "memory>8G" and "cpu_count<4" compare, as do ">=" and "<=". Only a
    field that is a number can be compared, and a size may be typed the
    way it is shown ("8G", "500G").

    The index compares one way only, strictly greater or strictly less
    (see index_search()). Every field that can be compared is a whole
    number -- bytes, or a count -- so ">= n" is asked as "> n-1" and
    "<= n" as "< n+1", which is the same question and not a near one.

    Returns the field, the index attribute, and one of a value, a
    lower bound or an upper bound.
    """
    operator = None
    # The two-character ones first: ">" is in ">=" as well.
    for x_operator in (">=", "<=", ">", "<", "="):
        if x_operator in expression:
            operator = x_operator
            break
    if operator is None:
        msg = _("Invalid hardware search: {expression}")
        msg = msg.format(expression=expression)
        raise OTPmeException(msg)
    name, value = expression.split(operator, 1)
    name = resolve_hardware_field(name)
    attribute = HARDWARE_SEARCH_FIELDS[name]
    value = value.strip()
    if not value:
        msg = _("Missing value: {expression}")
        msg = msg.format(expression=expression)
        raise OTPmeException(msg)
    if operator != "=":
        if name not in HARDWARE_INT_FIELDS:
            msg = _("Field cannot be compared: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        if name in HARDWARE_SIZE_FIELDS:
            number = size2int(value)
        else:
            try:
                number = int(value)
            except ValueError:
                msg = _("Not a number: {value}")
                msg = msg.format(value=value)
                raise OTPmeException(msg) from None
        if operator == ">":
            return name, attribute, {'greater_than':number}
        if operator == "<":
            return name, attribute, {'less_than':number}
        if operator == ">=":
            return name, attribute, {'greater_than':number - 1}
        return name, attribute, {'less_than':number + 1}
    if name in HARDWARE_BOOL_FIELDS:
        try:
            return name, attribute, {'value':BOOL_VALUES[value.lower()]}
        except KeyError:
            msg = _("Not a yes or no: {value}")
            msg = msg.format(value=value)
            raise OTPmeException(msg) from None
    if name in HARDWARE_SIZE_FIELDS and "*" not in value:
        return name, attribute, {'value':size2int(value)}
    if name in HARDWARE_INT_FIELDS and "*" not in value:
        try:
            return name, attribute, {'value':int(value)}
        except ValueError:
            msg = _("Not a number: {value}")
            msg = msg.format(value=value)
            raise OTPmeException(msg) from None
    if name == "disk":
        # A disk is in the index as "<name>=<size>", the way a package
        # is "<name>=<version>". What is typed is the name, so what is
        # matched is the name and any size.
        return name, attribute, {'value':f"{value}=*"}
    return name, attribute, {'value':value}

def show_inventory(host, _caller="API", callback=default_callback, **kwargs):
    """ The system of a host, and how many packages it has. """
    host_object = get_host(host, callback=callback)
    if not host_object:
        return host_object
    inventory = get_host_inventory(host_object.uuid)
    packages = "-"
    last_update = "-"
    hardware = {}
    if inventory:
        packages = str(len(inventory.packages))
        hardware = inventory.hardware or {}
        if inventory.last_inventory_update:
            last_update = time.strftime("%Y-%m-%d %H:%M",
                            time.localtime(inventory.last_inventory_update))
    lines = [
            f"host: {host_object.name}",
            f"os: {host_object.os or '-'}",
            f"os_version: {host_object.os_version or '-'}",
            f"packages: {packages}",
            ]
    # The three that say which machine this is. The rest of the
    # hardware has its own command.
    for x_name in ("vendor", "model", "serial"):
        x_value = hardware.get(x_name)
        if x_value is None:
            continue
        lines.append(f"{x_name}: {format_hardware_value(x_name, x_value)}")
    lines.append(f"last_update: {last_update}")
    return callback.ok("\n".join(lines))

def show_hardware(host, _caller="API", callback=default_callback, **kwargs):
    """ What a host is made of. """
    host_object = get_host(host, callback=callback)
    if not host_object:
        return host_object
    inventory = get_host_inventory(host_object.uuid)
    hardware = {}
    if inventory:
        hardware = inventory.hardware or {}
    if not hardware:
        msg = _("No hardware inventory for host: {host}")
        msg = msg.format(host=host)
        return callback.error(msg)
    lines = []
    for x_name in sorted(hardware):
        if x_name == "disks":
            continue
        lines.append(f"{x_name}: {format_hardware_value(x_name, hardware[x_name])}")
    for disk in hardware.get("disks") or []:
        disk_line = f"disk: {disk.get('name')} {int2size(disk.get('size', 0))}"
        disk_model = disk.get("model")
        if disk_model:
            disk_line = f"{disk_line} {disk_model}"
        lines.append(disk_line)
    return callback.ok("\n".join(lines))

def list_packages(host, package_filter=None, _caller="API",
    callback=default_callback, **kwargs):
    """ The packages of a host, one per line: name and version. """
    host_object = get_host(host, callback=callback)
    if not host_object:
        return host_object
    inventory = get_host_inventory(host_object.uuid)
    if not inventory:
        msg = _("No inventory for host: {host}")
        msg = msg.format(host=host)
        return callback.error(msg)
    packages = inventory.packages
    lines = []
    for name in sorted(packages):
        if package_filter and not fnmatch.fnmatch(name, package_filter):
            continue
        lines.append(f"{name} {packages[name]}")
    if not lines:
        return callback.ok(_("No packages."))
    return callback.ok("\n".join(lines))

def search_inventory(package=None, os_version=None, hardware=None,
    host=None, _caller="API", callback=default_callback, **kwargs):
    """ The hosts that have a package, run a system version, or are
    built a certain way.

    <package> is a name ("openssl"), a name and a version
    ("openssl=3.0.15-1~deb12u1"), and either may have wildcards
    ("libreoffice*", "openssl=3.0.*").

    <hardware> is "<field><op><value>": "serial=ABC123",
    "model=PowerEdge*", "memory<8G", "cpu_count>8". See
    parse_hardware_search().

    <host> limits all of it to one host, which is how the packages of
    one host are searched without listing them all.

    Whatever is given has to match, so they narrow each other down.
    """
    if not package and not os_version and not hardware and not host:
        msg = _("Need a package, an OS version, a hardware field or a host.")
        return callback.error(msg)
    # The hosts still in the running. None means every host of our
    # site; each of the filters below takes hosts out of it.
    host_uuids = None

    if host:
        host_object = get_host(host, callback=callback)
        if not host_object:
            return host_object
        host_uuids = {host_object.uuid}

    if os_version:
        os_uuids = set()
        result = backend.search(object_types=["host", "node"],
                                attribute="os_version",
                                value=os_version,
                                realm=config.realm,
                                site=config.site,
                                return_type="uuid")
        os_uuids.update(result)
        if host_uuids is None:
            host_uuids = os_uuids
        else:
            host_uuids &= os_uuids

    if hardware:
        try:
            hw_name, hw_attribute, hw_search = parse_hardware_search(hardware)
        except OTPmeException as e:
            return callback.error(str(e))
        # Only inventories of our own site are kept here, see
        # host_inventory.py.
        hw_inventories = backend.search(object_type="host_inventory",
                                        attribute=hw_attribute,
                                        return_type="instance",
                                        **hw_search)
        hw_uuids = {x.host_uuid for x in hw_inventories}
        if host_uuids is None:
            host_uuids = hw_uuids
        else:
            host_uuids &= hw_uuids

    if not package:
        return show_search_hosts(host_uuids,
                                os_version=os_version,
                                hardware_field=hardware and hw_name,
                                hardware_search=hardware and hw_search,
                                callback=callback)

    # Hosts by package: in the inventories.
    name_pattern = package
    version_pattern = "*"
    if "=" in package:
        name_pattern, version_pattern = package.split("=", 1)
    search_value = f"{name_pattern}={version_pattern}"
    inventories = backend.search(object_type="host_inventory",
                                attribute="package",
                                value=search_value,
                                return_type="instance")
    lines = []
    for inventory in inventories:
        if host_uuids is not None and inventory.host_uuid not in host_uuids:
            continue
        x_host = backend.get_object(uuid=inventory.host_uuid)
        if not x_host:
            continue
        if not inventory_read_allowed(x_host):
            continue
        packages = inventory.packages
        # The index search is a LIKE, where "_" matches any character;
        # what is shown matches the pattern exactly.
        for name in sorted(packages):
            if not fnmatch.fnmatchcase(name, name_pattern):
                continue
            if not fnmatch.fnmatchcase(packages[name], version_pattern):
                continue
            lines.append(f"{x_host.name} {name}={packages[name]}")
    if not lines:
        return callback.ok(_("No hosts found."))
    return callback.ok("\n".join(sorted(lines)))

def hardware_value_matches(value, search):
    """ Whether one value is what the search asked for.

    The same question the index answered, asked again here -- the index
    says which hosts match, this says which of a host's disks did.
    """
    if 'greater_than' in search:
        try:
            return int(value) > search['greater_than']
        except (TypeError, ValueError):
            return False
    if 'less_than' in search:
        try:
            return int(value) < search['less_than']
        except (TypeError, ValueError):
            return False
    wanted = search.get('value')
    if isinstance(wanted, str):
        return fnmatch.fnmatchcase(str(value), wanted)
    return value == wanted

def show_search_hosts(host_uuids, os_version=None, hardware_field=None,
    hardware_search=None, callback=default_callback):
    """ The hosts a search without a package found.

    Each line says the host and what it was found by, so that a search
    for a serial number shows the serial and not just the name.

    Of a field a host has several of -- its disks -- only the ones that
    match are shown, with their name. Listing all of them would leave
    the reader to work out which one answered the question, and next to
    "disk_size>=100G" a line saying "32.0G,150.0G,738.0M" reads like a
    mistake.
    """
    if hardware_search is None:
        hardware_search = {}
    lines = []
    for host_uuid in host_uuids or []:
        x_host = backend.get_object(uuid=host_uuid)
        if not x_host:
            continue
        if not inventory_read_allowed(x_host):
            continue
        line = x_host.name
        if os_version:
            line = f"{line} {x_host.os_version}"
        if hardware_field:
            inventory = get_host_inventory(x_host.uuid)
            x_hardware = {}
            if inventory:
                x_hardware = inventory.hardware or {}
            if hardware_field in ("disk", "disk_size"):
                disks = []
                for x_disk in x_hardware.get("disks") or []:
                    if hardware_field == "disk_size":
                        x_value = x_disk.get("size", 0)
                    else:
                        # The same string the index holds and the
                        # search was built against, see
                        # parse_hardware_search().
                        x_value = "{name}={size}".format(
                                            name=x_disk.get("name"),
                                            size=x_disk.get("size", 0))
                    if not hardware_value_matches(x_value, hardware_search):
                        continue
                    x_name = x_disk.get("name")
                    x_size = int2size(x_disk.get("size", 0))
                    disks.append(f"{x_name}={x_size}")
                line = f"{line} {','.join(disks) or '-'}"
            else:
                x_value = x_hardware.get(hardware_field)
                if x_value is None:
                    line = f"{line} -"
                else:
                    line = f"{line} {format_hardware_value(hardware_field, x_value)}"
        lines.append(line)
    if not lines:
        return callback.ok(_("No hosts found."))
    return callback.ok("\n".join(sorted(lines)))
