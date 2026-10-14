# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Showing and searching the inventory of hosts (otpme-inventory).

The system a host runs, its packages and its hardware are all in its
host_inventory object; confd on the host reports all of it (see
daemon/confd.py, confd/inventory.py and confd/hardware.py). This is the
side that reads them. Only hosts of our own site: the inventory of a
host is kept on the nodes of its site.

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
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_DISK_SERIAL_ATTRIBUTE
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_DISK_VENDOR_ATTRIBUTE
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_DISK_MODEL_ATTRIBUTE
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_CONTROLLER_ATTRIBUTE
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_CONTROLLER_FIELDS
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_NIC_ATTRIBUTE
from otpme.lib.classes.data_objects.host_inventory import HARDWARE_NIC_FIELDS

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
HARDWARE_SEARCH_FIELDS['disk_serial'] = HARDWARE_DISK_SERIAL_ATTRIBUTE
HARDWARE_SEARCH_FIELDS['disk_vendor'] = HARDWARE_DISK_VENDOR_ATTRIBUTE
HARDWARE_SEARCH_FIELDS['disk_model'] = HARDWARE_DISK_MODEL_ATTRIBUTE
HARDWARE_SEARCH_FIELDS['controller'] = HARDWARE_CONTROLLER_ATTRIBUTE
HARDWARE_SEARCH_FIELDS['nic'] = HARDWARE_NIC_ATTRIBUTE
# The fields a host has several of, one per disk. A search by one of
# them finds the host through the index and then says which of its
# disks answered, see show_search_hosts().
HARDWARE_DISK_SEARCH_FIELDS = {
                    'disk'          : None,
                    'disk_size'     : "size",
                    'disk_serial'   : "serial",
                    'disk_vendor'   : "vendor",
                    'disk_model'    : "model",
                    }
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
                                            'kernel', 'reboot_required',
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

    A host of another site that reports here (inventory_site) brings
    its allow_inventory with it, at the host, its unit and its site of
    origin. Whoever runs a central inventory can take that decision
    over with allow_foreign_inventory on this site, which is asked
    first and, where it is unset, leaves the host's own in charge. Both
    are wanted: one where the site that keeps the data says who reads
    it, one where the site the data is about keeps saying.

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
    allowed = None
    if host_object.site != config.site or host_object.realm != config.realm:
        # A host of another site that reports here (inventory_site).
        # Our own say about data that is not ours comes first, and
        # where we have not said anything the host brings its own with
        # it, as below.
        allowed = read_config_parameter(get_own_site(),
                                        "allow_foreign_inventory")
    if not allowed:
        allowed = read_config_parameter(host_object, "allow_inventory")
    return token_role_list_allows(allowed, token)

def get_own_site():
    """ The site object of this site, or None. """
    if not config.site_uuid:
        return None
    return backend.get_object(object_type="site", uuid=config.site_uuid)

def read_config_parameter(config_object, name):
    """ One config parameter as it is stored, or None.

    Not as the getter shows it: these hold token and role UUIDs, and
    the getter turns them into paths that would have to be turned back.
    """
    if not config_object:
        return None
    try:
        return config_object.get_config_parameter(name, apply_getter=False)
    except Exception:
        return None

def get_host(host, callback=default_callback):
    """ A host or node by its name, if the caller may see its inventory.

    Of any site of our realm, not only of ours: a host may report its
    inventory to another site (inventory_site), and then that site is
    the one that answers for it. What we have an inventory of is what
    we can say something about, whoever the host belongs to.

    A host name is unique within its site and not within the realm, so
    the first of two is taken -- as everywhere else a host is named
    without saying where it is.
    """
    result = backend.search(object_types=["host", "node"],
                            attribute="name",
                            value=host,
                            realm=config.realm,
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

def format_disk_name(disk):
    """ A disk as "<name>=<size>". """
    name = disk.get("name")
    size = int2size(disk.get("size", 0))
    return f"{name}={size}"

def format_controller(controller, hardware):
    """ One controller, and the disks that hang on it.

    Called by the name on the card where the host could read one, else
    by the chip, else by its PCI address. The disks by name and size:
    the question a controller is searched for is which disks are on it,
    and what each of them is beside that has its own field.
    """
    name = controller.get("model") \
            or controller.get("chip") \
            or controller.get("address")
    disks = []
    for x_disk in hardware.get("disks") or []:
        if x_disk.get("controller") != controller.get("address"):
            continue
        disks.append(format_disk_name(x_disk))
    disks = ",".join(disks) or "-"
    return f"{name}({disks})"

def device_matches(device, fields, search):
    """ Whether a device is one the search asked for.

    Against every name it has, which are the ones the index holds, so
    the answer here and the hosts the index found agree.
    """
    for name in fields:
        value = device.get(name)
        if value is None:
            continue
        if hardware_value_matches(value, search):
            return True
    return False

def format_nic(nic):
    """ One network card, the way a search result names it.

    The name the kernel gave it and its MAC, and behind them what the
    card is. The MAC is the answer to the question a card is usually
    searched for: which host has this one.
    """
    name = nic.get("name")
    mac = nic.get("mac") or "-"
    known = [x for x in (nic.get("vendor"),
                        nic.get("model"),
                        nic.get("chip")) if x]
    if not known:
        return f"{name}={mac}"
    known = " ".join(known)
    return f"{name}={mac}({known})"

def format_disk(disk):
    """ One disk, the way a search result names it.

    Name and size, and behind them what says which disk this is: the
    vendor, the model and the serial, where the host reported them. A
    search for "disk_size>=10G" is asked to find a disk, so the answer
    has to be enough to go and find it in the rack. The same three the
    hardware of a host shows, in the same order, so a line here and a
    line there read alike.
    """
    disk_name = format_disk_name(disk)
    known = [x for x in (disk.get("vendor"),
                        disk.get("model"),
                        disk.get("serial")) if x]
    if not known:
        return disk_name
    known = " ".join(known)
    return f"{disk_name}({known})"

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
    os_name = "-"
    os_version = "-"
    kernel = "-"
    reboot_required = "-"
    if inventory:
        os_name = inventory.os or "-"
        os_version = inventory.os_version or "-"
        kernel = inventory.kernel or "-"
        # A no is an answer, so it is not "or '-'": that is for a host
        # that has not said anything.
        if inventory.reboot_required is not None:
            reboot_required = "yes" if inventory.reboot_required else "no"
    lines = [
            f"host: {host_object.name}",
            f"os: {os_name}",
            f"os_version: {os_version}",
            f"kernel: {kernel}",
            f"reboot_required: {reboot_required}",
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
        if x_name in ("disks", "controllers", "nics"):
            continue
        lines.append(f"{x_name}: {format_hardware_value(x_name, hardware[x_name])}")
    for controller in hardware.get("controllers") or []:
        controller_line = f"controller: {controller.get('address')}"
        for x_key in ("vendor", "model", "chip"):
            x_value = controller.get(x_key)
            if x_value:
                controller_line = f"{controller_line} {x_value}"
        # Named, because none of these says what it is by itself.
        for x_key in ("vendor_id", "device_id", "subsystem_id", "driver"):
            x_value = controller.get(x_key)
            if x_value:
                controller_line = f"{controller_line} {x_key}={x_value}"
        lines.append(controller_line)
    for nic in hardware.get("nics") or []:
        nic_line = f"nic: {nic.get('name')} {nic.get('mac') or '-'}"
        for x_key in ("vendor", "model", "chip"):
            x_value = nic.get(x_key)
            if x_value:
                nic_line = f"{nic_line} {x_value}"
        for x_key in ("vendor_id", "device_id", "subsystem_id", "driver"):
            x_value = nic.get(x_key)
            if x_value:
                nic_line = f"{nic_line} {x_key}={x_value}"
        lines.append(nic_line)
    for disk in hardware.get("disks") or []:
        disk_line = f"disk: {disk.get('name')} {int2size(disk.get('size', 0))}"
        for x_key in ("vendor", "model"):
            x_value = disk.get(x_key)
            if x_value:
                disk_line = f"{disk_line} {x_value}"
        # Named, because a serial and a PCI address say nothing about
        # themselves the way a model does.
        for x_key in ("serial", "controller"):
            x_value = disk.get(x_key)
            if x_value:
                disk_line = f"{disk_line} {x_key}={x_value}"
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

def search_inventory(package=None, os_version=None, kernel=None,
    reboot_required=None, hardware=None, host=None, _caller="API",
    callback=default_callback, **kwargs):
    """ The hosts that have a package, run a system version or a
    kernel, wait for a reboot, or are built a certain way.

    <package> is a name ("openssl"), a name and a version
    ("openssl=3.0.15-1~deb12u1"), and either may have wildcards
    ("libreoffice*", "openssl=3.0.*").

    <kernel> is the kernel a host is running ("6.1.0-37-amd64"), with
    wildcards ("6.1.0-3*").

    <reboot_required> is a yes or nothing: the hosts that have to be
    rebooted to run what is installed on them.

    <hardware> is "<field><op><value>": "serial=ABC123",
    "model=PowerEdge*", "memory<8G", "cpu_count>8". See
    parse_hardware_search().

    <host> limits all of it to one host, which is how the packages of
    one host are searched without listing them all.

    Whatever is given has to match, so they narrow each other down.
    """
    if not package and not os_version and not kernel \
    and not reboot_required and not hardware and not host:
        msg = _("Need a package, an OS version, a kernel, a reboot, a hardware field or a host.")
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
        # In the inventories, the same as the packages and the hardware:
        # that is where a host says what it runs.
        os_inventories = backend.search(object_type="host_inventory",
                                        attribute="os_version",
                                        value=os_version,
                                        return_type="instance")
        os_uuids = {x.host_uuid for x in os_inventories}
        if host_uuids is None:
            host_uuids = os_uuids
        else:
            host_uuids &= os_uuids

    if kernel:
        kernel_inventories = backend.search(object_type="host_inventory",
                                            attribute="kernel",
                                            value=kernel,
                                            return_type="instance")
        kernel_uuids = {x.host_uuid for x in kernel_inventories}
        if host_uuids is None:
            host_uuids = kernel_uuids
        else:
            host_uuids &= kernel_uuids

    if reboot_required:
        # A yes and nothing else. The hosts that answered no are the
        # ones that are as they should be, and nobody looks for those;
        # a host that cannot say has no value here and is left out, the
        # same as one that never reported.
        reboot_inventories = backend.search(object_type="host_inventory",
                                            attribute="reboot_required",
                                            value=True,
                                            return_type="instance")
        reboot_uuids = {x.host_uuid for x in reboot_inventories}
        if host_uuids is None:
            host_uuids = reboot_uuids
        else:
            host_uuids &= reboot_uuids

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
                                kernel=kernel,
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

def show_search_hosts(host_uuids, os_version=None, kernel=None,
    hardware_field=None, hardware_search=None, callback=default_callback):
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
        inventory = None
        if os_version or kernel or hardware_field:
            inventory = get_host_inventory(x_host.uuid)
        if os_version:
            line = f"{line} {inventory and inventory.os_version or '-'}"
        if kernel:
            line = f"{line} {inventory and inventory.kernel or '-'}"
        if hardware_field:
            x_hardware = {}
            if inventory:
                x_hardware = inventory.hardware or {}
            if hardware_field == "controller":
                # A controller is asked for to get at the disks on it,
                # so that is what the answer is.
                found = []
                for x_controller in x_hardware.get("controllers") or []:
                    if not device_matches(x_controller,
                                        HARDWARE_CONTROLLER_FIELDS,
                                        hardware_search):
                        continue
                    found.append(format_controller(x_controller, x_hardware))
                line = f"{line} {' '.join(found) or '-'}"
            elif hardware_field == "nic":
                found = []
                for x_nic in x_hardware.get("nics") or []:
                    if not device_matches(x_nic, HARDWARE_NIC_FIELDS,
                                        hardware_search):
                        continue
                    found.append(format_nic(x_nic))
                line = f"{line} {','.join(found) or '-'}"
            elif hardware_field in HARDWARE_DISK_SEARCH_FIELDS:
                disk_key = HARDWARE_DISK_SEARCH_FIELDS[hardware_field]
                disks = []
                for x_disk in x_hardware.get("disks") or []:
                    if disk_key is None:
                        # The same string the index holds and the
                        # search was built against, see
                        # parse_hardware_search().
                        x_value = "{name}={size}".format(
                                            name=x_disk.get("name"),
                                            size=x_disk.get("size", 0))
                    else:
                        x_value = x_disk.get(disk_key)
                        if x_value is None:
                            continue
                    if not hardware_value_matches(x_value, hardware_search):
                        continue
                    disks.append(format_disk(x_disk))
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
