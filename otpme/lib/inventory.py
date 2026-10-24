# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Showing and searching the inventory of hosts (otpme-inventory).

The system a host runs, its packages and its hardware are all in its
host_inventory object; confd on the host reports all of it (see
daemon/confd.py, confd/inventory.py and confd/hardware.py). This is the
side that reads them. Only hosts of our own site: the inventory of a
host is kept on the nodes of its site.

What a system offers -- the packages that can be installed on a host
that runs it -- is in an os_packages object per OS version and
architecture, which a reference host reports (see os_packages.py). It
belongs to no host, so who may read it follows the hosts: whoever may
read the inventory of a host that runs a system may read what that
system offers (system_visible()).

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
from otpme.lib.classes.data_objects.os_packages import get_os_packages
from otpme.lib.confd.inventory import compare_versions
from otpme.lib.confd.inventory import native_package_name

from otpme.lib.exceptions import *

logger = config.logger
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.host",
                "otpme.lib.classes.data_objects.os_packages",
                ]

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
                                            'otpme_version',
                                            'hardware', 'host',
                                            'upgradable'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'systems'   : {
            'default'    : {
                'exists'    : {
                    'job_type'          : 'thread',
                    },
                },
            },
    'available'   : {
            'default'    : {
                'exists'    : {
                    'oargs'             : ['package', 'os_version',
                                            'arch', 'host'],
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
    arch = "-"
    kernel = "-"
    reboot_required = "-"
    otpme_version = "-"
    if inventory:
        os_name = inventory.os or "-"
        os_version = inventory.os_version or "-"
        arch = inventory.arch or "-"
        kernel = inventory.kernel or "-"
        otpme_version = inventory.otpme_version or "-"
        # A no is an answer, so it is not "or '-'": that is for a host
        # that has not said anything.
        if inventory.reboot_required is not None:
            reboot_required = "yes" if inventory.reboot_required else "no"
    lines = [
            f"host: {host_object.name}",
            f"os: {os_name}",
            f"os_version: {os_version}",
            f"arch: {arch}",
            f"kernel: {kernel}",
            f"reboot_required: {reboot_required}",
            f"otpme_version: {otpme_version}",
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
    reboot_required=None, otpme_version=None, hardware=None, host=None,
    upgradable=None, _caller="API", callback=default_callback, **kwargs):
    """ The hosts that have a package, run a system version, a kernel
    or an OTPme version, wait for a reboot, or are built a certain way.

    <package> is a name ("openssl"), a name and a version
    ("openssl=3.0.15-1~deb12u1"), and either may have wildcards
    ("libreoffice*", "openssl=3.0.*").

    <kernel> is the kernel a host is running ("6.1.0-37-amd64"), with
    wildcards ("6.1.0-3*").

    <reboot_required> is a yes or nothing: the hosts that have to be
    rebooted to run what is installed on them.

    <otpme_version> is the OTPme version a host runs ("0.3.0a283"), with
    wildcards ("0.3.0a28*").

    <hardware> is "<field><op><value>": "serial=ABC123",
    "model=PowerEdge*", "memory<8G", "cpu_count>8". See
    parse_hardware_search().

    <host> limits all of it to one host, which is how the packages of
    one host are searched without listing them all.

    <upgradable> is a yes or nothing: the installed packages of which
    the system of the host offers a newer version, see
    search_upgradable(). <package> then says which packages.

    Whatever is given has to match, so they narrow each other down.
    """
    if not package and not os_version and not kernel \
    and not reboot_required and not otpme_version \
    and not hardware and not host and not upgradable:
        msg = _("Need a package, an OS version, a kernel, a reboot, an OTPme version, a hardware field or a host.")
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

    if otpme_version:
        version_inventories = backend.search(object_type="host_inventory",
                                            attribute="otpme_version",
                                            value=otpme_version,
                                            return_type="instance")
        version_uuids = {x.host_uuid for x in version_inventories}
        if host_uuids is None:
            host_uuids = version_uuids
        else:
            host_uuids &= version_uuids

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

    if upgradable:
        return search_upgradable(host_uuids, package=package,
                                callback=callback)

    if not package:
        return show_search_hosts(host_uuids,
                                os_version=os_version,
                                kernel=kernel,
                                otpme_version=otpme_version,
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

def split_package_pattern(package):
    """ "<name>=<version>" taken apart, each part a pattern. """
    if not package:
        return "*", "*"
    if "=" in package:
        name_pattern, version_pattern = package.split("=", 1)
        return name_pattern or "*", version_pattern or "*"
    return package, "*"

def first_value(value):
    """ One value out of what a search with return_attributes gives:
    a list for every attribute that is no base attribute. """
    if isinstance(value, list):
        if not value:
            return None
        return value[0]
    return value

def get_inventory_systems():
    """ {host_uuid: (os_version, arch)} of every inventory we keep.

    Out of the index alone: an inventory holds the packages of its
    host, and loading all of them to read two values would be the
    packages of every host. """
    result = backend.search(object_type="host_inventory",
                            attribute="host_uuid",
                            value="*",
                            return_attributes=["host_uuid",
                                                "os_version",
                                                "arch"])
    systems = {}
    for x_data in result.values():
        host_uuid = first_value(x_data.get('host_uuid'))
        if not host_uuid:
            continue
        os_version = first_value(x_data.get('os_version'))
        if not os_version:
            continue
        arch = first_value(x_data.get('arch'))
        systems[host_uuid] = (os_version, arch)
    return systems

def get_visible_systems(token=None):
    """ The systems the caller may see what they offer, and how many of
    their hosts the caller may see: {(os_version, arch): count}.

    A system is seen through its hosts: a token that may read the
    inventory of a host may read what the system of that host offers.
    The data belongs to no host, so no allow_inventory names it; this
    asks the one of every host that runs it. A host that did not say
    its architecture counts with None, see system_matches(). """
    visible = {}
    for host_uuid, system in get_inventory_systems().items():
        x_host = backend.get_object(uuid=host_uuid)
        if not x_host:
            continue
        if not inventory_read_allowed(x_host, token=token):
            continue
        visible[system] = visible.get(system, 0) + 1
    return visible

def system_matches(system, os_version, arch):
    """ Whether a system of a host is <os_version> and <arch>.

    A host that did not say its architecture runs code from before it
    was reported. Its system is taken for every architecture of its OS
    version: what it lacks is a name, not a reason to see less. """
    x_os_version, x_arch = system
    if x_os_version != os_version:
        return False
    if x_arch is None:
        return True
    return x_arch == arch

def system_visible(os_version, arch, visible_systems):
    """ Whether the caller may see what <os_version>/<arch> offers. """
    for x_system in visible_systems:
        if system_matches(x_system, os_version, arch):
            return True
    return False

def get_all_os_packages(os_version=None, arch=None):
    """ The os_packages objects we keep, of an OS version and an
    architecture (patterns) if given. """
    result = backend.search(object_type="os_packages",
                            attribute="os_version",
                            value=os_version or "*",
                            return_type="instance")
    os_packages_list = []
    for x in result:
        if os_version and not fnmatch.fnmatchcase(x.os_version, os_version):
            continue
        if arch and not fnmatch.fnmatchcase(x.arch, arch):
            continue
        os_packages_list.append(x)
    return sorted(os_packages_list, key=lambda x: (x.os_version, x.arch))

def show_systems(_caller="API", callback=default_callback, **kwargs):
    """ The systems our hosts run, and what we know they offer.

    One line per OS version and architecture: how many hosts run it,
    the reference host that reports what it offers, how many packages
    that is, and when it last reported. Only systems with a host the
    caller may see, and only those hosts are counted. """
    visible = get_visible_systems()
    os_packages_map = {}
    for x in get_all_os_packages():
        os_packages_map[(x.os_version, x.arch)] = x
    # A host that did not say its architecture is counted with every
    # system of its OS version that is known, or on its own where none
    # is.
    rows = {}
    for (os_version, arch), count in visible.items():
        if arch is None:
            matches = [x for x in os_packages_map if x[0] == os_version]
            if not matches:
                matches = [(os_version, None)]
        else:
            matches = [(os_version, arch)]
        for x_system in matches:
            rows[x_system] = rows.get(x_system, 0) + count
    lines = []
    for x_system in sorted(rows, key=lambda x: (x[0], x[1] or "")):
        os_version, arch = x_system
        line = f"{os_version} {arch or '-'} hosts={rows[x_system]}"
        x_packages = os_packages_map.get(x_system)
        reference_host = "-"
        packages_count = "-"
        last_report = "-"
        if x_packages:
            packages_count = str(len(x_packages.packages))
            if x_packages.reference_host:
                x_host = backend.get_object(uuid=x_packages.reference_host)
                reference_host = x_host.name if x_host else x_packages.reference_host
            if x_packages.last_report:
                last_report = time.strftime("%Y-%m-%d %H:%M",
                                time.localtime(x_packages.last_report))
        line = (f"{line} reference_host={reference_host}"
                f" packages={packages_count} last_report={last_report}")
        lines.append(line)
    if not lines:
        return callback.ok(_("No systems found."))
    return callback.ok("\n".join(lines))

def list_available(package=None, os_version=None, arch=None, host=None,
    _caller="API", callback=default_callback, **kwargs):
    """ The packages a system offers: what can be installed.

    <package> is a name or "<name>=<version>", with wildcards. With
    <host> the system is the one of that host, and each package says
    the version installed there, if it is. Else <os_version> and <arch>
    say which systems, with wildcards, and each line says its system.
    """
    if not package:
        msg = _("Need a package.")
        return callback.error(msg)
    name_pattern, version_pattern = split_package_pattern(package)
    installed = None
    if host:
        if os_version or arch:
            msg = _("--host takes the OS version and the architecture of the host.")
            return callback.error(msg)
        host_object = get_host(host, callback=callback)
        if not host_object:
            return host_object
        inventory = get_host_inventory(host_object.uuid)
        if not inventory or not inventory.os_version:
            msg = _("No inventory for host: {host}")
            msg = msg.format(host=host)
            return callback.error(msg)
        host_system = (inventory.os_version, inventory.arch)
        os_packages_list = [x for x in get_all_os_packages(inventory.os_version)
                            if system_matches(host_system, x.os_version, x.arch)]
        installed = {}
        for x_name, x_version in inventory.packages.items():
            x_name = native_package_name(x_name, inventory.arch)
            if x_name is None:
                continue
            installed[x_name] = x_version
    else:
        visible = get_visible_systems()
        os_packages_list = [x for x in get_all_os_packages(os_version, arch)
                            if system_visible(x.os_version, x.arch, visible)]
    if not os_packages_list:
        msg = _("No reference host reported the packages of this system.")
        return callback.error(msg)
    lines = []
    for x_packages in os_packages_list:
        packages = x_packages.packages
        for name in sorted(packages):
            if not fnmatch.fnmatchcase(name, name_pattern):
                continue
            version = packages[name]
            if not fnmatch.fnmatchcase(version, version_pattern):
                continue
            if installed is None:
                lines.append(f"{x_packages.os_version} {x_packages.arch} {name}={version}")
                continue
            line = f"{name}={version}"
            if name in installed:
                line = f"{line} installed={installed[name]}"
            lines.append(line)
    if not lines:
        return callback.ok(_("No packages."))
    return callback.ok("\n".join(lines))

def search_upgradable(host_uuids, package=None, callback=default_callback):
    """ The hosts with installed packages of which their system offers a
    newer version, one line per package: the host, the package, the
    version installed and the one offered.

    Against the os_packages of the system of each host. A host whose
    system no reference host reports is left out: we cannot say. So is
    a package the system does not offer, which came from elsewhere. """
    name_pattern, version_pattern = split_package_pattern(package)
    if package:
        # The hosts that have it at all, out of the index. With a "*"
        # behind the name: dpkg names some packages with their
        # architecture (libc6:amd64), and the name is matched without
        # it below.
        inventories = backend.search(object_type="host_inventory",
                                    attribute="package",
                                    value=f"{name_pattern}*={version_pattern}",
                                    return_type="instance")
    else:
        inventories = backend.search(object_type="host_inventory",
                                    attribute="host_uuid",
                                    value="*",
                                    return_type="instance")
    os_packages_cache = {}
    def get_offered(os_version, arch):
        key = (os_version, arch)
        if key in os_packages_cache:
            return os_packages_cache[key]
        offered = None
        if arch is None:
            # A host that did not say its architecture: when its OS
            # version is reported for one architecture only, that is
            # the one.
            matches = get_all_os_packages(os_version)
            matches = [x for x in matches if x.os_version == os_version]
            if len(matches) == 1:
                offered = matches[0].packages
        else:
            x_packages = get_os_packages(os_version, arch)
            if x_packages:
                offered = x_packages.packages
        os_packages_cache[key] = offered
        return offered
    lines = []
    for inventory in inventories:
        if host_uuids is not None and inventory.host_uuid not in host_uuids:
            continue
        if not inventory.os_version:
            continue
        x_host = backend.get_object(uuid=inventory.host_uuid)
        if not x_host:
            continue
        if not inventory_read_allowed(x_host):
            continue
        offered = get_offered(inventory.os_version, inventory.arch)
        if not offered:
            continue
        packages = inventory.packages
        for x_name in sorted(packages):
            installed_version = packages[x_name]
            name = native_package_name(x_name, inventory.arch)
            if name is None:
                continue
            if not fnmatch.fnmatchcase(name, name_pattern):
                continue
            if not fnmatch.fnmatchcase(installed_version, version_pattern):
                continue
            offered_version = offered.get(name)
            if offered_version is None:
                continue
            if compare_versions(offered_version, installed_version) <= 0:
                continue
            lines.append(f"{x_host.name} {name}={installed_version} -> {offered_version}")
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
    otpme_version=None, hardware_field=None, hardware_search=None,
    callback=default_callback):
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
        if os_version or kernel or otpme_version or hardware_field:
            inventory = get_host_inventory(x_host.uuid)
        if os_version:
            line = f"{line} {inventory and inventory.os_version or '-'}"
        if kernel:
            line = f"{line} {inventory and inventory.kernel or '-'}"
        if otpme_version:
            line = f"{line} {inventory and inventory.otpme_version or '-'}"
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
