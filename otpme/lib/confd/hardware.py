# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The hardware of a host: what it is made of.

confd on the host reads it, syncd on the nodes keeps it in the host's
inventory object next to its packages (see
classes/data_objects/host_inventory.py). Both sides need the same idea
of what a hardware inventory looks like and when two of them are the
same, and that is what this module is for.

Everything is read out of files -- /sys/class/dmi/id, /proc/cpuinfo,
/proc/meminfo, /sys/block -- so nothing has to be installed for it.
What a file does not say, or what may not be read, is left out rather
than guessed: a value that is not there is more use than one that is
wrong.

Sizes are bytes, as integers, so the index can compare them (see
lib/inventory.py, which turns them into "8.0G" on the way out and back
on the way in).
"""
import os
import re
import json
import hashlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib.exceptions import *

DMI_DIR = "/sys/class/dmi/id"
BLOCK_DIR = "/sys/block"
CPUINFO_FILE = "/proc/cpuinfo"
MEMINFO_FILE = "/proc/meminfo"
HYPERVISOR_TYPE_FILE = "/sys/hypervisor/type"

# The fields an inventory may carry, and which of them are numbers.
# Anything else a host sends is dropped rather than stored: the host
# says what it has, but only in the shape of an inventory.
STRING_FIELDS = [
                "vendor",
                "model",
                "serial",
                "asset_tag",
                "sku",
                "board_vendor",
                "board_model",
                "board_serial",
                "bios_vendor",
                "bios_version",
                "bios_date",
                "chassis_type",
                "cpu_model",
                "virt_type",
                ]
INT_FIELDS = [
            "cpu_count",
            "memory",
            ]
BOOL_FIELDS = [
            "virtual",
            ]
# One entry per disk: {'name':..., 'size':..., 'model':...}.
DISK_FIELDS = ["disks"]

VALUE_RE = r'^[\x20-\x7e]{1,128}$'
DISK_NAME_RE = r'^[a-zA-Z0-9._-]{1,32}$'
MAX_DISKS = 64
# A value that says nothing. DMI is full of them, and a serial of
# "To Be Filled By O.E.M." is worse than no serial at all: it would
# turn up in a search for every board of that vendor.
EMPTY_VALUES = [
            "",
            "none",
            "n/a",
            "na",
            "unknown",
            "default string",
            "not specified",
            "not available",
            "to be filled by o.e.m.",
            "system serial number",
            "system manufacturer",
            "system product name",
            "chassis serial number",
            "default",
            "0",
            "00000000",
            ]
# What DMI numbers mean for a chassis. The number alone says nothing
# to anybody reading a report, and it is the number that says whether
# a host is a server, a desktop or a laptop -- which is most of what a
# chassis type is asked for. A number this does not know is kept as it
# is rather than dropped.
CHASSIS_TYPES = {
            "1"     : "other",
            "2"     : "unknown",
            "3"     : "desktop",
            "4"     : "low-profile-desktop",
            "5"     : "pizza-box",
            "6"     : "mini-tower",
            "7"     : "tower",
            "8"     : "portable",
            "9"     : "laptop",
            "10"    : "notebook",
            "11"    : "handheld",
            "12"    : "docking-station",
            "13"    : "all-in-one",
            "14"    : "sub-notebook",
            "15"    : "space-saving",
            "16"    : "lunch-box",
            "17"    : "main-server-chassis",
            "18"    : "expansion-chassis",
            "19"    : "sub-chassis",
            "20"    : "bus-expansion-chassis",
            "21"    : "peripheral-chassis",
            "22"    : "raid-chassis",
            "23"    : "rack-mount-chassis",
            "24"    : "sealed-case-pc",
            "25"    : "multi-system-chassis",
            "28"    : "blade",
            "29"    : "blade-enclosure",
            "30"    : "tablet",
            "31"    : "convertible",
            "32"    : "detachable",
            "35"    : "mini-pc",
            "36"    : "stick-pc",
            }

# What a hypervisor calls itself in DMI. Asked only after
# /sys/hypervisor/type, which says it outright where it exists.
VIRT_VENDORS = {
            "qemu"                  : "kvm",
            "kvm"                   : "kvm",
            "bochs"                 : "kvm",
            "vmware"                : "vmware",
            "innotek gmbh"          : "virtualbox",
            "oracle corporation"    : "virtualbox",
            "xen"                   : "xen",
            "parallels"             : "parallels",
            "microsoft corporation" : "hyperv",
            "amazon ec2"            : "amazon",
            "google"                : "google",
            "digitalocean"          : "digitalocean",
            "hetzner"               : "hetzner",
            }

def read_file(path):
    """ One line of a file, or None.

    Not being allowed to read it is as good as it not being there: some
    DMI files are root only, and confd is root, but a host that is set
    up otherwise should report what it can rather than nothing.
    """
    try:
        with open(path, "r") as fd:
            return fd.read().strip()
    except Exception:
        return None

def clean_value(value):
    """ Drop a value that says nothing, and trim what it says. """
    if value is None:
        return None
    value = " ".join(str(value).split())
    if value.lower() in EMPTY_VALUES:
        return None
    if not re.match(VALUE_RE, value):
        return None
    return value

def read_dmi(name):
    """ One DMI field, cleaned. """
    return clean_value(read_file(os.path.join(DMI_DIR, name)))

def get_chassis_type():
    """ What kind of case this is, by name. """
    chassis_type = read_dmi("chassis_type")
    if chassis_type is None:
        return None
    return CHASSIS_TYPES.get(chassis_type, chassis_type)

def get_cpu_info():
    """ The CPU model and how many of them there are.

    The count is the logical CPUs, which is what a host has to work
    with -- cores times threads, or however the hypervisor cut it.
    """
    model = None
    count = 0
    content = read_file(CPUINFO_FILE)
    if content is None:
        return model, count
    for line in content.splitlines():
        if line.startswith("processor"):
            count += 1
            continue
        if model is not None:
            continue
        if not line.startswith("model name"):
            continue
        try:
            model = clean_value(line.split(":", 1)[1])
        except IndexError:
            pass
    return model, count

def get_memory():
    """ How much memory the host has, in bytes.

    MemTotal is what the kernel has left to hand out, so it is a little
    under what is built in. It is the number the host itself works
    with, and the one that does not change when somebody boots with
    another kernel parameter.
    """
    content = read_file(MEMINFO_FILE)
    if content is None:
        return None
    for line in content.splitlines():
        if not line.startswith("MemTotal:"):
            continue
        try:
            return int(line.split()[1]) * 1024
        except (IndexError, ValueError):
            return None
    return None

def get_disks():
    """ The disks of the host: name, size in bytes, model.

    Only what has a device behind it, which leaves out loop and ram
    devices. A CD-ROM is one too, and it is kept: what is in a host is
    what this is about.
    """
    disks = []
    try:
        names = sorted(os.listdir(BLOCK_DIR))
    except Exception:
        return disks
    for name in names:
        if not re.match(DISK_NAME_RE, name):
            continue
        disk_dir = os.path.join(BLOCK_DIR, name)
        if not os.path.exists(os.path.join(disk_dir, "device")):
            continue
        size = read_file(os.path.join(disk_dir, "size"))
        try:
            # /sys/block/*/size counts sectors of 512 bytes, always,
            # whatever the drive itself uses.
            size = int(size) * 512
        except (TypeError, ValueError):
            continue
        disk = {'name':name, 'size':size}
        model = clean_value(read_file(os.path.join(disk_dir,
                                                "device", "model")))
        if model:
            disk['model'] = model
        disks.append(disk)
        if len(disks) >= MAX_DISKS:
            break
    return disks

def get_virtualization(vendor, model):
    """ Whether this host is a virtual machine, and on what.

    /sys/hypervisor/type says it where it exists, which on a Xen guest
    is the only place it is said. Everywhere else the board tells on
    itself: a hypervisor puts its own name in the DMI vendor.
    """
    hypervisor = read_file(HYPERVISOR_TYPE_FILE)
    if hypervisor:
        return True, clean_value(hypervisor.lower())
    for x_value in (vendor, model):
        if not x_value:
            continue
        x_value = x_value.lower()
        for x_vendor, virt_type in VIRT_VENDORS.items():
            if x_vendor in x_value:
                return True, virt_type
    return False, None

def get_hardware():
    """ What this host is made of. """
    hardware = {}
    vendor = read_dmi("sys_vendor")
    model = read_dmi("product_name")
    dmi_fields = {
                'vendor'        : vendor,
                'model'         : model,
                'serial'        : read_dmi("product_serial"),
                'asset_tag'     : read_dmi("chassis_asset_tag"),
                'sku'           : read_dmi("product_sku"),
                'board_vendor'  : read_dmi("board_vendor"),
                'board_model'   : read_dmi("board_name"),
                'board_serial'  : read_dmi("board_serial"),
                'bios_vendor'   : read_dmi("bios_vendor"),
                'bios_version'  : read_dmi("bios_version"),
                'bios_date'     : read_dmi("bios_date"),
                'chassis_type'  : get_chassis_type(),
                }
    for x_name, x_value in dmi_fields.items():
        if x_value is None:
            continue
        hardware[x_name] = x_value

    cpu_model, cpu_count = get_cpu_info()
    if cpu_model:
        hardware['cpu_model'] = cpu_model
    if cpu_count:
        hardware['cpu_count'] = cpu_count

    memory = get_memory()
    if memory:
        hardware['memory'] = memory

    disks = get_disks()
    if disks:
        hardware['disks'] = disks

    virtual, virt_type = get_virtualization(vendor, model)
    hardware['virtual'] = virtual
    if virt_type:
        hardware['virt_type'] = virt_type

    return hardware

def get_hardware_checksum(hardware):
    """ The checksum of a hardware inventory.

    Sorted, so it does not depend on the order the fields were found
    or stored in.
    """
    if not hardware:
        hardware = {}
    data = json.dumps(hardware, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()

def check_hardware(hardware):
    """ Refuse a hardware inventory that does not look like one.

    Asked by syncd before anything of it is stored: the host says what
    it has, and that is taken as it is, but only in the shape of an
    inventory. What is not one of the known fields is dropped, so a
    host cannot fill the index with names of its own.

    Returns what may be stored.
    """
    if hardware is None:
        return {}
    if not isinstance(hardware, dict):
        msg = _("Invalid hardware inventory.")
        raise OTPmeException(msg)
    checked = {}
    for name in STRING_FIELDS:
        value = hardware.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or not re.match(VALUE_RE, value):
            msg = _("Invalid hardware value: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        checked[name] = value
    for name in INT_FIELDS:
        value = hardware.get(name)
        if value is None:
            continue
        # A bool is an int in python, and "virtual: 1" is not a CPU
        # count. Asked for on its own so it cannot slip in here.
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            msg = _("Invalid hardware value: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        checked[name] = value
    for name in BOOL_FIELDS:
        value = hardware.get(name)
        if value is None:
            continue
        if not isinstance(value, bool):
            msg = _("Invalid hardware value: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        checked[name] = value
    disks = hardware.get("disks")
    if disks is not None:
        if not isinstance(disks, list):
            msg = _("Invalid hardware value: disks")
            raise OTPmeException(msg)
        if len(disks) > MAX_DISKS:
            msg = _("Too many disks.")
            raise OTPmeException(msg)
        checked_disks = []
        for disk in disks:
            if not isinstance(disk, dict):
                msg = _("Invalid hardware value: disks")
                raise OTPmeException(msg)
            name = disk.get("name")
            size = disk.get("size")
            if not isinstance(name, str) or not re.match(DISK_NAME_RE, name):
                msg = _("Invalid disk name: {name}")
                msg = msg.format(name=name)
                raise OTPmeException(msg)
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                msg = _("Invalid disk size: {name}")
                msg = msg.format(name=name)
                raise OTPmeException(msg)
            checked_disk = {'name':name, 'size':size}
            disk_model = disk.get("model")
            if disk_model is not None:
                if not isinstance(disk_model, str) \
                or not re.match(VALUE_RE, disk_model):
                    msg = _("Invalid disk model: {name}")
                    msg = msg.format(name=name)
                    raise OTPmeException(msg)
                checked_disk['model'] = disk_model
            checked_disks.append(checked_disk)
        if checked_disks:
            checked['disks'] = checked_disks
    return checked
