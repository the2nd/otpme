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
import gzip
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
DEVICES_DIR = "/sys/devices"
CPUINFO_FILE = "/proc/cpuinfo"
MEMINFO_FILE = "/proc/meminfo"
HYPERVISOR_TYPE_FILE = "/sys/hypervisor/type"
# SCSI VPD page 0x80, the unit serial number. The kernel hands the page
# out as it came off the device: two bytes of header, the length, and
# then the serial as ASCII.
VPD_SERIAL_FILE = "vpd_pg80"
VPD_SERIAL_HEADER_LEN = 4
# What a PCI class says: 0x01 is a mass storage controller, which is
# what a disk hangs on.
PCI_STORAGE_CLASS = "0x01"
# And 0x02 is a network controller.
PCI_NETWORK_CLASS = "0x02"
PCI_DEVICES_DIR = "/sys/bus/pci/devices"
# Where the PCI ID database is, by distribution. It is what turns
# 1000:005d into "MegaRAID SAS-3 3108" and 1028:1f47 into "PERC H730P
# Mini". Not on every host, and then a controller is its IDs and its
# driver and nothing more.
PCI_IDS_FILES = [
            "/usr/share/misc/pci.ids",
            "/usr/share/hwdata/pci.ids",
            "/usr/share/pci.ids",
            ]
# How that file is written: a line per vendor, a line indented once per
# device of that vendor, and a line indented twice per subsystem of that
# device. Two spaces between the IDs and the name.
PCI_ID_RE = r'^[0-9a-f]{4}$'
PCI_VENDOR_LINE_RE = r'^([0-9a-f]{4})  (.+)$'
PCI_DEVICE_LINE_RE = r'^\t([0-9a-f]{4})  (.+)$'
PCI_SUBSYSTEM_LINE_RE = r'^\t\t([0-9a-f]{4}) ([0-9a-f]{4})  (.+)$'
MAX_CONTROLLERS = 32
NET_DIR = "/sys/class/net"
NIC_NAME_RE = r'^[a-zA-Z0-9._:-]{1,32}$'
MAX_NICS = 64

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
# One entry per disk: {'name':..., 'size':..., ...}.
DISK_FIELDS = ["disks"]
# What else a disk may say, beside its name and its size. Anything a
# host sends that is not in here is dropped, the way it is for the
# fields of the machine itself.
DISK_STRING_FIELDS = [
                "vendor",
                "model",
                "serial",
                # The PCI address of the controller it hangs on, which
                # is what says which disks share one.
                "controller",
                ]
# One entry per storage controller, keyed by its PCI address, which is
# what a disk names as the controller it hangs on.
CONTROLLER_FIELDS = ["controllers"]
CONTROLLER_STRING_FIELDS = [
                "vendor_id",
                "device_id",
                "subsystem_id",
                "driver",
                "vendor",
                # The name on the card, and the name of the chip on it.
                "model",
                "chip",
                ]
# One entry per network card, keyed by the name the kernel gave it.
NIC_FIELDS = ["nics"]
NIC_STRING_FIELDS = [
                "mac",
                ] + CONTROLLER_STRING_FIELDS

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

def read_vpd_serial(device_dir):
    """ The serial number a SCSI or SATA disk reports.

    From VPD page 0x80, which is the one page that is the serial and
    nothing else. Read as bytes, because that is what it is: the fourth
    byte says how long the serial is, and the rest of the page may be
    anything.

    NVMe has no VPD pages and answers with "serial" instead, which
    get_disks() asks for first.
    """
    try:
        with open(os.path.join(device_dir, VPD_SERIAL_FILE), "rb") as fd:
            page = fd.read(256)
    except Exception:
        return None
    if len(page) <= VPD_SERIAL_HEADER_LEN:
        return None
    length = page[VPD_SERIAL_HEADER_LEN - 1]
    serial = page[VPD_SERIAL_HEADER_LEN:VPD_SERIAL_HEADER_LEN + length]
    try:
        serial = serial.decode("ascii")
    except UnicodeDecodeError:
        return None
    return clean_value(serial)

def read_pci_id(device_dir, name):
    """ One of the hex IDs of a PCI device, as pci.ids writes them. """
    value = read_file(os.path.join(device_dir, name))
    if not value:
        return None
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    if not re.match(PCI_ID_RE, value):
        return None
    return value

def get_pci_ids_file():
    """ Where the PCI ID database is on this host, if it is here. """
    for path in PCI_IDS_FILES:
        for x_path in (path, f"{path}.gz"):
            if os.path.exists(x_path):
                return x_path
    return None

def open_pci_ids(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")

def read_pci_names(devices):
    """ The names the PCI ID database has for these devices.

    Each device is a dict with vendor_id, device_id and subsystem_id.
    Answers what the database calls each vendor, device and subsystem
    of them, keyed by the IDs that were looked up.

    One pass over a file of about a megabyte, and only over the vendors
    that are wanted. It runs when the hardware of a host changed, which
    is rare, and the alternative is a library that is not everywhere
    either.
    """
    names = {}
    path = get_pci_ids_file()
    if not path:
        return names
    wanted_vendors = set()
    wanted_devices = set()
    wanted_subsystems = set()
    for device in devices:
        vendor_id = device.get('vendor_id')
        if not vendor_id:
            continue
        wanted_vendors.add(vendor_id)
        device_id = device.get('device_id')
        if not device_id:
            continue
        wanted_devices.add((vendor_id, device_id))
        subsystem_id = device.get('subsystem_id')
        if not subsystem_id or ":" not in subsystem_id:
            continue
        subsystem_vendor, subsystem_device = subsystem_id.split(":", 1)
        wanted_subsystems.add((vendor_id, device_id,
                            subsystem_vendor, subsystem_device))
    if not wanted_vendors:
        return names
    try:
        fd = open_pci_ids(path)
    except Exception:
        return names
    vendor_id = None
    device_id = None
    try:
        for line in fd:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if not line.startswith("\t"):
                match = re.match(PCI_VENDOR_LINE_RE, line)
                if not match:
                    # The list of device classes, which comes after the
                    # vendors and has nothing for us.
                    break
                vendor_id = match.group(1)
                device_id = None
                if vendor_id in wanted_vendors:
                    names[('vendor', vendor_id)] = match.group(2).strip()
                continue
            if vendor_id not in wanted_vendors:
                continue
            match = re.match(PCI_DEVICE_LINE_RE, line)
            if match:
                device_id = match.group(1)
                if (vendor_id, device_id) in wanted_devices:
                    names[('device', vendor_id, device_id)] = match.group(2).strip()
                continue
            match = re.match(PCI_SUBSYSTEM_LINE_RE, line)
            if not match:
                continue
            if device_id is None:
                continue
            key = ('subsystem', vendor_id, device_id,
                    match.group(1), match.group(2))
            if key[1:] in wanted_subsystems:
                names[key] = match.group(3).strip()
    finally:
        fd.close()
    return names

def get_controllers():
    """ The storage controllers of the host.

    Every PCI device of the mass storage class, by its address, with
    the IDs and the driver behind it. The names come from the PCI ID
    database where the host has one.

    Two names, because the card and the chip on it are not the same
    thing and either one may be what somebody looks for: the model is
    what the subsystem is called, which is the name on the card ("PERC
    H730P Mini"), and the chip is what the device is called ("MegaRAID
    SAS-3 3108 [Invader]"). Preferring one over the other would lose
    the better name half the time -- a card says "PERC H730P Mini"
    where a chipset controller says "Motherboard".
    """
    controllers = []
    try:
        addresses = sorted(os.listdir(PCI_DEVICES_DIR))
    except Exception:
        return controllers
    for address in addresses:
        device_dir = os.path.join(PCI_DEVICES_DIR, address)
        pci_class = read_file(os.path.join(device_dir, "class"))
        if not pci_class or not pci_class.startswith(PCI_STORAGE_CLASS):
            continue
        address = clean_value(address)
        if not address:
            continue
        controller = {'address':address}
        controller.update(read_pci_device(device_dir))
        controllers.append(controller)
        if len(controllers) >= MAX_CONTROLLERS:
            break
    add_pci_names(controllers)
    return controllers

def read_pci_device(device_dir):
    """ The IDs and the driver of a PCI device, as far as it has them.

    Answers an empty dict for something that is not a PCI device: a
    network card on USB has none of these files, and then it is the
    name and the MAC and nothing else.
    """
    device = {}
    vendor_id = read_pci_id(device_dir, "vendor")
    if vendor_id:
        device['vendor_id'] = vendor_id
    device_id = read_pci_id(device_dir, "device")
    if device_id:
        device['device_id'] = device_id
    subsystem_vendor = read_pci_id(device_dir, "subsystem_vendor")
    subsystem_device = read_pci_id(device_dir, "subsystem_device")
    if subsystem_vendor and subsystem_device:
        device['subsystem_id'] = f"{subsystem_vendor}:{subsystem_device}"
    driver = read_device_driver(device_dir)
    if driver:
        device['driver'] = driver
    return device

def read_device_driver(device_dir):
    """ The driver bound to a device, by name. """
    driver = os.path.join(device_dir, "driver")
    if not os.path.exists(driver):
        return None
    return clean_value(os.path.basename(os.path.realpath(driver)))

def add_pci_names(devices):
    """ Put the names of the PCI ID database on these devices.

    The vendor, the chip and -- where the database has one for the
    subsystem -- the name on the card. Nothing happens to a device
    without IDs, or on a host without the database.
    """
    names = read_pci_names(devices)
    if not names:
        return
    for device in devices:
        vendor_id = device.get('vendor_id')
        device_id = device.get('device_id')
        vendor = names.get(('vendor', vendor_id))
        if vendor:
            device['vendor'] = vendor
        chip = names.get(('device', vendor_id, device_id))
        if chip:
            device['chip'] = chip
        subsystem_id = device.get('subsystem_id')
        if subsystem_id and ":" in subsystem_id:
            subsystem_vendor, subsystem_device = subsystem_id.split(":", 1)
            model = names.get(('subsystem', vendor_id, device_id,
                            subsystem_vendor, subsystem_device))
            if model:
                device['model'] = model

def get_nics():
    """ The network cards of the host.

    Only what has a device behind it, the way a disk is only what has
    one: that leaves out the loopback, the bridges, the bonds, the VLAN
    interfaces and the tunnels, which are not hardware and are named
    after whoever configured them.

    The name, the MAC, and what the card is, the same way a controller
    says it. Not the link speed: that is the state of a cable and not
    of the hardware, it is -1 where nothing is plugged in, and the
    inventory is reported again whenever anything in it changes.
    """
    nics = []
    try:
        names = sorted(os.listdir(NET_DIR))
    except Exception:
        return nics
    for name in names:
        if not re.match(NIC_NAME_RE, name):
            continue
        nic_dir = os.path.join(NET_DIR, name)
        device_dir = os.path.join(nic_dir, "device")
        if not os.path.exists(device_dir):
            continue
        nic = {'name':name}
        mac = clean_value(read_file(os.path.join(nic_dir, "address")))
        if mac:
            nic['mac'] = mac
        # Not the device the link points at: for a virtio card that is
        # the virtio device, whose IDs say "virtio network card" and
        # nothing about the card it runs on.
        pci_dir = get_pci_device_dir(device_dir, PCI_NETWORK_CLASS)
        if pci_dir:
            nic.update(read_pci_device(pci_dir))
        # The driver of the card and not of the bus it sits on: a
        # virtio card is driven by virtio_net, and the PCI device below
        # it by virtio-pci, which says nothing about a network card.
        driver = read_device_driver(device_dir)
        if driver:
            nic['driver'] = driver
        nics.append(nic)
        if len(nics) >= MAX_NICS:
            break
    add_pci_names(nics)
    return nics

def get_pci_device_dir(start_dir, pci_class):
    """ The PCI device of this class at or above a device.

    A device sits below the PCI device it belongs to, so the way to it
    is up: /sys/block/sda leads to something like

      /sys/devices/pci0000:00/0000:00:05.0/virtio1/host2/.../block/sda

    and 0000:00:05.0 is the first thing on that way that is a PCI
    device of the mass storage class.

    The class is asked for and not just "the nearest PCI device",
    because the nearest one is not always the device itself: a network
    card on USB would find the PCI device of the USB controller, and
    its IDs say nothing about the card. No device of the class asked
    for, no answer.
    """
    path = os.path.realpath(start_dir)
    while path.startswith(DEVICES_DIR) and path != DEVICES_DIR:
        device_class = read_file(os.path.join(path, "class"))
        if device_class and device_class.startswith(pci_class):
            return path
        path = os.path.dirname(path)
    return None

def get_disk_controller(disk_dir):
    """ The controller a disk hangs on, as its PCI address.

    The address and not a name: what the controller is called needs the
    PCI ID database, which is not on every host. The address is what
    says which disks hang on the same controller, and the controllers
    themselves are inventoried under it, see get_controllers().
    """
    path = get_pci_device_dir(disk_dir, PCI_STORAGE_CLASS)
    if not path:
        return None
    return clean_value(os.path.basename(path))

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
    """ The disks of the host.

    Per disk: name, size in bytes, and what of vendor, model, serial
    and controller can be read.

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
        device_dir = os.path.join(disk_dir, "device")
        vendor = clean_value(read_file(os.path.join(device_dir, "vendor")))
        if vendor:
            disk['vendor'] = vendor
        model = clean_value(read_file(os.path.join(device_dir, "model")))
        if model:
            disk['model'] = model
        # NVMe says it outright, SCSI and SATA through the VPD page.
        serial = clean_value(read_file(os.path.join(device_dir, "serial")))
        if not serial:
            serial = read_vpd_serial(device_dir)
        if serial:
            disk['serial'] = serial
        controller = get_disk_controller(disk_dir)
        if controller:
            disk['controller'] = controller
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

    controllers = get_controllers()
    if controllers:
        hardware['controllers'] = controllers

    nics = get_nics()
    if nics:
        hardware['nics'] = nics

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
            for x_field in DISK_STRING_FIELDS:
                x_value = disk.get(x_field)
                if x_value is None:
                    continue
                if not isinstance(x_value, str) \
                or not re.match(VALUE_RE, x_value):
                    msg = _("Invalid disk {field}: {name}")
                    msg = msg.format(field=x_field, name=name)
                    raise OTPmeException(msg)
                checked_disk[x_field] = x_value
            checked_disks.append(checked_disk)
        if checked_disks:
            checked['disks'] = checked_disks
    controllers = hardware.get("controllers")
    if controllers is not None:
        if not isinstance(controllers, list):
            msg = _("Invalid hardware value: controllers")
            raise OTPmeException(msg)
        if len(controllers) > MAX_CONTROLLERS:
            msg = _("Too many controllers.")
            raise OTPmeException(msg)
        checked_controllers = []
        for controller in controllers:
            if not isinstance(controller, dict):
                msg = _("Invalid hardware value: controllers")
                raise OTPmeException(msg)
            address = controller.get("address")
            if not isinstance(address, str) or not re.match(VALUE_RE, address):
                msg = _("Invalid controller address: {address}")
                msg = msg.format(address=address)
                raise OTPmeException(msg)
            checked_controller = {'address':address}
            for x_field in CONTROLLER_STRING_FIELDS:
                x_value = controller.get(x_field)
                if x_value is None:
                    continue
                if not isinstance(x_value, str) \
                or not re.match(VALUE_RE, x_value):
                    msg = _("Invalid controller {field}: {address}")
                    msg = msg.format(field=x_field, address=address)
                    raise OTPmeException(msg)
                checked_controller[x_field] = x_value
            checked_controllers.append(checked_controller)
        if checked_controllers:
            checked['controllers'] = checked_controllers
    nics = hardware.get("nics")
    if nics is not None:
        if not isinstance(nics, list):
            msg = _("Invalid hardware value: nics")
            raise OTPmeException(msg)
        if len(nics) > MAX_NICS:
            msg = _("Too many nics.")
            raise OTPmeException(msg)
        checked_nics = []
        for nic in nics:
            if not isinstance(nic, dict):
                msg = _("Invalid hardware value: nics")
                raise OTPmeException(msg)
            name = nic.get("name")
            if not isinstance(name, str) or not re.match(NIC_NAME_RE, name):
                msg = _("Invalid nic name: {name}")
                msg = msg.format(name=name)
                raise OTPmeException(msg)
            checked_nic = {'name':name}
            for x_field in NIC_STRING_FIELDS:
                x_value = nic.get(x_field)
                if x_value is None:
                    continue
                if not isinstance(x_value, str) \
                or not re.match(VALUE_RE, x_value):
                    msg = _("Invalid nic {field}: {name}")
                    msg = msg.format(field=x_field, name=name)
                    raise OTPmeException(msg)
                checked_nic[x_field] = x_value
            checked_nics.append(checked_nic)
        if checked_nics:
            checked['nics'] = checked_nics
    return checked
