# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The inventory of a host: its operating system and its packages.

confd on the host works out what is installed, syncd on the nodes keeps
it in the host object (OS, OS_VERSION, PACKAGES). Both sides need the
same idea of what a list of packages looks like and when two of them are
the same, and that is what this module is for.

The whole list does not travel every time. confd sends the checksum of
what it has; only when the nodes hold something else do they send their
list, and confd sends back only the difference.
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

# What the parts of an inventory may look like. A package name as dpkg
# gives it, with the architecture of a multi-arch package (libc6:amd64).
OS_NAME_RE = r'^[A-Za-z0-9._-]{1,32}$'
OS_VERSION_RE = r'^[A-Za-z0-9._+~-]{1,64}$'
# A kernel release as uname -r gives it: "6.1.0-37-amd64",
# "6.12.9-1-pve", "5.15.0-1055-aws". A locally built one carries
# whatever was set as its local version, so "+" and "_" belong in here.
KERNEL_RE = r'^[A-Za-z0-9._+~-]{1,128}$'
# The OTPme version the host runs, as otpme.__version__ gives it:
# "0.3.0a283", or with a local part "0.3.0a283+git1".
OTPME_VERSION_RE = r'^[A-Za-z0-9.+_-]{1,64}$'
PACKAGE_NAME_RE = r'^[a-zA-Z0-9][a-zA-Z0-9+._:-]{0,191}$'
PACKAGE_VERSION_RE = r'^[a-zA-Z0-9.+~:_-]{1,128}$'
# The architecture packages are built for, the way the package manager
# names it: "amd64", "arm64", "i386". Not what uname -m says (x86_64):
# that is the name the packages do not carry.
ARCH_RE = r'^[a-z0-9][a-z0-9_-]{0,31}$'
# How many packages a host may have, and how many change in one request.
# The first report of a host is all of its packages at once, so a
# request is kept small and the rest follows in the next ones.
MAX_PACKAGES = 50000
MAX_PACKAGES_PER_UPDATE = 1000
# The same for what a reference host reports: the packages its system
# offers, which is all of a distribution -- some 65,000 for Debian
# main alone, more with a second repository. Larger parts, because the
# first report is all of them, and a thousand at a time would be
# seventy rounds.
MAX_AVAILABLE_PACKAGES = 200000
MAX_AVAILABLE_PER_UPDATE = 5000

def get_packages_checksum(packages):
    """ The checksum of a list of packages ({name: version}).

    Sorted, so it does not depend on the order the packages were found
    or stored in. """
    if not packages:
        packages = {}
    data = json.dumps(sorted(dict(packages).items()))
    return hashlib.sha256(data.encode()).hexdigest()

def diff_packages(old_packages, new_packages):
    """ What changed between two lists of packages.

    Returns the packages that are new or have another version now, and
    the names of the packages that are gone. """
    old_packages = dict(old_packages or {})
    new_packages = dict(new_packages or {})
    set_packages = {}
    for name, version in new_packages.items():
        if old_packages.get(name) == version:
            continue
        set_packages[name] = version
    del_packages = []
    for name in old_packages:
        if name in new_packages:
            continue
        del_packages.append(name)
    return set_packages, sorted(del_packages)

def check_inventory(os_name, os_version, set_packages, del_packages,
    kernel=None, reboot_required=None, otpme_version=None, arch=None):
    """ Refuse an inventory update that does not look like one.

    Asked by syncd before anything of it reaches the host object: the
    host says what it has, and that is taken as it is, but only in the
    shape of an inventory. """
    if arch is not None:
        if not isinstance(arch, str) or not re.match(ARCH_RE, arch):
            msg = _("Invalid architecture: {arch}")
            msg = msg.format(arch=arch)
            raise OTPmeException(msg)
    if os_name is not None:
        if not isinstance(os_name, str) or not re.match(OS_NAME_RE, os_name):
            msg = _("Invalid OS: {os_name}")
            msg = msg.format(os_name=os_name)
            raise OTPmeException(msg)
    if os_version is not None:
        if not isinstance(os_version, str) \
        or not re.match(OS_VERSION_RE, os_version):
            msg = _("Invalid OS version: {os_version}")
            msg = msg.format(os_version=os_version)
            raise OTPmeException(msg)
    if kernel is not None:
        if not isinstance(kernel, str) or not re.match(KERNEL_RE, kernel):
            msg = _("Invalid kernel: {kernel}")
            msg = msg.format(kernel=kernel)
            raise OTPmeException(msg)
    if otpme_version is not None:
        if not isinstance(otpme_version, str) \
        or not re.match(OTPME_VERSION_RE, otpme_version):
            msg = _("Invalid OTPme version: {otpme_version}")
            msg = msg.format(otpme_version=otpme_version)
            raise OTPmeException(msg)
    if reboot_required is not None:
        # A yes or a no and nothing else: it goes into the index as it
        # is, and a host saying "maybe" would be a third value there.
        if not isinstance(reboot_required, bool):
            msg = _("Invalid reboot required: {reboot_required}")
            msg = msg.format(reboot_required=reboot_required)
            raise OTPmeException(msg)
    check_package_lists(set_packages, del_packages, MAX_PACKAGES_PER_UPDATE)

def check_available_packages(os_version, arch, set_packages, del_packages):
    """ Refuse a report of a reference host that does not look like one:
    the packages its system offers (see os_packages.py). """
    if not isinstance(os_version, str) \
    or not re.match(OS_VERSION_RE, os_version):
        msg = _("Invalid OS version: {os_version}")
        msg = msg.format(os_version=os_version)
        raise OTPmeException(msg)
    if not isinstance(arch, str) or not re.match(ARCH_RE, arch):
        msg = _("Invalid architecture: {arch}")
        msg = msg.format(arch=arch)
        raise OTPmeException(msg)
    check_package_lists(set_packages, del_packages, MAX_AVAILABLE_PER_UPDATE)

def check_package_lists(set_packages, del_packages, max_per_update):
    """ The changes of a package list: {name: version} and names. """
    if not isinstance(set_packages, dict):
        msg = _("Invalid package list.")
        raise OTPmeException(msg)
    if not isinstance(del_packages, list):
        msg = _("Invalid package list.")
        raise OTPmeException(msg)
    if len(set_packages) + len(del_packages) > max_per_update:
        msg = _("Too many packages in one update.")
        raise OTPmeException(msg)
    for name, version in set_packages.items():
        if not isinstance(name, str) or not re.match(PACKAGE_NAME_RE, name):
            msg = _("Invalid package name: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        if not isinstance(version, str) \
        or not re.match(PACKAGE_VERSION_RE, version):
            msg = _("Invalid package version: {name}: {version}")
            msg = msg.format(name=name, version=version)
            raise OTPmeException(msg)
    for name in del_packages:
        if not isinstance(name, str) or not re.match(PACKAGE_NAME_RE, name):
            msg = _("Invalid package name: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)

def split_package_update(set_packages, del_packages, max_per_update):
    """ The changes of a package list in parts of <max_per_update>, the
    removals first. """
    changes = [('del', name) for name in del_packages]
    changes += [('set', name) for name in sorted(set_packages)]
    updates = []
    for start in range(0, len(changes), max_per_update):
        x_set = {}
        x_del = []
        for kind, name in changes[start:start + max_per_update]:
            if kind == "del":
                x_del.append(name)
            else:
                x_set[name] = set_packages[name]
        updates.append((x_set, x_del))
    return updates

def native_package_name(name, arch):
    """ The name of an installed package the way the package lists name
    it, or None for a package of another architecture.

    dpkg names a package that may be installed for several
    architectures with the one it is installed for (libc6:amd64), and
    the lists do not: there it is libc6, offered for the architecture
    of the system. """
    if ":" not in name:
        return name
    name, name_arch = name.split(":", 1)
    if name_arch in (arch, "all"):
        return name
    return None

def _version_char_order(char):
    """ Where a character of a Debian version sorts: "~" before
    everything, even the end of the string, then the end, then letters,
    then everything else. """
    if char == "~":
        return -1
    if char == "":
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256

def _compare_version_part(a, b):
    """ One of upstream version and revision, the way dpkg compares them:
    a run of non-digits by character, then a run of digits as a number,
    and again. """
    while a or b:
        a_text = re.match(r'^[^0-9]*', a).group(0)
        b_text = re.match(r'^[^0-9]*', b).group(0)
        a = a[len(a_text):]
        b = b[len(b_text):]
        for i in range(max(len(a_text), len(b_text))):
            a_char = a_text[i] if i < len(a_text) else ""
            b_char = b_text[i] if i < len(b_text) else ""
            diff = _version_char_order(a_char) - _version_char_order(b_char)
            if diff:
                return diff
        a_digits = re.match(r'^[0-9]*', a).group(0)
        b_digits = re.match(r'^[0-9]*', b).group(0)
        a = a[len(a_digits):]
        b = b[len(b_digits):]
        diff = int(a_digits or 0) - int(b_digits or 0)
        if diff:
            return diff
    return 0

def compare_versions(a, b):
    """ Compare two Debian package versions: below zero when <a> is
    older, zero when they are the same, above zero when it is newer.

    Here and not asked of dpkg, because the nodes compare the packages
    of every host against what its system offers, and a node need not
    have dpkg -- nor would a process per package be any way to do it.
    """
    def split(version):
        epoch = 0
        if ":" in version:
            epoch_str, version = version.split(":", 1)
            try:
                epoch = int(epoch_str)
            except ValueError:
                epoch = 0
        revision = ""
        if "-" in version:
            version, revision = version.rsplit("-", 1)
        return epoch, version, revision
    a_epoch, a_upstream, a_revision = split(a)
    b_epoch, b_upstream, b_revision = split(b)
    if a_epoch != b_epoch:
        return a_epoch - b_epoch
    diff = _compare_version_part(a_upstream, b_upstream)
    if diff:
        return diff
    return _compare_version_part(a_revision, b_revision)
