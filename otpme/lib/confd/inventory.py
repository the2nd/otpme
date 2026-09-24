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
PACKAGE_NAME_RE = r'^[a-zA-Z0-9][a-zA-Z0-9+._:-]{0,191}$'
PACKAGE_VERSION_RE = r'^[a-zA-Z0-9.+~:_-]{1,128}$'
# How many packages a host may have, and how many change in one request.
# The first report of a host is all of its packages at once, so a
# request is kept small and the rest follows in the next ones.
MAX_PACKAGES = 50000
MAX_PACKAGES_PER_UPDATE = 1000

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

def check_inventory(os_name, os_version, set_packages, del_packages):
    """ Refuse an inventory update that does not look like one.

    Asked by syncd before anything of it reaches the host object: the
    host says what it has, and that is taken as it is, but only in the
    shape of an inventory. """
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
    if not isinstance(set_packages, dict):
        msg = _("Invalid package list.")
        raise OTPmeException(msg)
    if not isinstance(del_packages, list):
        msg = _("Invalid package list.")
        raise OTPmeException(msg)
    if len(set_packages) + len(del_packages) > MAX_PACKAGES_PER_UPDATE:
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
