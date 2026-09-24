# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Which handler runs the configuration management jobs of this host.

One handler per operating system family, picked by what
/etc/os-release says. A system nobody wrote a handler for gets none,
and confd refuses its jobs instead of guessing that apt might be there.
"""
import os
import platform

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

logger = config.logger

OS_RELEASE_FILE = "/etc/os-release"

# The handler classes there are, by the os-release ID they answer to.
handlers = {}

def register_handler(handler_class):
    """ Register a handler class for the systems it knows. """
    for os_id in handler_class.os_ids:
        handlers[os_id] = handler_class

def read_os_release(os_release_file=OS_RELEASE_FILE):
    """ The keys and values of /etc/os-release. """
    os_release = {}
    try:
        with open(os_release_file, "r") as fd:
            file_content = fd.read()
    except OSError as e:
        log_msg = _("Failed to read {file}: {e}", log=True)[1]
        log_msg = log_msg.format(file=os_release_file, e=e)
        logger.warning(log_msg)
        return os_release
    for line in file_content.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        os_release[key] = value.strip().strip('"').strip("'")
    return os_release

def get_os_ids(os_release_file=OS_RELEASE_FILE):
    """ What this system calls itself: its ID first, then what it says
    it is like (ID_LIKE), so a derivative is served by the handler of
    the system it derives from. """
    os_ids = []
    os_release = read_os_release(os_release_file)
    if os_release.get("ID"):
        os_ids.append(os_release["ID"].lower())
    for x_id in os_release.get("ID_LIKE", "").lower().split():
        if x_id in os_ids:
            continue
        os_ids.append(x_id)
    return os_ids

def get_os_info(os_release_file=OS_RELEASE_FILE):
    """ The system this host runs, the way the host object keeps it:
    ("Linux", "debian-13").

    The version is the ID and VERSION_ID of /etc/os-release. A system
    without a version number (Debian testing, for example) has its
    codename instead ("debian-trixie"). """
    os_names = {
            'Linux'     : "Linux",
            'Windows'   : "Windows",
            'Darwin'    : "MacOS",
            }
    system = platform.system()
    os_name = os_names.get(system, system)
    os_release = read_os_release(os_release_file)
    os_id = os_release.get("ID", "").lower()
    version = os_release.get("VERSION_ID") \
            or os_release.get("VERSION_CODENAME")
    if not os_id:
        return os_name, None
    if not version:
        return os_name, os_id
    return os_name, f"{os_id}-{version}"

def get_handler(logger=None, os_release_file=OS_RELEASE_FILE):
    """ The handler for this system. """
    os_ids = get_os_ids(os_release_file=os_release_file)
    for os_id in os_ids:
        try:
            handler_class = handlers[os_id]
        except KeyError:
            continue
        return handler_class(logger=logger)
    msg = _("No configuration management handler for this system: {os_ids}")
    msg = msg.format(os_ids=", ".join(os_ids) or "unknown")
    raise OTPmeException(msg)

from otpme.lib.confd.debian import DebianHandler

register_handler(DebianHandler)
