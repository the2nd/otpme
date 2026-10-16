# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The maintenance mode of a site.

A site is in maintenance while its nodes run other code than its
objects are stored for, or while somebody switched it on:

- The major and minor version of the code is not the one the site
  says (Site.otpme_version). Patch levels and pre-releases do not
  count. A site that says none counts as the same.
- The object config versions of the code are not the ones the site
  stores (Site.config_versions). A type the site does not name is at
  version 1.
- Site.maintenance is set: by "otpme-site maintenance on", or by
  "otpme-site upgrade" while it runs or after it failed.

Nothing is written to say so. Each node compares its own code with
what the site says, so an update of the code starts the mode on that
node by itself. Objects of the tree are written on the master node,
so it is the code there that counts.

While it is on, no object of the tree is written, renamed or deleted
here. What the cluster and the sync bring in is still written.
"otpme-site upgrade" writes with override() and ends it.
"""
import os
from contextlib import contextmanager

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

import otpme
from otpme.lib import re
from otpme.lib import config

# Who switched it on, as Site.maintenance says.
MANUAL = "manual"
UPGRADE = "upgrade"

def get_release(version=None):
    """ Major and minor of an OTPme version, as (0, 3). None if unreadable. """
    if version is None:
        version = otpme.__version__
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))

def get_reasons(site):
    """ Why a site is in maintenance on this node, empty if it is not. """
    reasons = []
    if site.maintenance == MANUAL:
        reasons.append(_("Switched on by hand."))
    elif site.maintenance == UPGRADE:
        reasons.append(_("Switched on by an upgrade that runs or failed."))
    elif site.maintenance:
        msg = _("Switched on: {who}")
        msg = msg.format(who=site.maintenance)
        reasons.append(msg)
    if site.otpme_version:
        if get_release(site.otpme_version) != get_release():
            msg = _("Site is at OTPme {site_version}, this node runs {code_version}.")
            msg = msg.format(site_version=site.otpme_version,
                            code_version=otpme.__version__)
            reasons.append(msg)
    site_versions = site.config_versions or {}
    code_versions = config.get_config_versions()
    for key in sorted(set(site_versions) | set(code_versions)):
        site_version = site_versions.get(key, 1)
        code_version = code_versions.get(key, 1)
        if site_version == code_version:
            continue
        msg = _("Objects {key}: site stores version {site_version}, this node writes {code_version}.")
        msg = msg.format(key=key,
                        site_version=site_version,
                        code_version=code_version)
        reasons.append(msg)
    return reasons

def is_active():
    """ Whether objects of the tree must not be written here now. """
    from otpme.lib import backend
    if config.maintenance_override:
        return False
    # A host writes no objects of the tree, only what the sync brings.
    if config.host_type != "node":
        return False
    if not config.site_uuid:
        return False
    site = backend.get_object(uuid=config.site_uuid)
    if not site:
        return False
    if get_reasons(site):
        return True
    return False

@contextmanager
def override():
    """ Write while the site is in maintenance: the upgrade and the switch. """
    old_value = config.maintenance_override
    config.maintenance_override = True
    try:
        yield
    finally:
        config.maintenance_override = old_value
