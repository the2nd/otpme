# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The packages a system offers: what can be installed on a host that
runs it.

One object per OS version and architecture ("debian-13", "amd64"),
which is also the OID. A reference host reports it: confd there reads
the package lists of the host and sends what changed, the same way
every host sends its own packages (see confd/inventory.py and
daemon/confd.py). It goes where the host sends its inventory
(inventory_site) and stays on the nodes of that site, like the
inventory.

Which hosts are reference hosts says that site, in its config parameter
reference_hosts -- the site that keeps the data, the same way it says
in inventory_trusts whose inventories it keeps. Its syncd tells confd
with the answer to get_host_inventory, so the parameter never has to
reach the hosts.

One reference host writes an object at a time. Two of them with the
same system but other repositories would otherwise take turns, each
putting back what the other took out. The one that wrote it last keeps
it while it reports; one that has been quiet for REFERENCE_TAKEOVER_AGE,
is gone or is no longer a reference host is taken over by the next one
that reports.

The packages are kept in the index the way the inventory keeps them,
one value per package, "<name>=<version>", with the version apt would
install.
"""
import os
import time
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeDataObject
from otpme.lib.classes.otpme_object import check_index_attribute

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.site",
                "otpme.lib.classes.data_objects.host_inventory",
                ]
OS_PACKAGES_DIR = os.path.join(config.data_dir, "data", "os_packages")
# How long a reference host may be quiet before another one with the
# same system takes its object over. It reports every hour while it
# runs, so this is a host that is down, not one that is slow.
REFERENCE_TAKEOVER_AGE = 3 * 86400
# The OID parts besides realm and site: what os-release and dpkg say
# (see confd/inventory.py), without a "/".
OS_VERSION_OID_RE = r'[A-Za-z0-9._+~-]{1,64}'
ARCH_OID_RE = r'[a-z0-9][a-z0-9_-]{0,31}'

def register():
    register_oid()
    register_backend()
    register_sync_settings()
    register_config_params()

def register_config_params():
    """ Register config parameters. """
    def hosts_setter(host_names, **kwargs):
        if isinstance(host_names, str):
            host_names = host_names.split(",")
        host_uuids = []
        for x_name in host_names:
            x_name = x_name.strip()
            if not x_name:
                continue
            # Host and node names are unique in the realm.
            result = backend.search(object_types=["host", "node"],
                                    attribute="name",
                                    value=x_name,
                                    realm=config.realm,
                                    return_type="uuid")
            if not result:
                msg = _("Unknown host: {host}")
                msg = msg.format(host=x_name)
                raise ValueError(msg)
            if result[0] in host_uuids:
                continue
            host_uuids.append(result[0])
        return host_uuids
    def hosts_getter(host_uuids, **kwargs):
        if isinstance(host_uuids, str):
            host_uuids = host_uuids.split(",")
        host_names = []
        for x_uuid in host_uuids:
            result = backend.search(object_types=["host", "node"],
                                    attribute="uuid",
                                    value=x_uuid,
                                    return_type="name")
            if not result:
                host_names.append(x_uuid)
                continue
            host_names.append(result[0])
        return host_names
    # The hosts that report to us the packages their system offers. One
    # per system and architecture is enough; a second one with the same
    # is a stand-in, see the module docstring.
    #
    # On the site that keeps the inventory of the host: its own, or its
    # inventory_site. Our own site object is one every node of ours
    # has whole, and the hosts are told by syncd.
    config.register_config_parameter(name="reference_hosts",
                                    ctype=list,
                                    warn_if_exists=True,
                                    setter=hosts_setter,
                                    getter=hosts_getter,
                                    object_types=['site'])

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'os_version', 'arch' ]
    read_oid_schema = None
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    os_packages_oid_re = (f'os_packages[|]{realm_name_re}'
                        f'[/]{site_name_re}[/]{OS_VERSION_OID_RE}'
                        f'[/]{ARCH_OID_RE}')
    oid.register_oid_schema(object_type="os_packages",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=os_packages_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="os_packages",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. Between the nodes of our own site and
    nowhere else, like the inventory. """
    config.register_cluster_sync(object_type="os_packages")

def get_os_packages_dir(realm, site, os_version, arch):
    """ The directory of one object. """
    return os.path.join(OS_PACKAGES_DIR, realm, site, os_version, arch)

def get_os_packages(os_version, arch, realm=None, site=None):
    """ The packages of a system, or None if no reference host reported
    them. """
    if realm is None:
        realm = config.realm
    if site is None:
        site = config.site
    os_packages_oid = oid.get(object_type="os_packages",
                            realm=realm,
                            site=site,
                            os_version=os_version,
                            arch=arch)
    return backend.get_object(object_type="os_packages",
                            object_id=os_packages_oid)

def register_backend():
    """ Register object for the file backend. """
    path_id = "os_packages"
    backend.register_data_dir(name=path_id,
                            path=OS_PACKAGES_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(OS_PACKAGES_DIR):
            return
        path = path.rstrip("/")
        if os.path.basename(path) == config.object_config_file_name:
            path = os.path.dirname(path)
        rel_path = os.path.relpath(path, OS_PACKAGES_DIR)
        parts = rel_path.split("/")
        if len(parts) != 4:
            return
        object_realm, object_site, os_version, arch = parts
        object_id = oid.OTPmeOid(object_type="os_packages",
                                realm=object_realm,
                                site=object_site,
                                os_version=os_version,
                                arch=arch)
        return object_id
    def path_getter(object_id, object_uuid):
        config_dir = get_os_packages_dir(object_id.realm,
                                        object_id.site,
                                        object_id.os_version,
                                        object_id.arch)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild(object_dir=None):
        if object_dir:
            object_dir = object_dir.rstrip("/")
        packages_dir = backend.get_data_dir(path_id)
        for x_realm in filetools.list_dir(packages_dir):
            realm_dir = os.path.join(packages_dir, x_realm)
            for x_site in filetools.list_dir(realm_dir):
                site_dir = os.path.join(realm_dir, x_site)
                for x_os_version in filetools.list_dir(site_dir):
                    os_version_dir = os.path.join(site_dir, x_os_version)
                    for x_arch in filetools.list_dir(os_version_dir):
                        x_path = os.path.join(os_version_dir, x_arch)
                        if object_dir:
                            if x_path != object_dir:
                                continue
                        x_file = os.path.join(x_path, config.object_config_file_name)
                        log_msg = _("Processing {path_id}: {x_file}", log=True)[1]
                        log_msg = log_msg.format(path_id=path_id, x_file=x_file)
                        logger.debug(log_msg)
                        x_oid = oid_getter(x_path)
                        if not x_oid:
                            continue
                        backend.index_add(object_id=x_oid,
                                        object_config="auto",
                                        full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="os_packages",
                            version=1,
                            tree_object=False,
                            uniq_name=False,
                            add_after=["host_inventory"],
                            object_cache=16,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'os_version',
                                                'arch'])
    # Register index attributes.
    os_packages_types = ["os_packages"]
    config.register_index_attribute('package', sync=[],
                                    object_types=os_packages_types)
    config.register_index_attribute('os_version', sync=[],
                                    object_types=os_packages_types)
    config.register_index_attribute('arch', sync=[],
                                    object_types=os_packages_types)
    # Which reference host wrote it last, see the module docstring.
    config.register_index_attribute('reference_host', sync=[],
                                    object_types=os_packages_types)
    config.register_index_attribute('last_report', sync=[],
                                    object_types=os_packages_types)
    # Register object to backend.
    class_getter = lambda: OsPackages
    backend.register_object_type(object_type="os_packages",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

@match_class_typing
class OsPackages(OTPmeDataObject):
    """ The packages one system offers. """
    def __init__(
        self,
        os_version: Union[str,None]=None,
        arch: Union[str,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "os_packages"
        self.os_version = os_version
        self.arch = arch
        self.reference_host = None
        self.last_report = None
        # Call parent class init.
        super().__init__(object_id=object_id, **kwargs)
        if object_id:
            self.os_version = object_id.os_version
            self.arch = object_id.arch

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'REFERENCE_HOST'            : {
                                                        'var_name'  : 'reference_host',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'LAST_REPORT'               : {
                                                        'var_name'  : 'last_report',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        }
        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            os_version=self.os_version,
                            arch=self.arch)

    @property
    def packages(self):
        """ The packages: {name: version}. """
        packages = {}
        for x_value in self.get_index("package") or []:
            try:
                name, version = str(x_value).split("=", 1)
            except ValueError:
                continue
            packages[name] = version
        return packages

    def update_packages(self, set_packages=None, del_packages=None):
        """ Change the packages. Written by the caller.

        Not by add_index() and del_index() one by one: those look for
        the value in the list first, and with some 65,000 packages
        that is a search through all of them for each one. The list is
        gone through once here instead.

        The list is changed where it is and never replaced. The index
        is an incremental attribute: a list put in its place is written
        as one "add" for each of its items, and those go onto the list
        that is stored -- which then held every package twice, after
        the next part four times, and so on. """
        check_index_attribute("package", self.type)
        values = self.index.get("package")
        if values is None:
            self.index["package"] = []
            values = self.index["package"]
        elif len(values) != len(set(values)):
            # Written by the version that put a new list in place of
            # the old one. Once, and whole: taken out and put back
            # without the doubles.
            unique_values = list(dict.fromkeys(values))
            del self.index["package"]
            self.index["package"] = []
            values = self.index["package"]
            values += unique_values
        packages = self.packages
        removed = set()
        added = []
        now = time.time_ns()
        for name in del_packages or []:
            version = packages.pop(name, None)
            if version is None:
                continue
            x_value = f"{name}={version}"
            removed.add(x_value)
            self.index_journal.append([now, 'del', "package", x_value])
        for name, version in (set_packages or {}).items():
            old_version = packages.get(name)
            if old_version == version:
                continue
            if old_version is not None:
                x_value = f"{name}={old_version}"
                removed.add(x_value)
                self.index_journal.append([now, 'del', "package", x_value])
            x_value = f"{name}={version}"
            added.append(x_value)
            self.index_journal.append([now, 'add', "package", x_value])
            packages[name] = version
        if removed:
            # From the back, so the positions in front stay where they
            # were found.
            positions = [i for i, x in enumerate(values) if x in removed]
            for i in reversed(positions):
                del values[i]
        values += added

    def held_by_other(self, host_uuid):
        """ The reference host that keeps this object from <host_uuid>,
        or None if <host_uuid> may write it. See the module docstring. """
        if not self.reference_host or self.reference_host == host_uuid:
            return None
        if not self.last_report:
            return None
        if (time.time() - self.last_report) > REFERENCE_TAKEOVER_AGE:
            return None
        holder = backend.get_object(uuid=self.reference_host)
        if not holder:
            return None
        if not is_reference_host(holder.uuid):
            return None
        return holder

    def touch_report(self, host_uuid):
        """ Note that <host_uuid> reported just now, and that it is the
        one that writes us. """
        if self.reference_host != host_uuid:
            self.reference_host = host_uuid
            self.update_index("reference_host", host_uuid)
        self.last_report = time.time()
        self.update_index("last_report", int(self.last_report))

    def add(self, **kwargs):
        """ Add the object. """
        self.add_index('os_version', self.os_version)
        self.add_index('arch', self.arch)
        # Call base class add method.
        return super().add(**kwargs)

def is_reference_host(host_uuid):
    """ Whether a host is in the reference_hosts of our site. """
    own_site = backend.get_object(object_type="site",
                                uuid=config.site_uuid)
    if not own_site:
        return False
    try:
        reference_hosts = own_site.get_config_parameter("reference_hosts",
                                                        apply_getter=False)
    except Exception:
        return False
    if not reference_hosts:
        return False
    return host_uuid in reference_hosts
