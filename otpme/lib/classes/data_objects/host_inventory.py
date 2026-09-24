# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The inventory of one host: its packages and its hardware.

confd on the host reports both, syncd on the nodes keeps them here (see
otpme/lib/confd/inventory.py and confd/hardware.py). One object per
host, which is also the OID.

Not part of the host object on purpose: host objects are synced to every
host, and a list of some thousand packages per host -- changing with
every update -- has no business there. This object stays on the nodes
of the site.

The packages are kept in the index, one value per package in the form
"<name>=<version>", so they can be searched:

    backend.search(object_type="host_inventory",
                    attribute="package",
                    value="openssl=*")

The hardware is small enough to live in the object config, and only
what is worth searching is mirrored into the index, one attribute per
field ("hw_serial", "hw_model", ...). Sizes and counts go in as
integers so the index can compare them:

    backend.search(object_type="host_inventory",
                    attribute="hw_memory",
                    less_than=8 * 1024 ** 3)
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
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeDataObject
from otpme.lib.classes.otpme_object import token_role_list_setter
from otpme.lib.classes.otpme_object import token_role_list_getter

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.site",
                "otpme.lib.classes.data_objects.conf_result",
                ]
HOST_INVENTORY_DIR = os.path.join(config.data_dir, "data", "host_inventory")

# The hardware fields that go into the index, by the name they get
# there. The rest of the hardware is read off the object: an index
# attribute is something to search by, and nobody searches for a BIOS
# date.
#
# A disk is two values. "hw_disk" is "<name>=<size>", which lists and
# matches like a package; "hw_disk_size" is the size on its own,
# because the index compares by casting the value to an integer and
# "sda=123" is not one.
HARDWARE_INDEX_FIELDS = {
                    'vendor'        : "hw_vendor",
                    'model'         : "hw_model",
                    'serial'        : "hw_serial",
                    'asset_tag'     : "hw_asset_tag",
                    'sku'           : "hw_sku",
                    'cpu_model'     : "hw_cpu_model",
                    'cpu_count'     : "hw_cpu_count",
                    'memory'        : "hw_memory",
                    'bios_version'  : "hw_bios_version",
                    'chassis_type'  : "hw_chassis_type",
                    'virtual'       : "hw_virtual",
                    'virt_type'     : "hw_virt_type",
                    }
HARDWARE_DISK_ATTRIBUTE = "hw_disk"
HARDWARE_DISK_SIZE_ATTRIBUTE = "hw_disk_size"
HARDWARE_INDEX_ATTRIBUTES = sorted(set(HARDWARE_INDEX_FIELDS.values())
                                | {HARDWARE_DISK_ATTRIBUTE,
                                    HARDWARE_DISK_SIZE_ATTRIBUTE})

def register():
    register_oid()
    register_backend()
    register_sync_settings()
    register_config_params()

def register_config_params():
    """ Register config parameters. """
    # Who may read the inventory of a host: its packages, its hardware,
    # and what "otpme-inventory show" says about it. Resolved per host,
    # so a role can be allowed to see the hosts of one unit and no
    # other. Unset means nobody but an admin.
    #
    # A config parameter and not an ACL, because the inventory is not
    # one more attribute of a host: it is the serial number, what is
    # installed and what it is built from. On an ACL a plain "view" on
    # the host would carry all of it, and "view" is given out to have
    # somebody read a status.
    config.register_config_parameter(name="allow_inventory",
                                    ctype=list,
                                    warn_if_exists=True,
                                    setter=token_role_list_setter,
                                    getter=token_role_list_getter,
                                    object_types=[
                                                'site',
                                                'unit',
                                                'host',
                                                'node',
                                                ])

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'host_uuid' ]
    read_oid_schema = None
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    host_inventory_oid_re = (f'host_inventory[|]{realm_name_re}'
                            f'[/]{site_name_re}[/]{oid.uuid_re}')
    oid.register_oid_schema(object_type="host_inventory",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=host_inventory_oid_re)
    rel_path_getter = lambda x: x[-1:]
    oid.register_rel_path_getter(object_type="host_inventory",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. Between the nodes of our own site and
    nowhere else, see the module docstring. """
    config.register_cluster_sync(object_type="host_inventory")

def get_host_inventory_dir(realm, site, host_uuid):
    """ The directory of one inventory. """
    config_dir = os.path.join(HOST_INVENTORY_DIR, realm, site)
    return os.path.join(config_dir, host_uuid)

def get_host_inventory(host_uuid, realm=None, site=None):
    """ The inventory of a host, or None if it has not reported yet. """
    if realm is None:
        realm = config.realm
    if site is None:
        site = config.site
    inventory_oid = oid.get(object_type="host_inventory",
                            realm=realm,
                            site=site,
                            host_uuid=host_uuid)
    return backend.get_object(object_type="host_inventory",
                            object_id=inventory_oid)

def remove_orphan_inventories(still_allowed, logger):
    """ Remove the inventories of hosts that are gone.

    Runs on the master node only, with the cleanup of old jobs (see
    confd). <still_allowed> is asked before each inventory, so a
    failover stops it right away. Returns how many were removed. """
    inventories = backend.search(object_type="host_inventory",
                                attribute="host_uuid",
                                value="*",
                                return_type="instance")
    removed = 0
    for inventory in inventories:
        if not still_allowed():
            return removed
        if backend.get_oid(uuid=inventory.host_uuid):
            continue
        inventory.delete()
        removed += 1
        log_msg = _("Removed inventory of deleted host: {host_uuid}", log=True)[1]
        log_msg = log_msg.format(host_uuid=inventory.host_uuid)
        logger.info(log_msg)
    return removed

def register_backend():
    """ Register object for the file backend. """
    path_id = "host_inventory"
    backend.register_data_dir(name=path_id,
                            path=HOST_INVENTORY_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(HOST_INVENTORY_DIR):
            return
        path = path.rstrip("/")
        if os.path.basename(path) == config.object_config_file_name:
            path = os.path.dirname(path)
        host_uuid = os.path.basename(path)
        if not stuff.is_uuid(host_uuid):
            return
        site_dir = os.path.dirname(path)
        object_site = os.path.basename(site_dir)
        realm_dir = os.path.dirname(site_dir)
        object_realm = os.path.basename(realm_dir)
        object_id = oid.OTPmeOid(object_type="host_inventory",
                                realm=object_realm,
                                site=object_site,
                                host_uuid=host_uuid)
        return object_id
    def path_getter(object_id, object_uuid):
        config_dir = get_host_inventory_dir(object_id.realm,
                                            object_id.site,
                                            object_id.host_uuid)
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
        inventory_dir = backend.get_data_dir(path_id)
        for x_realm in filetools.list_dir(inventory_dir):
            realm_dir = os.path.join(inventory_dir, x_realm)
            for x_site in filetools.list_dir(realm_dir):
                site_dir = os.path.join(realm_dir, x_site)
                host_dirs = [x for x in filetools.list_dir(site_dir)
                            if stuff.is_uuid(x)]
                counter = 0
                files_count = len(host_dirs)
                for x in host_dirs:
                    counter += 1
                    x_path = os.path.join(site_dir, x)
                    if object_dir:
                        if x_path != object_dir:
                            continue
                    x_file = os.path.join(x_path, config.object_config_file_name)
                    log_msg = _("Processing {path_id} ({counter}/{files_count}): {x_file}", log=True)[1]
                    log_msg = log_msg.format(path_id=path_id,
                                            counter=counter,
                                            files_count=files_count,
                                            x_file=x_file)
                    logger.debug(log_msg)
                    x_oid = oid_getter(x_path)
                    if not x_oid:
                        continue
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="host_inventory",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["conf_result"],
                            object_cache=256,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'host_uuid'])
    # Register index attributes.
    inventory_types = ["host_inventory"]
    # Which host this inventory is of. A config result names its host
    # as well, see conf_result.py.
    config.register_index_attribute('host_uuid', sync=[],
                                    object_types=inventory_types)
    config.register_index_attribute('package', sync=[],
                                    object_types=inventory_types)
    # The hardware, one attribute per field. Only what is worth
    # searching, the rest is read off the object.
    for x_attribute in HARDWARE_INDEX_ATTRIBUTES:
        config.register_index_attribute(x_attribute, sync=[],
                                        object_types=inventory_types)
    # What a host reported about itself to its own site.
    config.register_index_attribute('last_inventory_update', sync=[],
                                    object_types=inventory_types)
    # Register object to backend.
    class_getter = lambda: HostInventory
    backend.register_object_type(object_type="host_inventory",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

@match_class_typing
class HostInventory(OTPmeDataObject):
    """ The installed packages of one host. """
    def __init__(
        self,
        host_uuid: Union[str,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "host_inventory"
        self.host_uuid = host_uuid
        self.hardware = {}
        self.last_inventory_update = None
        # Call parent class init.
        super().__init__(object_id=object_id, **kwargs)
        if object_id:
            self.host_uuid = object_id.host_uuid
        # No _sync_fields: the object goes to the nodes of our own site
        # through the cluster and to nobody else, see
        # register_sync_settings().

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'HOST_UUID'                 : {
                                                        'var_name'  : 'host_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        # Not incremental: it is replaced whole every
                        # time a host reports (update_hardware()), so
                        # there is no difference to carry. Incremental
                        # would also hand the value out wrapped in an
                        # IncrementalDict, which does not serialize --
                        # and the checksum of it is JSON.
                        'HARDWARE'                  : {
                                                        'var_name'      : 'hardware',
                                                        'type'          : dict,
                                                        'incremental'   : False,
                                                        'required'      : False,
                                                    },
                        'LAST_INVENTORY_UPDATE'     : {
                                                        'var_name'  : 'last_inventory_update',
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
                            host_uuid=self.host_uuid)

    @property
    def packages(self):
        """ The installed packages: {name: version}.

        Neither a package name nor a version contains a "=", so the
        first one splits them. """
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

        <set_packages> are new, or have another version now; the names
        in <del_packages> are gone. """
        packages = self.packages
        for name in del_packages or []:
            version = packages.get(name)
            if version is None:
                continue
            self.del_index("package", f"{name}={version}")
        for name, version in (set_packages or {}).items():
            old_version = packages.get(name)
            if old_version == version:
                continue
            if old_version is not None:
                self.del_index("package", f"{name}={old_version}")
            self.add_index("package", f"{name}={version}")
        self.touch_inventory()

    def update_hardware(self, hardware):
        """ Replace the hardware. Written by the caller.

        Whole, not by difference: it is a dozen values, and a host that
        got a second disk says so by sending all of them again. What is
        worth searching goes into the index as well, the rest stays in
        the object.
        """
        hardware = dict(hardware or {})
        for index_attribute in HARDWARE_INDEX_ATTRIBUTES:
            self.del_index(index_attribute)
        for name, index_attribute in HARDWARE_INDEX_FIELDS.items():
            value = hardware.get(name)
            if value is None:
                continue
            self.add_index(index_attribute, value)
        for disk in hardware.get("disks") or []:
            disk_name = disk.get("name")
            disk_size = disk.get("size")
            if disk_name is None or disk_size is None:
                continue
            self.add_index(HARDWARE_DISK_ATTRIBUTE, f"{disk_name}={disk_size}")
            self.add_index(HARDWARE_DISK_SIZE_ATTRIBUTE, disk_size)
        self.hardware = hardware
        self.touch_inventory()

    def touch_inventory(self):
        """ Note that the host reported just now. """
        self.last_inventory_update = time.time()
        self.update_index("last_inventory_update", int(self.last_inventory_update))

    def add(self, **kwargs):
        """ Add the object. """
        self.add_index('host_uuid', self.host_uuid)
        # Call base class add method.
        return super().add(**kwargs)
