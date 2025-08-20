# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import filetools
from otpme.lib.pidfile import pidfile_handler

from otpme.lib.exceptions import *

LOCK_TYPE = "nsscache"
UPDATE_EXT = "update"
REMOVE_EXT = "remove"

locking.register_lock_type(LOCK_TYPE, module=__file__)

valid_actions = {
                'update' : UPDATE_EXT,
                'remove' : REMOVE_EXT,
                }

# nsscache files we link to /etc/ on realm join.
NSSCACHE_FILES = [
            'group.cache',
            'group.cache.ixgid',
            'group.cache.ixname',
            'passwd.cache',
            'passwd.cache.ixname',
            'passwd.cache.ixuid',
            'shadow.cache',
            'shadow.cache.ixname',
            'shadow.cache.ixuid',
            ]

# Object types that will be added to nsscache.
NSSCACHE_ADD_ORDER = [ 'user', 'group' ]
NSSCACHE_OBJECT_TYPES = {
                        'user' : {
                                'realm_uniq' : True,
                                },
                        'group' : {
                                'realm_uniq' : True,
                                },
                        'role' : {
                                'realm_uniq' : False,
                                },
                        }

def get_last_synced_revision():
    if not os.path.exists(config.nsscache_sync_file):
        return
    # Get logger.
    logger = config.logger
    try:
        last_synced_revision = filetools.read_file(config.nsscache_sync_file)
    except Exception as e:
        msg = "Failed to read last synced revision: %s" % e
        logger.warning(msg)
        return
    try:
        last_synced_revision = float(last_synced_revision)
    except Exception as e:
        msg = "Invalid revision format, should be float: %s" % e
        logger.warning(msg)
        return
    return last_synced_revision

def set_last_synced_revision(last_synced_revision):
    # Get logger.
    logger = config.logger
    try:
        filetools.create_file(path=config.nsscache_sync_file,
                            content=str(last_synced_revision))
    except Exception as e:
        msg = "Failed to read last synced revision: %s" % e
        logger.warning(msg)
        return
    return last_synced_revision

def gen_cachefile_path(object_id, action):
    """ Generate cache file path. """
    if action not in valid_actions:
        msg = "Invalid action: %s" % action
        raise OTPmeException(msg)
    path = "%s/%s.%s" % (config.nsscache_objects_dir,
                        object_id.full_oid.replace("/", "+"),
                        action)
    return path

def update_sync_map(lock=None, syncing=False):
    """
    Update checksum in sync map to indicate that local nsscache is up-to-date.
    """
    from otpme.lib import backend
    from otpme.lib.protocols.server.sync1 import add_sync_list_checksum
    # Get logger.
    logger = config.logger

    if lock is None:
        lock = locking.OTPmeFakeLock(lock_type=LOCK_TYPE, lock_id="fake")

    all_sites = backend.search(object_type="site",
                                attribute="uuid",
                                value="*",
                                realm=config.realm,
                                return_type="instance")
    # Get users to skip.
    skip_users = list(config.get_internal_objects("user"))
    # Get object types to sync.
    try:
        host_type = config.host_data['type']
    except:
        return
    object_types = config.get_sync_object_types(host_type)

    for x in all_sites:
        # Skip disabled sites.
        if not x.enabled:
            continue
        # Set "syncing" status.
        if syncing:
            try:
                reply = add_sync_list_checksum(realm=x.realm,
                                            site=x.name,
                                            peer_realm=config.realm,
                                            peer_site=config.site,
                                            skip_admin=False,
                                            skip_users=skip_users,
                                            object_types=object_types,
                                            checksum=config.SYNCING_STATUS_STRING)
                exception = None
            except OTPmeException as e:
                exception = str(e)
            if exception:
                logger.warning(exception)
            else:
                logger.debug(reply)
            return

        # Get sync list checksum.
        sync_list, \
        sync_list_checksum = backend.get_sync_list(realm=x.realm,
                                                    site=x.name,
                                                    skip_admin=False,
                                                    skip_users=skip_users,
                                                    object_types=object_types)
        # Add sync list checksum to sync map.
        try:
            reply = add_sync_list_checksum(realm=x.realm,
                                        site=x.name,
                                        peer_realm=config.realm,
                                        peer_site=config.site,
                                        skip_admin=False,
                                        skip_users=skip_users,
                                        object_types=object_types,
                                        checksum=sync_list_checksum)
            exception = None
        except OTPmeException as e:
            exception = str(e)
        if exception:
            logger.warning(exception)
        else:
            logger.debug(reply)

def update_object(object_id, action):
    """ Add object ID to nsscache spool directory. """
    # Get logger.
    logger = config.logger
    if action not in valid_actions:
        msg = "Invalid action: %s" % action
        raise OTPmeException(msg)
    # Skip internal users.
    if object_id.object_type == "user":
        internal_users = config.get_internal_objects("user")
        if object_id.name in internal_users:
            return
    # Get file paths.
    update_file = gen_cachefile_path(object_id, UPDATE_EXT)
    remove_file = gen_cachefile_path(object_id, REMOVE_EXT)
    if action == "update":
        cache_file = update_file
        obsolete_file = remove_file
    elif action == "remove":
        cache_file = remove_file
        obsolete_file = update_file

    if os.path.exists(obsolete_file):
        msg = ("Removing obsolete spool file: %s" % obsolete_file)
        logger.debug(msg)
        try:
            filetools.delete(obsolete_file)
        except FileNotFoundError:
            pass
        except Exception as e:
            msg = "Failed to remove nsscache file: %s: %s" % (obsolete_file, e)
            logger.critical(msg)
    # Write file.
    filetools.touch(path=cache_file,
                    user=config.user,
                    group=config.group,
                    mode=0o660)

@pidfile_handler(config.nsscache_pidfile)
def update(realm, site, resync=False, cache_resync=False, lock=None):
    """ Update nsscache cache files. """
    from otpme.lib import backend
    from otpme.lib.third_party.nss_cache.maps import group
    from otpme.lib.third_party.nss_cache.maps import passwd
    from otpme.lib.third_party.nss_cache.maps import shadow
    from otpme.lib.third_party.nss_cache.caches import files
    from otpme.lib.daemon.clusterd import cluster_nsscache_sync
    # Get logger.
    logger = config.logger

    msg = "Starting sync of nsscache: %s/%s" % (realm, site)
    logger.info(msg)

    if lock is None:
        lock = locking.OTPmeFakeLock(lock_type=LOCK_TYPE, lock_id="fake")

    # Get current data revision.
    data_revision = config.get_data_revision()

    # Set "syncing" status.
    update_sync_map(lock=lock, syncing=True)

    nsscache_config = {'dir': config.nsscache_dir}
    user_cache = files.FilesPasswdMapHandler(nsscache_config)
    shadow_cache = files.FilesShadowMapHandler(nsscache_config)
    group_cache = files.FilesGroupMapHandler(nsscache_config)
    nss_cache_files = filetools.list_dir(config.nsscache_objects_dir)

    # Object types we support.
    object_types = NSSCACHE_ADD_ORDER

    # Nsscache caches we need.
    nsscache_caches = {
                            'user'      : user_cache,
                            'group'     : group_cache,
                            'shadow'    : shadow_cache,
                    }

    # Nsscache methods used to create new maps.
    nsscache_map_methods = {
                            'user'      : passwd.PasswdMap,
                            'shadow'    : shadow.ShadowMap,
                            'group'     : group.GroupMap,
                        }

    # Will hold current nsscache map entry objects (used to do incremental
    # updates)
    nsscache_current_entries = {
                            'user'  : {},
                            'group' : {},
                    }

    # Map entries for new/updated objects we got from last OTPme sync process.
    nsscache_update_entries = {
                            'user'  : {},
                            'group' : {},
                        }

    # OTPme object names of deleted objects we have to remove from nsscache.
    nsscache_remove_names = {
                            'user'  : [],
                            'group' : [],
                        }

    # Will hold the new/merged entries we will write to nsscache.
    nsscache_new_entries = {
                            'user'  : [],
                            'group' : [],
                        }

    updated_objects = {}
    removed_objects = {}
    files_to_remove = {}

    update_members = True
    if config.host_type == "host":
        update_members = False
    else:
        if not config.use_api:
            if not config.master_node:
                update_members = False
            if config.master_failover:
                update_members = False
            if not config.cluster_status:
                update_members = False

    if update_members:
        # Get roles/groups to update members of.
        counter = 0
        update_roles = []
        update_groups = []
        update_objects = len(nss_cache_files)
        for f in nss_cache_files:
            file_path = os.path.join(config.nsscache_objects_dir, f)
            x_oid = ".".join(f.split(".")[:-1]).replace("+", "/")
            x_oid = oid.get(x_oid)
            if x_oid.realm != realm:
                continue
            if x_oid.site != site:
                continue

            counter += 1
            msg = "Reading nsscache (%s/%s): %s" % (counter, update_objects, x_oid)
            logger.debug(msg)

            x_object = backend.get_object(x_oid)
            if not x_object:
                continue

            # FIXME: do we need this lines?
            #if x_object.type == "user":
            #    update_roles += x_object.get_roles(return_type="instance")
            #    update_groups += x_object.get_groups(return_type="instance")

            if x_object.type == "role":
                if x_object.site != config.site:
                    continue
                update_roles.append(x_object)
                try:
                    filetools.delete(file_path)
                except Exception as e:
                    msg = ("Failed to remove nsscache file: %s: %s"
                            % (file_path, e))
                    logger.critical(msg)

            if x_object.type == "group":
                if x_object.site != config.site:
                    continue
                update_groups.append(x_object)

        # Update group members from role members.
        updated_groups = []
        if config.host_type == "node":
            for role in set(sorted(update_roles)):
                if role.site != config.site:
                    continue
                msg = "Updating group members from role: %s" % role.oid
                logger.info(msg)
                callback = config.get_callback()
                try:
                    updated_groups += role.update_extensions("update_members",
                                                            callback=callback)[1]
                except Exception as e:
                    msg = ("Failed to update role members: %s: %s"
                            % (role.oid, e))
                finally:
                    update_objects = False
                    if config.master_node:
                        if config.cluster_status:
                            if not config.master_failover:
                                update_objects = True
                    if config.use_api:
                        update_objects = True
                    if update_objects:
                        callback.write_modified_objects()
                        callback.release_cache_locks()

            # Update group members (but not those processed by role updates above).
            for _group in set(sorted(update_groups)):
                if _group.site != config.site:
                    continue
                if _group.oid in updated_groups:
                    continue
                callback = config.get_callback()
                try:
                    _group.update_extensions("update_members",
                                            callback=callback)
                except Exception as e:
                    msg = ("Failed to update group members: %s: %s"
                            % (_group.oid, e))
                finally:
                    update_objects = False
                    if config.master_node:
                        if config.cluster_status:
                            if not config.master_failover:
                                update_objects = True
                    if config.use_api:
                        update_objects = True
                    if update_objects:
                        callback.write_modified_objects()
                        callback.release_cache_locks()
                        updated_groups.append(_group.oid)

            for x in updated_groups:
                update_file = gen_cachefile_path(x, UPDATE_EXT)
                update_file = os.path.basename(update_file)
                nss_cache_files.append(update_file)

    if cache_resync:
        for object_type in object_types:
            # If object type has a realm wide namespace we have to search
            # objects of all sites.
            if NSSCACHE_OBJECT_TYPES[object_type]['realm_uniq']:
                site = None
            else:
                site = config.site

            search_attrs = {
                            'uuid'      : {
                                        'value'     : '*',
                                        },
                            'template'  : {
                                        'value'     : False,
                                        },
                            }
            result = backend.search(realm=config.realm,
                                    site=site,
                                    object_type=object_type,
                                    attributes=search_attrs,
                                    return_type="full_oid")
            if result:
                try:
                    x_updated_objects = updated_objects[object_type]
                except:
                    x_updated_objects = []
                x_updated_objects += result
                updated_objects[object_type] = x_updated_objects
    else:
        # No spool dir, no updates ;)
        if not os.path.exists(config.nsscache_objects_dir):
            update_sync_map(lock=lock)
            msg = "No nsscache updates found."
            logger.info(msg)
            # Mark current revision as synced.
            if realm == config.realm:
                if site == config.site:
                    set_last_synced_revision(data_revision)
            return None

        for f in set(nss_cache_files):
            action = f.split(".")[-1]
            if action not in valid_actions:
                continue
            full_oid = ".".join(f.split(".")[:-1]).replace("+", "/")
            object_id = oid.get(full_oid)
            object_type = object_id.object_type
            if object_id.realm != realm:
                continue
            if object_id.site != site:
                continue

            file_path = os.path.join(config.nsscache_objects_dir, f)
            try:
                files_to_remove[file_path] = os.path.getmtime(file_path)
            except FileNotFoundError:
                continue

            if object_type == "role":
                try:
                    filetools.delete(file_path)
                except Exception as e:
                    msg = "Failed to remove nsscache file: %s: %s" % (file_path, e)
                    logger.warning(msg)
                continue

            if action == "update":
                try:
                    x_updated_objects = updated_objects[object_type]
                except:
                    x_updated_objects = []
                x_updated_objects.append(full_oid)
                updated_objects[object_type] = x_updated_objects

            if action == "remove":
                try:
                    x_removed_objects = removed_objects[object_type]
                except:
                    x_removed_objects = []
                x_removed_objects.append(object_id)
                removed_objects[object_type] = x_removed_objects

    if len(updated_objects) + len(removed_objects) == 0:
        update_sync_map(lock=lock)
        msg = "No nsscache updates found."
        logger.info(msg)
        # Mark current revision as synced.
        if realm == config.realm:
            if site == config.site:
                set_last_synced_revision(data_revision)
        return None

    object_count = 0
    object_attributes = {}
    for object_type in updated_objects:
        object_oids = updated_objects[object_type]
        if object_type == "user":
            return_attrs = [
                            'name',
                            'full_oid',
                            'extension',
                            'ldif:cn',
                            'ldif:uidNumber',
                            'ldif:gidNumber',
                            'ldif:loginShell',
                            'ldif:homeDirectory',
                            ]
        if object_type == "group":
            return_attrs = [
                            'name',
                            'full_oid',
                            'extension',
                            'ldif:gidNumber',
                            'ldif:memberUid',
                            ]
        # Get objects.
        result = backend.search(object_type=object_type,
                                attribute="full_oid",
                                values=object_oids,
                                return_attributes=return_attrs)
        object_attributes[object_type] = result
        object_count += len(result)

    counter = 0
    for object_type in object_attributes:
        object_attrs = object_attributes[object_type]
        # Create map entries for new/updated objects.
        for uuid in object_attrs:
            counter += 1
            try:
                extensions = object_attrs[uuid]['extension']
            except:
                extensions = []
            if "posix" not in extensions:
                continue
            # Get OID and type.
            full_oid = object_attrs[uuid]['full_oid']
            object_id = oid.get(full_oid)
            object_type = object_id.object_type
            # Skip unsupported objects.
            if not object_type in object_types:
                continue
            # Skip objects from other sites which do not have a realm wide uniq
            # name.
            if not NSSCACHE_OBJECT_TYPES[object_type]['realm_uniq']:
                object_site = object_id.site
                if object_site != config.site:
                    continue
            # Get object name.
            object_name = object_attrs[uuid]['name']
            msg = ("Processing nsscache (%s/%s): %s"
                % (counter, object_count, object_id))
            logger.debug(msg)
            shadow_map_entry = None
            if object_type == "user":
                try:
                    cn = object_attrs[uuid]['ldif:cn'][0]
                except:
                    cn = ''
                try:
                    uidnumber = object_attrs[uuid]['ldif:uidNumber'][0]
                except:
                    msg = ("Cannot create nsscache map: Object is missing "
                            "uidNumber: %s" % full_oid)
                    logger.warning(msg)
                    continue
                try:
                    gidnumber = object_attrs[uuid]['ldif:gidNumber'][0]
                except:
                    msg = ("Cannot create nsscache map: Object is missing "
                            "gidNumber: %s" % full_oid)
                    logger.warning(msg)
                    continue
                try:
                    homedir = object_attrs[uuid]['ldif:homeDirectory'][0]
                except:
                    msg = ("Cannot create nsscache map: Object is missing "
                            "homeDirectory: %s" % full_oid)
                    logger.warning(msg)
                    continue
                try:
                    loginshell = object_attrs[uuid]['ldif:loginShell'][0]
                except:
                    msg = ("Cannot create nsscache map: Object is missing "
                            "loginShell: %s" % full_oid)
                    logger.warning(msg)
                    continue
                # Gen passwd entry.
                map_entry = passwd.PasswdMapEntry()
                map_entry.name = object_name
                map_entry.passwd = 'x'
                map_entry.uid = uidnumber
                map_entry.gid = gidnumber
                map_entry.gecos = cn
                map_entry.dir = homedir
                map_entry.shell = loginshell
                # Gen shadow entry.
                shadow_map_entry = shadow.ShadowMapEntry()
                shadow_map_entry.name = object_name
                shadow_map_entry.passwd = "*"
                #shadow_map_entry.lstchg = int(nss_entry[2])
                #shadow_map_entry.min = int(nss_entry[3])
                #shadow_map_entry.max = int(nss_entry[4])
                #shadow_map_entry.warn = int(nss_entry[5])
                #shadow_map_entry.inact = int(nss_entry[6])
                #shadow_map_entry.expire = int(nss_entry[7])
                #shadow_map_entry.flag = int(nss_entry[8])

            if object_type == "group":
                try:
                    gidnumber = object_attrs[uuid]['ldif:gidNumber'][0]
                except Exception as e:
                    msg = ("Cannot create nsscache map: Object is missing "
                            "gidNumber: %s" % full_oid)
                    logger.warning(msg)
                    continue
                try:
                    group_members = object_attrs[uuid]['ldif:memberUid']
                except:
                    group_members = None
                # Gen group entry.
                map_entry = group.GroupMapEntry()
                map_entry.name = object_name
                map_entry.passwd = 'x'
                map_entry.gid = gidnumber
                if group_members is not None:
                    map_entry.members = group_members
            nsscache_update_entries[object_type][map_entry.name] = (map_entry, shadow_map_entry)

    # Counters for log message.
    nsscache_adds = 0
    nsscache_updates = 0
    nsscache_removes = 0

    if resync or cache_resync:
        for object_type in object_types:
            for name in sorted(nsscache_update_entries[object_type]):
                logger.debug("Adding %s to nsscache: %s" % (object_type, name))
                entry = nsscache_update_entries[object_type][name]
                nsscache_new_entries[object_type].append(entry)
                nsscache_adds += 1
    else:
        # Get object names of removed objects.
        del_order = reversed(config.object_add_order)
        for object_type in del_order:
            try:
                oids = removed_objects[object_type]
            except:
                continue
            for object_id in oids:
                object_type = object_id.object_type
                # Skip objects from other sites which do not have a realm wide uniq
                # name.
                if not NSSCACHE_OBJECT_TYPES[object_type]['realm_uniq']:
                    object_site = object_id.site
                    if object_site != config.site:
                        continue
                object_name = object_id.name
                nsscache_remove_names[object_type].append(object_name)

        # Get current map entries.
        for object_type in object_types:
            current_map = nsscache_caches[object_type].GetMap()
            for entry in current_map:
                nsscache_current_entries[object_type][entry.name] = (entry,)

        for object_type in object_types:
            update_needed = False
            # Handle removed entries.
            for name in sorted(nsscache_remove_names[object_type]):
                if name not in nsscache_current_entries[object_type]:
                    #msg = ("Deleted OTPme object is missing in nsscache: "
                    #        "%s: %s" % (object_type, name))
                    #logger.warning(msg)
                    continue
                update_needed = True
                msg = ("Removing %s from nsscache: %s" % (object_type, name))
                logger.debug(msg)
                nsscache_removes += 1
                nsscache_current_entries[object_type].pop(name)

            # Remove non existing users from updated groups.
            if config.host_type == "host":
                if object_type == "group":
                    for group_name in nsscache_update_entries[object_type]:
                        entry = nsscache_update_entries[object_type][group_name][0]
                        local_users = backend.search(object_type="user",
                                                    attribute="uuid",
                                                    value="*",
                                                    return_type="name")
                        for x_uid in list(entry.members):
                            if x_uid in local_users:
                                continue
                            entry.members.remove(x_uid)

            # Handle new/updated entries.
            for name in sorted(nsscache_update_entries[object_type]):
                x_entries = nsscache_update_entries[object_type][name]
                x_entry = x_entries[0]
                try:
                    current_entry = nsscache_current_entries[object_type][x_entry.name][0]
                except KeyError:
                    current_entry = None
                if current_entry == x_entry:
                    msg = "No update required for %s: %s" % (object_type, name)
                    logger.debug(msg)
                    continue
                update_needed = True
                if name in nsscache_current_entries[object_type]:
                    msg = ("Updating %s in nsscache: %s" % (object_type, name))
                    logger.debug(msg)
                    nsscache_updates += 1
                else:
                    msg = ("Adding %s to nsscache: %s" % (object_type, name))
                    logger.debug(msg)
                    nsscache_adds += 1
                nsscache_current_entries[object_type][x_entry.name] = x_entries

            if update_needed:
                # We need merged entries in nsscache_new_entries.
                for name in nsscache_current_entries[object_type]:
                    entry = nsscache_current_entries[object_type][name][0]
                    nsscache_new_entries[object_type].append((entry,))

    # Actually create new/merged maps and write them to nsscache.
    for object_type in object_types:
        entries = nsscache_new_entries[object_type]
        cache = nsscache_caches[object_type]
        # Remove file if no objects exist for this cache.
        if len(entries) == 0:
            if resync or cache_resync:
                cache_file = cache.GetCacheFilename()
                if os.path.exists(cache_file):
                    try:
                        filetools.delete(cache_file)
                    except Exception as e:
                        msg = ("Failed to remove nsscache file: %s: %s"
                                % (cache_file, e))
                        logger.critical(msg)
            continue
        map_entries = []
        shadow_entries = []
        for x in entries:
            map_entry = x[0]
            try:
                shadow_entry = x[1]
            except IndexError:
                shadow_entry = None
            map_entries.append(map_entry)
            if shadow_entry:
                shadow_entries.append(shadow_entry)
        map_method = nsscache_map_methods[object_type]
        new_map = map_method(map_entries)
        logger.debug("Writing nsscache: %s" % object_type)
        cache.Write(new_map)
        cache.WriteIndex()
        cache._Commit()
        if shadow_entries:
            map_method = nsscache_map_methods['shadow']
            new_map = map_method(shadow_entries)
            shadow_cache = nsscache_caches['shadow']
            logger.debug("Writing nsscache (shadow): %s" % object_type)
            shadow_cache.Write(new_map)
            shadow_cache.WriteIndex()
            shadow_cache._Commit()

    # Set cache file ownership.
    for x in os.listdir(config.nsscache_dir):
        cache_file = os.path.join(config.nsscache_dir, x)
        filetools.set_fs_ownership(path=cache_file,
                                user=config.user,
                                group=config.group)

    if nsscache_adds > 0 or nsscache_updates > 0 or nsscache_removes > 0:
        cluster_nsscache = True
        msg = ("Updated nsscache: adds: %s updates: %s removes: %s"
                % (nsscache_adds, nsscache_updates, nsscache_removes))
        logger.info(msg)
    else:
        cluster_nsscache = False
        msg = "No nsscache update needed."
        logger.info(msg)

    # Inform hostd that we are in sync again.
    update_sync_map(lock=lock)

    # Remove cache files.
    for file_path in files_to_remove:
        if not os.path.exists(file_path):
            continue
        old_mtime = files_to_remove[file_path]
        try:
            new_mtime = os.path.getmtime(file_path)
        except FileNotFoundError:
            continue
        if new_mtime != old_mtime:
            continue
        try:
            filetools.delete(file_path)
        except Exception as e:
            msg = "Failed to remove nsscache file: %s: %s" % (file_path, e)
            logger.critical(msg)

    if config.host_data['type'] == "node":
        if not config.master_node:
            cluster_nsscache = False
        if cluster_nsscache:
            cluster_nsscache_sync()

    # Mark current revision as synced.
    if realm == config.realm:
        if site == config.site:
            set_last_synced_revision(data_revision)

    return True

def enable():
    """ Create OTPme nsscache symlinks. """
    # Get logger.
    logger = config.logger
    nsscache_links = {}
    for x in NSSCACHE_FILES:
        link_src = "%s/%s" % (config.nsscache_dir, x)
        link_dst = "/etc/%s" % x
        if os.path.exists(link_dst) \
        or os.path.islink(link_dst):
            curr_src = os.path.realpath(link_dst)
            if curr_src != link_src:
                msg = (_("Cannot enable OTPme nsscache configuration: File "
                        "exists: %s") % link_dst)
                raise OTPmeException(msg)
        else:
            nsscache_links[link_src] = link_dst

    for link_src in nsscache_links:
        link_dst = nsscache_links[link_src]
        logger.debug("Creating symlink: %s -> %s" % (link_src, link_dst))
        os.symlink(link_src, link_dst)

def disable():
    """ Remove OTPme nsscache symlinks. """
    # Get logger.
    logger = config.logger
    for x in NSSCACHE_FILES:
        link_src = "%s/%s" % (config.nsscache_dir, x)
        link_dst = "/etc/%s" % x
        if not os.path.islink(link_dst):
            continue
        curr_src = os.path.realpath(link_dst)
        if curr_src != link_src:
            continue
        logger.debug("Removing symlink: %s -> %s"
                    % (link_src, link_dst))
        os.remove(link_dst)
