# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import json
import pprint
from typing import List
from typing import Union
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import otpme_acl
from otpme.lib import multiprocessing
from otpme.lib.cache import ldif_cache
#from otpme.lib.locking import oid_lock
from otpme.lib.cache import search_cache
from otpme.lib.typing import match_typing
from otpme.lib.cache import ldap_search_cache
from otpme.lib.job.callback import JobCallback
from otpme.lib.classes.object_config import ObjectConfig

from otpme.lib.exceptions import *

#OID_LOCK_TYPE = "oid"
SYNC_MAP_LOCK_TYPE = "sync_map"

#locking.register_lock_type(OID_LOCK_TYPE, module=__file__)
locking.register_lock_type(SYNC_MAP_LOCK_TYPE, module=__file__)

multiprocessing.register_shared_dict("sync_map")
multiprocessing.register_shared_dict("instance_cache_read_times")
multiprocessing.register_shared_list("sync_map_cache_clear_queue")

default_callback = config.get_callback()

_index = config.get_index_module()
drop = getattr(_index, "drop")
command = getattr(_index, "command")
is_available = getattr(_index, "is_available")

from otpme.lib.backends.file.file import read
from otpme.lib.backends.file.file import write
from otpme.lib.backends.file.file import rename
from otpme.lib.backends.file.file import delete
from otpme.lib.backends.file.file import get_oid
from otpme.lib.backends.file.file import get_uuid
from otpme.lib.backends.file.file import index_dump
from otpme.lib.backends.file.file import index_restore
from otpme.lib.backends.file.file import index_search
from otpme.lib.backends.file.file import object_exists
from otpme.lib.backends.file.file import get_last_used
from otpme.lib.backends.file.file import set_last_used
from otpme.lib.backends.file.file import set_last_used_times
from otpme.lib.backends.file.file import get_last_used_times
from otpme.lib.backends.file.file import clear_index_caches
from otpme.lib.backends.file.file import register_object_type as _register_object_type

# Imports to be used by other modules.
from otpme.lib.backends.file.file import index_add
from otpme.lib.backends.file.file import index_del
from otpme.lib.backends.file.file import index_get
from otpme.lib.backends.file.file import get_data_dir
from otpme.lib.backends.file.file import get_site_dir
from otpme.lib.backends.file.file import get_object_dir
from otpme.lib.backends.file.file import get_unit_fs_path
from otpme.lib.backends.file.file import get_config_paths
from otpme.lib.backends.file.file import register_data_dir
from otpme.lib.backends.file.file import config_path_getter
from otpme.lib.backends.file.file import register_object_dir
from otpme.lib.backends.file.file import rebuild_object_index
from otpme.lib.backends.file.file import get_object_path_settings
from otpme.lib.backends.file.transaction import transaction
from otpme.lib.backends.file.transaction import get_transaction
from otpme.lib.backends.file.transaction import end_transaction
from otpme.lib.backends.file.transaction import begin_transaction
from otpme.lib.backends.file.transaction import abort_transaction
from otpme.lib.backends.file.transaction import replay_transactions
from otpme.lib.backends.file.transaction import get_file_transactions
from otpme.lib.backends.file.transaction import get_object_transactions

object_type_map = {}

def init(*args, **kwargs):
    from otpme.lib.backends.file.file import init
    return init(*args, **kwargs)

def atfork():
    from otpme.lib.backends.file.file import atfork
    return atfork()

def cleanup():
    from otpme.lib.backends.file.file import cleanup
    return cleanup()

def handle_daemon_shutdown():
    """ Decorator to handle daemon shutdown behavior. """
    def wrapper(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if config.daemon_shutdown:
                os._exit(0)
            result = func(*args, **kwargs)
            return result
        return wrapped
    return wrapper

@match_typing
def register_object_type(
    object_type: str,
    class_getter: object=None,
    class_getter_args: dict=None,
    tree_object: bool=True,
    path_getter: object=None,
    oid_getter: object=None,
    index_rebuild_func: object=None,
    dir_name_extension: str=None
    ):
    """ Register object type to be created by get_object(). """
    global object_type_map

    if object_type in object_type_map:
        msg = "Object type already registered: %s" % object_type
        raise OTPmeException(msg)

    try:
        class_config = object_type_map[object_type]
    except:
        class_config = {}

    if class_config:
        msg = "Object already registered."
        raise OTPmeException(msg)

    # Add object class config.
    class_config = {
        'class_getter'  : class_getter,
        'getter_args'   : class_getter_args,
        }
    object_type_map[object_type] = class_config
    # Register for file backend.
    if path_getter:
        _register_object_type(object_type=object_type,
                            tree_object=tree_object,
                            path_getter=path_getter,
                            oid_getter=oid_getter,
                            index_rebuild_func=index_rebuild_func,
                            dir_name_extension=dir_name_extension)

@match_typing
def get_class_getter(object_type: str):
    """ Get object class getter by type. """
    try:
        getter_args = object_type_map[object_type]['getter_args']
    except KeyError:
        getter_args = None
    try:
        class_getter = object_type_map[object_type]['class_getter']
    except KeyError:
        return
    return class_getter, getter_args

# xxxxxxxxxxxxxxxxxxxx
# FIXME: add parameter "cache_object=False" to prevent object from beeing cached!?
#@oid_lock(args_oid_pos=[0])
@match_typing
def read_config(
    object_id: oid.OTPmeOid,
    parameters: list=[],
    checksum_only: bool=False,
    decrypt: bool=True
    ):
    """ Read object config from backend. """
    # Get logger.
    logger = config.logger
    # Replay any leftover transaction.
    replay_transactions()
    object_config = None
    # Get objects read OID.
    read_oid = object_id.read_oid
    #object_type = object_id.object_type

    if decrypt and not config.master_key:
        if config.uuid:
            msg = ("Missing AES master key. Unable to decrypt config data.")
            logger.warning(msg)
        return

    # If we got no object_config from cache try to read from backend.
    if config.debug_level("backend_reads") > 0:
        data_type = "data"
        if checksum_only:
            data_type = "checksum"
        msg = ("Reading object (%(data_type)s) from backend: %(read_oid)s"
                % {"data_type":data_type, "read_oid":read_oid})
        logger.debug(msg)

    if checksum_only:
        # Read only objects checksum from backend if it does not exists in
        # checksum cache.
        try:
            object_config = read(object_id, parameters=['CHECKSUM','SYNC_CHECKSUM'])
        except Exception as e:
            config.raise_exception()
            msg = ("Failed to read config (checksum) from backend: %s: %s"
                    % (object_id, e))
            logger.critical(msg, exc_info=True)
            return
        return object_config

    # Read object config from backend. The read() function from backend
    # must return None if object does not exist.
    try:
        object_config = read(object_id, parameters=parameters)
    except Exception as e:
        msg = ("Failed to read config from backend: %s: %s"
                % (object_id, e))
        logger.critical(msg, exc_info=True)
        return

    if not object_config:
        return

    # Decrypt object config.
    if decrypt:
        object_config = ObjectConfig(object_id, object_config)
        object_config.decrypt(config.master_key)

    return object_config

@match_typing
@handle_daemon_shutdown()
#@oid_lock(args_oid_pos=[0], write=True)
def write_config(
    object_id: oid.OTPmeOid,
    instance: object=None,
    object_config: dict=None,
    cluster: bool=False,
    wait_for_cluster_writes: bool=False,
    full_index_update: bool=False,
    full_data_update: bool=False,
    full_ldif_update: bool=False,
    full_acl_update: bool=False,
    index_journal: Union[List,None]=[],
    ldif_journal: Union[List,None]=[],
    acl_journal: Union[List,None]=[],
    use_index_journal: bool=False,
    use_ldif_journal: bool=False,
    use_acl_journal: bool=False,
    no_transaction: bool=False,
    encrypt: bool=True,
    **kwargs
    ):
    """ Write object config to backend and update config cache. """
    # Get logger.
    logger = config.logger
    if not config.master_key:
        msg = "Missing AES master key. Unable to encrypt config data."
        logger.critical(msg)
        raise OTPmeException(msg)
    if full_index_update and index_journal:
        msg = "You can use only one of <full_index_update> or <index_journal>."
        raise OTPmeException(msg)
    if full_acl_update and acl_journal:
        msg = "You can use only one of <full_acl_update> or <acl_journal>."
        raise OTPmeException(msg)
    if full_ldif_update and ldif_journal:
        msg = "You can use only one of <full_ldif_update> or <ldif_journal>."
        raise OTPmeException(msg)

    # Replay any leftover transaction.
    replay_transactions()

    # Get config from instance.
    if instance is not None:
        object_config = instance.object_config
    else:
        object_config = ObjectConfig(object_id, object_config, encrypted=False)

    # Encrypt object config and update checksums.
    if encrypt:
        object_config = object_config.encrypt(config.master_key)
    else:
        object_config = object_config.copy()

    # Write config file.
    write_status = write(object_id=object_id,
                    object_config=object_config,
                    acl_journal=acl_journal,
                    ldif_journal=ldif_journal,
                    index_journal=index_journal,
                    full_index_update=full_index_update,
                    full_data_update=full_data_update,
                    full_ldif_update=full_ldif_update,
                    full_acl_update=full_acl_update,
                    use_index_journal=use_index_journal,
                    use_ldif_journal=use_ldif_journal,
                    use_acl_journal=use_acl_journal,
                    no_transaction=no_transaction,
                    wait_for_cluster_writes=wait_for_cluster_writes,
                    cluster=cluster,
                    **kwargs)
    # Update config cache.
    if write_status:
        # With an active transaction the object gets outdated
        # on successful commit.
        _transaction = get_transaction()
        if _transaction is None:
            # Make sure object is outdated in caches.
            outdate_object(object_id)

    return write_status

@match_typing
@handle_daemon_shutdown()
#@oid_lock(args_oid_pos=[0, 1], write=True)
def rename_object(
    object_id: oid.OTPmeOid,
    new_object_id: oid.OTPmeOid,
    no_transaction: bool=False,
    cluster: bool=False
    ):
    """ Rename object. """
    # Replay any leftover transaction.
    replay_transactions()
    # Rename object in backend.
    rename(object_id,
            new_object_id,
            no_transaction=no_transaction,
            cluster=cluster)
    # Outdate object.
    outdate_object(object_id, cache_type="all")
    return True

@match_typing
@handle_daemon_shutdown()
#@oid_lock(args_oid_pos=[0], write=True)
def delete_object(
    object_id: oid.OTPmeOid,
    no_transaction: bool=False,
    cluster: bool=False
    ):
    """ Delete object. """
    # Replay any leftover transaction.
    replay_transactions()
    # Get objects UUID before deleting from backend.
    object_uuid = get_uuid(object_id)
    if object_uuid == config.realm_uuid:
        raise Exception("Cannot delete own realm.")
    if object_uuid == config.site_uuid:
        raise Exception("Cannot delete own site.")
    if not index_get(object_id):
        if not object_exists(object_id):
            msg = "Unknown object: %s" % object_id
            raise UnknownObject(msg)
    # Remove object from backend.
    delete(object_id, no_transaction=no_transaction, cluster=cluster)
    # Outdate object.
    outdate_object(object_id, cache_type="all")
    return True

@match_typing
def outdate_object(object_id: oid.OTPmeOid, cache_type: Union[str,None]=None):
    """ Outdate object in caches, sync list etc. """
    object_site = object_id.site
    object_realm = object_id.realm
    object_type = object_id.object_type
    object_uuid = get_uuid(object_id)

    # Clear OID from cache. Cache type None just clears
    # the checksum cache.
    cache.clear(object_id, cache_type=cache_type)
    # Clear search cache.
    search_cache.invalidate()
    if object_type in config.tree_object_types:
        # Clear ldif cache.
        ldif_cache.invalidate()
        # Clear LDAP cache.
        ldap_search_cache.invalidate()

    if object_type == "realm" or object_type == "site":
        # Clear sync map for all sites.
        outdate_sync_map()
    elif object_realm and object_site:
        # Clear sync map for objects realm/site.
        outdate_sync_map(realm=object_realm,
                        site=object_site,
                        object_types=[object_type])
    # Clear ACL cache.
    if object_uuid:
        cache.outdate_acl_cache(object_uuid=object_uuid)

    # Make sure we notify ldapd about changed objects (e.g. clear ldap search cache).
    if config.daemon_mode:
        if config.get_ldap_settings(object_type):
            config.ldap_object_changed = True

@match_typing
def import_config(
    object_config: dict,
    object_id: oid.OTPmeOid=None,
    force: bool=False,
    aes_key: str=None,
    callback: JobCallback=default_callback,
    **kwargs
    ):
    """ Import object config. """
    if not object_id:
        # Try to get object ID.
        try:
            object_id = object_config['OID']
        except:
            object_id = None

    if not object_id:
        return callback.error("Missing OID. Import failed.")

    # Detect duplicate UUIDs
    try:
        object_uuid = object_config['UUID']
    except:
        object_uuid = None

    if object_uuid:
        x = get_object(uuid=object_uuid)
        if x and x.oid != object_id:
            msg = (_("UUID conflict: %(object_id)s <> %(xoid)s")
                    % {"object_id":object_id, "xoid":x.oid})
            return callback.error(msg)

    # Get OID.
    if not object_id or not isinstance(object_id, oid.OTPmeOid):
        object_id = oid.get(object_id=object_id)

    if not force:
        if object_exists(object_id):
            msg = (_("Object '%(object_id)s' already exists. "
                    "Override?: ") % {"object_id":object_id})
            answer = callback.ask(msg)
            if answer.lower() != "y":
                return callback.abort()
            # Delete object we will override.
            delete(object_id)

    # Decrypt object config.
    object_config = ObjectConfig(object_id, object_config)
    object_config.decrypt(aes_key)
    # Remove OID from object config before import.
    object_config.pop("OID")

    # Write object config to backend.
    try:
        write_config(object_id=object_id,
                    object_config=object_config,
                    cluster=True)
    except:
        config.raise_exception()
        return callback.error("Error writing object config.")

    return callback.ok()

@match_typing
def get_checksum(object_id: oid.OTPmeOid):
    """ Get object checksum. """
    checksum = None
    read_oid = object_id.read_oid
    object_type = object_id.object_type
    # Try to get checksum from index.
    result = search(attribute="read_oid",
                    value=read_oid,
                    object_type=object_type,
                    return_type="checksum")
    if result:
        checksum = result[0]

    if not checksum:
        # Try to get checksum from object config.
        object_config = read_config(object_id=object_id, checksum_only=True)
        if object_config:
            checksum = object_config['CHECKSUM']

    return checksum

@match_typing
def get_sync_checksum(object_id: oid.OTPmeOid):
    """ Get object sync checksum. """
    sync_checksum = None
    read_oid = object_id.read_oid
    object_type = object_id.object_type
    # Try to get sync checksum from index.
    result = search(attribute="read_oid",
                    value=read_oid,
                    object_type=object_type,
                    return_type="sync_checksum")
    if result:
        sync_checksum = result[0]

    if not sync_checksum:
        # Try to get sync checksum from object config.
        object_config = read_config(object_id=object_id, checksum_only=True)
        if object_config:
            sync_checksum = object_config['SYNC_CHECKSUM']

    return sync_checksum

def dump_sync_map():
    """ Dump sync map. """
    data = multiprocessing.sync_map.copy()
    dump_data = pprint.pformat(data)
    return dump_data

@match_typing
def get_sync_map_lock(sync_map_id: str, timeout: Union[int,None]=None):
    """ Acquire sync map lock. """
    lock_id = "sync_map:%s" % sync_map_id
    lock = locking.acquire_lock(lock_type=SYNC_MAP_LOCK_TYPE,
                                lock_id=lock_id,
                                timeout=timeout)
    return lock

@match_typing
def add_sync_map(
    realm: str,
    site: str,
    peer_realm: str,
    peer_site: str,
    checksum: str,
    object_types: List
    ):
    """ Add sync list checksum to sync map. """
    sync_map_id = ("site:%s/%s" % (peer_realm, peer_site))
    # Acquire sync map lock.
    sync_map_lock = get_sync_map_lock(sync_map_id)

    # Get site/node entry from sync map.
    try:
        map_entry = multiprocessing.sync_map[sync_map_id]
        map_entry = map_entry.copy()
    except:
        map_entry = {}

    if realm not in map_entry:
        map_entry[realm] = {}

    # Update map entry.
    map_entry[realm][site] = {
                                'time'          : time.time(),
                                'checksum'      : checksum,
                                'object_types'  : object_types,
                            }
    # Update sync map entry.
    multiprocessing.sync_map[sync_map_id] = map_entry
    # Release sync lock.
    sync_map_lock.release_lock()

@match_typing
def get_sync_map(
    realm: str,
    site: str,
    peer_realm: str,
    peer_site: str,
    timeout: Union[int,None]=None
    ):
    """ Get sync list checksum from sync map. """
    sync_map_id = ("site:%s/%s" % (peer_realm, peer_site))
    # Acquire sync lock.
    sync_map_lock = get_sync_map_lock(sync_map_id, timeout=timeout)

    # Remove outdated sync maps from cache.
    clear_outdated_sync_maps()

    # Get site/node entry from sync map.
    try:
        map_entry = multiprocessing.sync_map[sync_map_id].copy()
    except:
        map_entry = {}
    # Get sync list checksum.
    try:
        sync_list_checksum = map_entry[realm][site]['checksum']
    except:
        sync_list_checksum = None

    # Release sync lock.
    sync_map_lock.release_lock()

    return sync_list_checksum

@match_typing
def outdate_sync_map(
    realm: str=None,
    site: str=None,
    object_types: List=None
    ):
    """ Make sure sync maps that include one of object_types are cleared. """
    if site:
        if not realm:
            raise Exception("Need <realm> when <site> is given.")
        sites_list = search(realm=realm,
                            object_type="site",
                            attribute="name",
                            value=site,
                            return_type="oid")
    else:
        sites_list = search(realm=realm,
                            object_type="site",
                            attribute="uuid",
                            value="*",
                            return_type="oid")
    try:
        current_clear_queue = multiprocessing.sync_map_cache_clear_queue
    except:
        current_clear_queue = []
    for x in sites_list:
        x_realm = x.realm
        x_site = x.site
        clear_tuple = (x_realm, x_site, object_types)
        if clear_tuple in current_clear_queue:
            continue
        multiprocessing.sync_map_cache_clear_queue.append(clear_tuple)

def clear_outdated_sync_maps():
    """ Remove outdated sync maps from cache. """
    lock_id = "clear_outdated_sync_maps"
    lock = locking.acquire_lock(lock_type=SYNC_MAP_LOCK_TYPE, lock_id=lock_id)
    processed = []
    for x in list(multiprocessing.sync_map_cache_clear_queue):
        multiprocessing.sync_map_cache_clear_queue.remove(x)
        if x in processed:
            continue
        x_realm = x[0]
        x_site = x[1]
        x_object_types = x[2]
        clear_sync_map(realm=x_realm, site=x_site, object_types=x_object_types)
        processed.append(x)
    lock.release_lock()

@match_typing
def clear_sync_map(realm: str, site: str, object_types: Union[List,None]=None):
    """ Clear given realm/site from sync map. """
    for x in list(multiprocessing.sync_map.copy()):
        for x_realm in list(multiprocessing.sync_map[x].copy()):
            if realm and x_realm:
                if x_realm != realm:
                    continue
            for x_site in list(multiprocessing.sync_map[x][x_realm].copy()):
                if site and x_site:
                    if x_site != site:
                        continue

                clear_map = False
                if object_types:
                    for object_type in object_types:
                        map_entry = multiprocessing.sync_map[x].copy()
                        x_object_types = map_entry[x_realm][x_site]['object_types'].copy()
                        if not x_object_types:
                            continue
                        if object_type in x_object_types:
                            clear_map = True
                            break
                else:
                    clear_map = True

                if clear_map:
                    # Get site/node entry from sync map.
                    try:
                        map_entry = multiprocessing.sync_map[x]
                        map_entry[x_realm].pop(x_site)
                    except:
                        map_entry = {}
                    # Update entry.
                    multiprocessing.sync_map[x] = map_entry

@match_typing
def get_sync_list(
    realm: str,
    site: str,
    object_types: List=None,
    skip_users: List=None,
    skip_admin: bool=False,
    skip_list: List=None,
    include_uuids: dict=None,
    checksum_only_types: Union[List,None]=None,
    include_templates: bool=False,
    quiet: bool=False
    ):
    """ Get sync list. """
    sync_list = {}
    # Get logger.
    logger = config.logger

    if not object_types:
        object_types = [
                        "realm",
                        "site",
                        "user",
                        "token",
                        "group",
                        "accessgroup",
                        "client",
                        "node",
                        "host",
                        "unit",
                        "role",
                        "policy",
                        "resolver",
                        "script",
                        "dictionary",
                        "ca",
                        "used_otp",
                        "used_sotp",
                        "failed_pass",
                        "token_counter",
                        "revoked_signature",
                        ]

    if skip_users is None:
        skip_users = []
        _skip_users = []
    else:
        _skip_users = list(skip_users)

    if skip_list is None:
        skip_list = []
        _skip_list = []
    else:
        _skip_list = list(skip_list)

    # Add admin + tokens to skip list if requested.
    if skip_admin:
        _skip_users.append(config.admin_user_name)
        result = search(object_type="group",
                        attribute="name",
                        value=config.admin_group,
                        realm=config.realm,
                        site=config.site,
                        return_type="full_oid")
        if result:
            admin_group_oid = result[0]
            _skip_list.append(admin_group_oid)

    # Add "skip users" token to skip list.
    for user_name in _skip_users:
        result = search(object_type="user",
                        return_type="full_oid",
                        attribute="name",
                        value=user_name,
                        realm=realm,
                        site=site)
        if not result:
            continue
        user_oid = result[0]
        if user_oid not in _skip_list:
            _skip_list.append(user_oid)
        if "token" in object_types:
            search_regex = "%s/*" % user_name
            user_tokens = search(object_type="token",
                                attribute="rel_path",
                                value=search_regex,
                                return_type="full_oid",
                                realm=realm,
                                site=site)
            _skip_list += user_tokens

    if not quiet:
        logger.debug("Generating sync list...")

    for t in config.object_types:
        if not t in object_types:
            continue
        # By default we do not include templates.
        search_attrs = {
                        'uuid'      : {
                                    'value'     : '*',
                                    },
                        'template'  : {
                                    'value'     : False,
                                    },
                        }
        if include_templates:
            try:
                search_attrs.pop('template')
            except KeyError:
                pass
        if t not in config.tree_object_types:
            try:
                search_attrs.pop('template')
            except KeyError:
                pass

        # Get object checksums from index.
        object_checksums = search(object_type=t,
                                #attribute="uuid",
                                #value="*",
                                attributes=search_attrs,
                                realm=realm,
                                site=site,
                                return_attributes=['full_oid', 'sync_checksum'])
        # Add checksums to sync list.
        for x in object_checksums:
            x_data = object_checksums[x]
            x_oid = x_data['full_oid']
            x_checksum = x_data['sync_checksum']
            if x_oid in _skip_list:
                continue
            sync_list[x_oid] = x_checksum

    if include_uuids is not None:
        # By default we do not include templates.
        x_search_attrs = {
                        'template'  : {
                                    'value'     : include_templates,
                                    },
                        }

        for t in include_uuids:
            uuids = include_uuids[t]
            x_search_attrs['uuid'] = {}
            x_search_attrs['uuid']['values'] = uuids
            # Get object checksums from index.
            object_checksums = search(object_type=t,
                                    #attribute="uuid",
                                    #values=uuids,
                                    attributes=x_search_attrs,
                                    realm=realm,
                                    site=site,
                                    return_attributes=['full_oid', 'sync_checksum'])
            # Add checksums to sync list.
            for x in object_checksums:
                x_data = object_checksums[x]
                x_oid = x_data['full_oid']
                x_checksum = x_data['sync_checksum']
                if x_oid in _skip_list:
                    continue
                sync_list[x_oid] = x_checksum

    if checksum_only_types:
        # Get object checksums from index.
        object_checksums = search(object_types=checksum_only_types,
                                #attribute="uuid",
                                #value="*",
                                attributes=search_attrs,
                                realm=realm,
                                site=site,
                                return_attributes=['full_oid', 'sync_checksum'])
        # Add checksums to sync list.
        for x in object_checksums:
            x_data = object_checksums[x]
            x_oid = x_data['full_oid']
            x_checksum = x_data['sync_checksum']
            if x_oid in _skip_list:
                continue
            sync_list[x_oid] = x_checksum

    # NOTE: Its important to use the same JSON module on each host
    #       so we do not use otpme.lib.json.
    # Gen sync list checksum.
    sync_list_checksum = json.dumps(sync_list, sort_keys=True)
    sync_list_checksum = stuff.gen_md5(sync_list_checksum)

    return sync_list, sync_list_checksum

@match_typing
def get_instance_from_oid(
    object_id: oid.OTPmeOid,
    object_config: Union[dict,ObjectConfig]=None
    ):
    """ Load instance from oid. """
    # Get logger.
    logger = config.logger
    # Get object type.
    object_type = object_id.object_type
    # Get object class stuff.
    class_getter, getter_args = get_class_getter(object_type)
    # Try to get class getter arguments from object config.
    args = {}
    if getter_args:
        _object_config = None
        if object_config:
            _object_config = object_config.copy()
        if not _object_config:
            _object_config = read_config(object_id)
        if not _object_config:
            return
        for conf_arg in getter_args:
            getter_arg = getter_args[conf_arg]
            try:
                val = _object_config[conf_arg]
            except:
                msg = ("Missing object config parameter: %s: %s"
                        % (object_id, conf_arg))
                logger.critical(msg)
                return
            args[getter_arg] = val

    # Try to get object class.
    try:
        object_class = class_getter(**args)
    except Exception as e:
        msg = (_("Error creating %(object_type)s class "
                    "'%(object_id)s': %(error)s")
                    % {"object_type":object_type,
                        "object_id":object_id,
                        "error":e})
        config.raise_exception()
        raise OTPmeException(msg)

    # Try to load class.
    try:
        instance = object_class(object_id=object_id,
                        object_config=object_config)
    except Exception as e:
        msg = "Failed to load object class: %s: %s" % (object_id, e)
        logger.critical(msg, exc_info=True)
        config.raise_exception()
        raise OTPmeException(msg)

    # Try to load instance.
    try:
        instance._load()
    except Exception as e:
        msg = "Failed to load object from OID: %s: %s" % (object_id, e)
        logger.critical(msg)
        config.raise_exception()
        raise OTPmeException(msg)

    return instance

@match_typing
def get_object(
    object_id: Union[oid.OTPmeOid,None]=None,
    uuid: Union[str,None]=None,
    object_type: Union[str,None]=None,
    path: Union[str,None]=None,
    rel_path: Union[str,None]=None,
    realm: Union[str,None]=None,
    site: Union[str,None]=None,
    unit: Union[str,None]=None,
    name: Union[str,None]=None,
    run_policies: bool=False,
    use_cache: bool=True,
    **kwargs
    ):
    """ Get object from backend. """
    instance = None
    # Get logger.
    logger = config.logger

    if use_cache:
        try:
            instance = get_object_from_cache(object_id=object_id,
                                            uuid=uuid,
                                            object_type=object_type,
                                            path=path,
                                            rel_path=rel_path,
                                            realm=realm,
                                            site=site,
                                            unit=unit,
                                            name=name,
                                            run_policies=run_policies,
                                            **kwargs)
        except Exception as e:
            msg = "Failed to get object from cache: %s" % e
            raise OTPmeException(msg)
        if instance:
            return instance

    # Try to get full OID via UUID.
    if uuid and not object_id:
        object_id = get_oid(uuid=uuid,
                            realm=realm,
                            site=site,
                            object_type=object_type,
                            instance=True)
        if not object_id:
            return

    if not object_id or not object_id.full_oid:
        _read_oid = None
        # Get attributes from read OID.
        if object_id:
            name = object_id.name
            realm = object_id.realm
            if object_id.site:
                site = object_id.site
            _read_oid = object_id.read_oid
            object_type = object_id.object_type
        # Try to get full OID via attributes.
        try:
            object_id = oid.get(object_id=_read_oid,
                                object_type=object_type,
                                path=path,
                                rel_path=rel_path,
                                realm=realm,
                                site=site,
                                unit=unit,
                                name=name,
                                full=True,
                                resolve=True,
                                **kwargs)
        except UnknownObject as e:
            return
        except Exception as e:
            logger.critical("Error building full OID: %s" % e)
            config.raise_exception()
            return

    # Get object type.
    object_type = object_id.object_type

    # Get object UUID.
    object_uuid = uuid
    if not object_uuid:
        object_uuid = get_uuid(object_id)
    # No UUID no object to load.
    if not object_uuid:
        return

    # Try to load instance.
    instance = None
    object_config = read_config(object_id)
    if object_config:
        try:
            instance = get_instance_from_oid(object_id, object_config)
        except OTPmeException as e:
            instance = None
        except Exception as e:
            msg = "Failed to load object: %s: %s" % (object_id, e)
            logger.critical(msg)
            config.raise_exception()
            return

    # Call policies for the "exists" hook (e.g. auto_disable policy).
    if instance:
        instance_exists = instance.exists(run_policies=run_policies)
        if not instance_exists:
            instance = None

    # Add instance to cache if it exists.
    if instance:
        cache.add_instance(instance)

    return instance

@match_typing
def get_object_from_cache(
    object_id: Union[oid.OTPmeOid,None]=None,
    uuid: Union[str,None]=None,
    object_type: Union[str,None]=None,
    path: Union[str,None]=None,
    rel_path: Union[str,None]=None,
    realm: Union[str,None]=None,
    site: Union[str,None]=None,
    unit: Union[str,None]=None,
    name: Union[str,None]=None,
    run_policies: bool=False,
    **kwargs
    ):
    """ Get object from cache. """
    # Get logger.
    logger = config.logger
    instance = None
    read_oid = None

    if object_id:
        read_oid = object_id

    if uuid and not object_id:
        read_oid = get_oid(uuid=uuid,
                            realm=realm,
                            site=site,
                            object_type=object_type,
                            full=False,
                            instance=True)
        if not read_oid:
            return

    if read_oid is None:
        try:
            read_oid = oid.get(object_type=object_type,
                                path=path,
                                rel_path=rel_path,
                                realm=realm,
                                site=site,
                                unit=unit,
                                name=name,
                                full=False,
                                resolve=False,
                                **kwargs)
        except UnknownObject as e:
            return
        except Exception as e:
            logger.critical("Error building read OID: %s" % e)
            config.raise_exception()
            return

    # Try to get instance from cache.
    # At this stage the read OID is an object of the OID class but
    # it is not resolved to the full OID.
    instance = cache.get_instance(read_oid)
    if not instance:
        return None
    now = time.time()
    # Get last cache read time to prevent calling policies to frequently.
    if run_policies:
        try:
            last_read = multiprocessing.instance_cache_read_times[read_oid.read_oid]
        except:
            last_read = 0
        age = now - last_read
        if age > config.backend_policy_interval:
            # Call policies for the "exists" hook (e.g. auto_disable policy).
            instance.run_policies("exists")
    # Update read time.
    multiprocessing.instance_cache_read_times.add(key=read_oid.read_oid, value=now,
                                                expire=config.backend_policy_interval)

    # FIXME: Sometimes changed class code does not work because of pickle cache?
    #class_module = importlib.import_module(instance.__class__.__module__)
    #instance_class = getattr(class_module, instance.__class__.__name__)
    #instance.__class__ = instance_class
    return instance

#def search_ldif(ldif, attribute, value, less_than=False,
#    greater_than=False, search_regex=None, ignore_case=False):
#    """ Search attribute/value pair in list of attributes in LDIF format. """
#    result = []
#
#    if search_regex:
#        try:
#            if ignore_case:
#                search_re = re.compile(search_regex, flags=re.IGNORECASE)
#            else:
#                search_re = re.compile(search_regex)
#        except:
#            return result
#
#    for a in ldif:
#        if a.lower().startswith("%s:" % attribute.lower()):
#            v = a.split(" ")[1:][0]
#            if value:
#                if ignore_case:
#                    if v.lower() == value.lower():
#                        result.append(v)
#                else:
#                    if v == value:
#                        result.append(v)
#            elif search_regex:
#                if search_re.match(v):
#                    result.append(v)
#            elif less_than:
#                if int(v) < int(less_than):
#                    result.append(v)
#            elif greater_than:
#                if int(v) > int(greater_than):
#                    result.append(v)
#    return result

@match_typing
@search_cache.cache_function()
def search(
    attribute: str=None,
    value: str=None,
    values: List=None,
    attributes: dict={},
    less_than: int=None,
    greater_than: int=None,
    ignore_case: bool=False,
    object_type: str=None,
    object_types: List=None,
    order_by: str=None,
    reverse_order: bool=False,
    join_search_attr: str=None,
    join_search_val: str=None,
    join_object_type: str=None,
    join_attribute: str=None,
    return_type: str="uuid",
    max_results: int=0,
    size_limit: int=0,
    realm: Union[str,None]=None,
    site: Union[str,None]=None,
    return_attributes: List=None,
    verify_acls: List=None,
    return_query_count: bool=False,
    **kwargs
    ) -> Union[List,dict]:
    """ Search objects. """
    _result = []
    result = []

    _verify_acls = None
    if verify_acls:
        if not config.auth_token:
            msg = ("Unable to verify ACLs: config.auth_token is None")
            raise OTPmeException(msg)
        _verify_acls = otpme_acl.get_raw_acls(verify_acls, config.auth_token)

    if return_type == "instance":
        search_return_type = "oid"
    else:
        search_return_type = return_type

    # Search via index.
    _result = index_search(realm=realm,
                            site=site,
                            verify_acls=_verify_acls,
                            attributes=attributes,
                            attribute=attribute,
                            value=value,
                            values=values,
                            less_than=less_than,
                            greater_than=greater_than,
                            order_by=order_by,
                            reverse_order=reverse_order,
                            join_search_val=join_search_val,
                            join_search_attr=join_search_attr,
                            join_object_type=join_object_type,
                            join_attribute=join_attribute,
                            return_type=search_return_type,
                            return_attributes=return_attributes,
                            return_query_count=return_query_count,
                            max_results=max_results,
                            size_limit=size_limit,
                            object_types=object_types,
                            object_type=object_type,
                            **kwargs)

    if return_type == "instance":
        for object_id in _result:
            x = get_object(object_id)
            # Skip objects deleted while search was running.
            if not x:
                continue
            result.append(x)
    elif return_attributes and "instance" in return_attributes:
        for uuid in _result:
            o = get_object(uuid=uuid)
            _result[uuid]['instance'] = o
        result = _result
    else:
        result = _result

    return result

@match_typing
def get_sessions(
    session_id: Union[str,None]=None,
    uuid: Union[str,None]=None,
    user: Union[str,None]=None,
    token: Union[str,None]=None,
    session_type: Union[str,None]=None,
    access_group: Union[str,None]=None,
    return_type: str="uuid",
    return_attributes: List=None,
    ):
    """ Get sessions from backend. """
    search_attrs = {}
    if uuid is not None:
        search_attrs['uuid'] = {'value':uuid}
    if user is not None:
        search_attrs['user_uuid'] = {'value':user}
    if token is not None:
        search_attrs['token_uuid'] = {'value':token}
    if session_id is not None:
        search_attrs['session_id'] = {'value':session_id}
    if access_group is not None:
        search_attrs['accessgroup'] = {'value':access_group}
    if session_type is not None:
        search_attrs['session_type'] = {'value':session_type}
    if not search_attrs:
        search_attrs['uuid'] = {'value':"*"}
    result = search(object_type="session",
                    attributes=search_attrs,
                    return_type=return_type,
                    return_attributes=return_attributes)
    return result
