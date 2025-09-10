# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import time
#import pprint
from collections import OrderedDict

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import otpme_acl
from otpme.lib import multiprocessing
from otpme.lib.locking import oid_lock
from otpme.lib.cache import index_cache
from otpme.lib.cache import index_acl_cache
from otpme.lib.cache import object_list_cache
from otpme.lib.cache import index_search_cache
from otpme.lib.cache import oid_from_path_cache
from otpme.lib.nsscache import NSSCACHE_OBJECT_TYPES
from otpme.lib.third_party.dogpile_caching.caching_query import FromCache

# Imports (forwarded) to be imported from file backend module.
from .index import get_class
from .index import cleanup as index_cleanup

from .transaction import FileTransaction
# Imports (forwarded) to be imported from file backend module.
from .transaction import get_transaction
from .transaction import handle_transaction
from .transaction import init as init_transactions
from .transaction import cleanup as transaction_cleanup

from otpme.lib.exceptions import *

OBJECTS_DIR = os.path.join(config.data_dir, "tree")
USED_DIR = os.path.join(config.data_dir, "data", "used")

object_dirs = {}
data_dirs = {
            'objects'           : {
                                    'path'  : OBJECTS_DIR,
                                    'perms' : 0o770,
                                    'drop'  : True,
                                },
            'used'              : {
                                    'path'  : USED_DIR,
                                    'perms' : 0o770,
                                    'drop'  : True,
                                },
            }

logger = config.logger

# Per object type settings registered by modules.
object_settings = {}

def atfork():
    """ Run stuff at fork. """
    from .index import atfork as index_atfork
    from .transaction import atfork as transaction_atfork
    transaction_atfork()
    try:
        index_atfork()
    finally:
        pass

def cleanup():
    """ Do file backend cleanup. """
    transaction_cleanup()
    index_cleanup()

def is_available(write=True):
    """ Check if backend is available. """
    from . import index
    if write:
        if not os.access(OBJECTS_DIR, os.W_OK):
            return False
    if not os.access(OBJECTS_DIR, os.R_OK):
        return False
    if not index.is_available(write):
        return False
    return True

def init(init_file_dir_perms=False):
    """
    Make sure needed directories and files exists with the correct permissions.
    """
    if config.system_user() != config.user and config.system_user() != "root":
        print("THIS SHOULD NOT HAPPEN...")
        return True

    # Make sure directories exists and have sane permissions.
    if init_file_dir_perms:
        directories = {}
        for x in data_dirs:
            x_dir = data_dirs[x]['path']
            x_perms = data_dirs[x]['perms']
            directories[x_dir] = x_perms
        directories = (directories)

        if config.realm:
            realm_oid = oid.get(object_type="realm", name=config.realm)
            realm_config_dir = get_config_paths(realm_oid)['config_dir']
            directories[realm_config_dir] = 0o770

            for site_oid in get_sites(config.realm):
                site_config_dir = get_config_paths(site_oid)['config_dir']
                directories[site_config_dir] = 0o770

        if config.handle_files_dirs:
            filetools.ensure_fs_permissions(directories=directories, files=None)
        else:
            for x in directories:
                if os.path.exists(x):
                    continue
                msg = ("No such file or directory: %s" % x)
                raise OTPmeException(msg)

    from . import index
    index.init(init_file_dir_perms=init_file_dir_perms)

    # Init transactions dirs.
    init_transactions()

def drop():
    """ Remove all data from backend. """
    from .index import drop as index_drop
    # Clear index.
    index_drop()

    # Directories to remove on drop().
    for x in data_dirs:
        x_drop = data_dirs[x]['drop']
        if not x_drop:
            continue
        x_dir = data_dirs[x]['path']
        if not os.path.exists(x_dir):
            continue
        try:
            filetools.remove_dir(x_dir, recursive=True, remove_non_empty=True)
        except Exception as e:
            msg = (_("Error removing directory '%(dir)s: %(error)s")
                    % {"dir":x_dir, "error":e})
            raise OTPmeException(msg)

def get_data_dir(name):
    """ Get path to data directory. """
    try:
        x_dir = data_dirs[name]['path']
    except:
        msg = "Data directory not registered: %s" % name
        raise OTPmeException(msg)
    return x_dir

def register_data_dir(name, path, drop, perms):
    """ Register data directory. """
    global data_dirs
    try:
        _path = data_dirs[name]['path']
        _drop = data_dirs[name]['drop']
        _perms = data_dirs[name]['perms']
    except:
        _path = None
    if _path is not None:
        msg = ("Directory already registered: %s: path=%s, perms=%s, "
                "drop=%s" % (name, _path, _perms, _drop))
        if _path != path:
            raise OTPmeException(msg)
        if _drop != drop:
            raise OTPmeException(msg)
        if _perms != perms:
            raise OTPmeException(msg)
    if not name in data_dirs:
        data_dirs[name] = {}
    data_dirs[name]['path'] = path
    data_dirs[name]['drop'] = drop
    data_dirs[name]['perms'] = perms

def get_object_dir(object_id, object_uuid, name=None):
    """ Get path to object directory. """
    object_type = object_id.object_type
    if name is None:
        try:
            get_dirs = list(object_dirs[object_type])
        except:
            get_dirs = []
    else:
        get_dirs = [name]
    x_dirs = {}
    for x in get_dirs:
        try:
            x_getter = object_dirs[object_type][x]['getter']
            x_drop = object_dirs[object_type][x]['drop']
        except:
            msg = "Object (%s) directory not registered: %s" % (object_type, x)
            raise OTPmeException(msg)
        try:
            x_path = x_getter(object_id, object_uuid)
        except Exception as e:
            msg = ("Error getting %s directory path: %s: %s"
                    % (object_type, x, e))
            raise OTPmeException(msg)
        if x_path is None:
            continue
        x_dirs[x] = {}
        x_dirs[x]['path'] = x_path
        x_dirs[x]['drop'] = x_drop
    return x_dirs

def register_object_dir(object_type, name, getter, drop):
    """ Register object directory. """
    global object_dirs
    try:
        object_dirs[object_type][name]
        msg = ("Directory already registered: %s" % name)
        raise OTPmeException(msg)
    except:
        pass
    if object_type not in object_dirs:
        object_dirs[object_type] = {}
    object_dirs[object_type][name] = {}
    object_dirs[object_type][name]['getter'] = getter
    object_dirs[object_type][name]['drop'] = drop

def get_object_path_settings(object_type):
    """ Get object path settings. """
    try:
        return object_settings[object_type]
    except:
        msg = "Object type not registered: %s" % object_type
        raise OTPmeException(msg)

def register_object_type(object_type, path_getter, oid_getter,
    tree_object=True, index_rebuild_func=None, dir_name_extension=None):
    """ Register functions to get config paths. """
    global object_settings
    if object_type in object_settings:
        msg = "Object type already registered: %s" % object_type
        raise OTPmeException(msg)
    if not object_type in object_settings:
        object_settings[object_type] = {}
    object_settings[object_type]['oid_getter'] = oid_getter
    object_settings[object_type]['path_getter'] = path_getter
    if index_rebuild_func:
        if "index_rebuild" not in object_settings[object_type]:
            object_settings[object_type]['index_rebuild'] = {}
        if tree_object:
            object_settings[object_type]['index_rebuild']['tree'] = index_rebuild_func
        else:
            object_settings[object_type]['index_rebuild']['flat'] = index_rebuild_func
    if dir_name_extension:
        object_settings[object_type]['dir_name_extension'] = dir_name_extension

# Helper function to do proper logging.
def log_current_object(x_object):
    log_current_object.counter += 1
    msg = ("%s (%s/%s): %s"
        % (log_current_object.message,
        log_current_object.counter,
        log_current_object.file_count,
        x_object))
    logger.debug(msg)

def clear_index_caches(object_id):
    object_type = object_id.object_type
    index_cache.invalidate()
    _cache = config.get_cache_module()
    cache_region = config.get_cache_region(object_type)
    index_search_cache.invalidate(cache_region)
    object_list_cache.invalidate(object_type)
    if not config.dogpile_caching:
        return
    dogpile_region = _cache.get_dogpile_region(cache_region)
    dogpile_region.invalidate(hard=True)

#def get_index_data(object_id, no_lock=False):
#    """ Get index data from object. """
#    # Get object config.
#    object_config = read(object_id)
#    # Get object UUID.
#    try:
#        uuid = object_config['UUID']
#    except:
#        uuid = None
#    # Get object checksum.
#    try:
#        checksum = object_config['CHECKSUM']
#    except:
#        checksum = None
#    # Get object sync checksum.
#    try:
#        sync_checksum = object_config['SYNC_CHECKSUM']
#    except:
#        sync_checksum = None
#    # Get object ACLs.
#    try:
#        object_acls = object_config['ACLS']
#    except:
#        object_acls = []
#    # Get object index.
#    try:
#        object_index = object_config['INDEX']
#    except:
#        object_index = None
#    # Build index data.
#    index_data = {
#                'uuid'              : uuid,
#                'checksum'          : checksum,
#                'sync_checksum'     : sync_checksum,
#                'object_acls'       : object_acls,
#                'add_attributes'    : object_index,
#                }
#    return index_data

def get_config_file_move(uuid, new_oid, old_oid=None):
    """ Get object move data (e.g. on unit change). """
    if not old_oid and not uuid:
        msg = "Need <uuid> or <old_oid>."
        raise OTPmeException(msg)

    if not old_oid:
        # We need to use force_index=True to make sure we get the OID from
        # the index DB instead of a cached object.
        old_oid = get_oid(uuid=uuid,
                        object_type=new_oid.object_type,
                        force_index=True,
                        instance=True)

    old_config_file = None
    new_config_file = None
    object_type = new_oid.object_type
    if old_oid and new_oid.full_oid != old_oid.full_oid:
        test_oid_type = old_oid.object_type
        if object_type != test_oid_type:
            msg = (_("Found duplicate UUID for different objects: "
                    "%(new_oid)s <> %(old_oid)s")
                    % {"new_oid":new_oid, "old_oid":old_oid})
            raise OTPmeException(msg)
        old_config_file = get_config_paths(object_id=old_oid,
                                        object_uuid=uuid,
                                        use_index=True)['config_file']
        new_config_file = get_config_paths(object_id=new_oid,
                                        object_uuid=uuid,
                                        use_index=False)['config_file']
    return old_oid, old_config_file, new_config_file

def get_moved_child_objects(old_config_dir, new_config_dir):
    """ Get child objects to be updated in index. """
    child_objects = {}
    result = OrderedDict()
    for i in os.walk(old_config_dir):
        x_dir = i[0]
        if x_dir == old_config_dir:
            continue
        x_oid = get_oid_from_path(x_dir)
        x_uuid = get_uuid(x_oid)
        x_object_type = x_oid.object_type
        x_new_dir = x_dir.replace(old_config_dir, new_config_dir)
        x_new_oid = get_oid_from_path(x_new_dir)
        if x_object_type not in child_objects:
            child_objects[x_object_type] = {}
        child_objects[x_object_type][x_uuid] = {}
        child_objects[x_object_type][x_uuid]['old_oid'] = x_oid
        child_objects[x_object_type][x_uuid]['new_oid'] = x_new_oid
    # Make sure we return child objects in the correct add order.
    for object_type in config.object_add_order:
        try:
            x_objects = child_objects[object_type]
        except:
            continue
        for x_uuid in x_objects:
            result[x_uuid] = x_objects[x_uuid]
    return result

def read(object_id, parameters=None, no_lock=False, use_index=True):
    """ Read object config. """
    # Try to get object from transaction.
    _transaction = get_transaction()
    if _transaction:
        object_config = _transaction.get_object(object_id=object_id,
                                            parameters=parameters)
        if object_config:
            return object_config

    # Make sure the object exists.
    object_exists = index_get(object_id=object_id)
    if not object_exists:
        return

    # Get config file path.
    object_paths = get_config_paths(object_id, use_index=use_index)
    if "config_dir" in object_paths:
        config_dir = object_paths['config_dir']
        config_file = os.path.join(config_dir, config.object_config_file_name)
    else:
        config_file = object_paths['config_file']

    # Object without config file does not exist.
    if not config_file:
        return
    if not os.path.exists(config_file):
        return

    # Try to read object config.
    try:
        object_config = filetools.read_data_file(config_file, parameters)
    except Exception as e:
        logger.critical(str(e))
        object_config = None
        config.raise_exception()

    # Return object config.
    return object_config

def write(object_id, object_config, index_journal=None, ldif_journal=None,
    acl_journal=None, full_index_update=False, use_acl_journal=True,
    full_ldif_update=False, use_ldif_journal=True, full_acl_update=False,
    use_index_journal=True, checksum=None, sync_checksum=None, no_lock=False,
    commit_files=None, full_data_update=None, cluster=False,
    wait_for_cluster_writes=True, no_index_writes=False,
    parent_dir_check=True, no_transaction=False, transaction_replay=False):
    """ Write object config and update config cache. """
    from otpme.lib.backend import outdate_object
    if object_id.full_oid is None:
        msg = ("Object ID is missing full OID: %s" % object_id)
        raise OTPmeException(msg)

    if config.host_type != "node":
        cluster = False
    if not multiprocessing.cluster_out_event:
        cluster = False
    if config.one_node_setup:
        cluster = False

    # Get object type.
    object_type = object_id.object_type

    # Get objects UUID.
    try:
        uuid = object_config['UUID']
    except:
        uuid = None

    if not uuid:
        msg = ("Object does not have a UUID: %s" % object_id)
        raise OTPmeException(msg)

    # Get checksum
    if checksum is None:
        checksum = object_config['CHECKSUM']

    # Get config file path from index.
    object_paths = get_config_paths(object_id, object_uuid=uuid, use_index=False)
    if "config_dir" in object_paths:
        config_dir = object_paths['config_dir']
        config_file = os.path.join(config_dir, config.object_config_file_name)
    else:
        config_file = object_paths['config_file']
        config_dir = os.path.dirname(config_file)

    # Child objects to be updated in the index.
    child_objects = {}
    # Name of the file transaction.
    transaction_name = "write:%s" % object_id
    # Check for active object transaction.
    _transaction = None
    if not no_transaction:
        _transaction = get_transaction()
    if _transaction:
        # Transaction to handle index actions.
        index_handler = _transaction
        cluster_handler = _transaction
        # Add object to transaction.
        _transaction.add_object(object_id=object_id,
                                object_config=object_config,
                                acl_journal=acl_journal,
                                ldif_journal=ldif_journal,
                                full_ldif_update=full_ldif_update,
                                full_acl_update=full_acl_update,
                                use_acl_journal=use_acl_journal,
                                use_ldif_journal=use_ldif_journal,
                                index_journal=index_journal,
                                full_index_update=full_index_update,
                                use_index_journal=use_index_journal,
                                cluster=cluster)
        # Get write transaction.
        write_transaction = FileTransaction(transaction_name,
                                            no_disk_writes=True,
                                            no_index_writes=no_index_writes,
                                            commit_files=commit_files)
        write_transaction.begin()

    else:
        # For tree-objects we have to make sure the parent directory (e.g. the
        # object's unit) does exist.
        if parent_dir_check:
            if object_type in config.tree_object_types:
                parent_config_dir = os.path.dirname(config_dir)
                if not os.path.exists(parent_config_dir):
                    msg = ("Parent object config directory does not exist. "
                            "Probably wrong object id: %s: %s"
                            % (object_id, parent_config_dir))
                    raise OTPmeException(msg)
        # Get write transaction.
        write_transaction = FileTransaction(transaction_name,
                                        no_index_writes=no_index_writes,
                                        commit_files=commit_files)
        write_transaction.begin()

        # Transaction to handle index actions.
        index_handler = write_transaction
        cluster_handler = write_transaction
        # Check if objects config dir path has changed and we have to move it,
        if uuid:
            old_oid, \
            old_config_file, \
            new_config_file = get_config_file_move(uuid, new_oid=object_id)
            move_dirs = False
            if old_config_file and old_config_file != new_config_file:
                # We need to do a full index update if OID changed...
                full_index_update = True
                # Remove old OID from index.
                index_handler.index_del(object_id=old_oid,
                                    no_transaction=no_transaction)
                # Check if we have to move the config dir.
                old_config_dir = os.path.dirname(old_config_file)
                new_config_dir = os.path.dirname(new_config_file)
                if os.path.exists(old_config_dir):
                    if not os.path.exists(new_config_dir):
                        move_dirs = True
            if move_dirs:
                # Child objects needs to be re-added to the index.
                child_objects = get_moved_child_objects(old_config_dir,
                                                        new_config_dir)
                # Move directory.
                write_transaction.move(old_config_dir, new_config_dir)
                # Set new paths.
                config_dir = new_config_dir
                config_file = new_config_file

        # Create config dir if needed.
        write_transaction.create_dir(config_dir)
        # Try to write config file.
        write_transaction.write_object_file(object_id,
                                        config_file, object_config,
                                        full_data_update=full_data_update)

        # Update nsscache.
        if object_type in NSSCACHE_OBJECT_TYPES:
            # Get object template status.
            try:
                template = object_config['TEMPLATE']
            except:
                template = False
            if not template:
                write_transaction.update_nsscache(object_id, "update")

    # Add object to index.
    index_handler.index_add(object_id,
                object_paths=object_paths,
                object_config=object_config,
                acl_journal=acl_journal,
                full_acl_update=full_acl_update,
                use_acl_journal=use_acl_journal,
                ldif_journal=ldif_journal,
                full_ldif_update=full_ldif_update,
                use_ldif_journal=use_ldif_journal,
                index_journal=index_journal,
                full_index_update=full_index_update,
                use_index_journal=use_index_journal,
                checksum=checksum,
                sync_checksum=sync_checksum,
                no_transaction=no_transaction)

    # If we got child objects to modify we have to check if there is a active
    # transaction (active or currently committing).
    if child_objects:
        x_transaction = None
        if not no_transaction:
            x_transaction = get_transaction(active=None)
    # Modify child objects in index _after_ parent object is updated.
    for x_uuid in child_objects:
        x_old_oid = child_objects[x_uuid]['old_oid']
        # If there is a transaction try to get object from it.
        x_object_config = None
        if x_transaction:
            x_object_config = x_transaction.get_object(x_old_oid)
        if not x_object_config:
            x_object_config = read(x_old_oid, use_index=False)
        x_new_oid = child_objects[x_uuid]['new_oid']
        index_handler.index_del(object_id=x_old_oid,
                                no_transaction=no_transaction)
        index_handler.index_add(object_id=x_new_oid,
                            object_config=x_object_config,
                            full_index_update=True,
                            no_transaction=no_transaction)
        # Make sure object is also outdated in all caches because
        # changing the OID does not result in changed checksum.
        outdate_object(x_old_oid, cache_type="all")
        if not x_transaction:
            continue
        x_object = x_transaction.get_object(x_old_oid)
        if not x_object:
            continue
        # Update child object in transaction.
        x_transaction.dismiss_object(object_id=x_old_oid)
        x_transaction.add_object(object_id=x_new_oid,
                                object_config=x_object_config,
                                full_index_update=True,
                                cluster=cluster)

    if cluster:
        cluster_handler.cluster_write(object_uuid=uuid,
                                    object_id=object_id,
                                    acl_journal=acl_journal,
                                    index_journal=index_journal,
                                    wait_for_write=wait_for_cluster_writes)

    # Commit and remove write transaction.
    if transaction_replay:
        write_transaction.replay()
    else:
        write_transaction.commit()
    # With an running object transaction the file transaction
    # gets deleted by it.
    object_transaction = get_transaction(active=None)
    if not object_transaction:
        write_transaction.remove()
    write_transaction.release_lock()

    return True

@index_cache.cache_function()
def object_exists(object_id, realm=False, site=False, no_lock=False):
    """ Check if object exists. """
    # Check if object exists in transaction.
    _transaction = get_transaction()
    if _transaction:
        if _transaction.object_exists(object_id):
            return True
    if realm is False:
        realm = object_id.realm
    if site is False:
        site = object_id.site
    try:
        config_file = get_config_paths(object_id=object_id)['config_file']
    except:
        return False
    if not os.path.exists(config_file):
        return False
    return True

def rename(object_id, new_object_id, no_lock=False,
    cluster=False, object_uuid=None, commit_files=None,
    no_index_writes=False, no_transaction=False,
    transaction_replay=False):
    """ Rename object. """
    from otpme.lib.backend import outdate_object
    child_objects = {}
    # Get object type.
    object_type = object_id.object_type
    # Get object config.
    object_config = read(object_id)
    # Get object UUID.
    if object_uuid is None:
        try:
            object_uuid = object_config['UUID']
        except TypeError:
            object_uuid = None
        except KeyError:
            object_uuid = None

    if config.host_type != "node":
        cluster = False
    if not multiprocessing.cluster_out_event:
        cluster = False
    if config.one_node_setup:
        cluster = False

    # Name of the file transaction.
    transaction_name = "rename:%s:%s" % (object_id, new_object_id)
    # Check for active transaction.
    _transaction = None
    if not no_transaction:
        _transaction = get_transaction()
    if _transaction:
        # Transaction to handle index actions.
        index_handler = _transaction
        cluster_handler = _transaction
        rename_transaction = FileTransaction(transaction_name,
                                            no_disk_writes=True,
                                            no_index_writes=no_index_writes,
                                            commit_files=commit_files)
        rename_transaction.begin()
        _transaction.rename_object(object_id, new_object_id, cluster=cluster)
    else:
        # Get rename transaction.
        rename_transaction = FileTransaction(transaction_name,
                                            no_index_writes=no_index_writes,
                                            commit_files=commit_files)
        rename_transaction.begin()
        # Transaction to handle index actions.
        index_handler = rename_transaction
        cluster_handler = rename_transaction
        # Check if objects config dir path has changed and we have to move it,
        old_oid, \
        old_config_file, \
        new_config_file = get_config_file_move(object_uuid,
                                            new_oid=new_object_id,
                                            old_oid=object_id)
        old_config_dir = os.path.dirname(old_config_file)
        new_config_dir = os.path.dirname(new_config_file)
        if os.path.exists(new_config_dir):
            msg = ("Directory already exists: %s" % new_config_dir)
            rename_transaction.release_lock()
            raise OTPmeException(msg)
        if os.path.exists(new_config_file):
            msg = ("File already exists: %s" % new_config_file)
            rename_transaction.release_lock()
            raise OTPmeException(msg)

        # Get child objects to be updated in the index.
        child_objects = get_moved_child_objects(old_config_dir,
                                                new_config_dir)
        # Try to rename config dir.
        rename_transaction.move(old_config_dir, new_config_dir)

        # Rename config file if needed (probably never needed e.g. object.json).
        old_filename = os.path.basename(old_config_file)
        new_filename = os.path.basename(new_config_file)
        if old_filename != new_filename:
            old_filepath = os.path.join(new_config_dir, old_filename)
            new_filepath = os.path.join(new_config_dir, new_filename)
            rename_transaction.move(old_filepath, new_filepath)

    # Cluster rename action.
    if object_uuid:
        # Update index.
        if not no_index_writes:
            index_handler.index_del(object_id=object_id,
                                    no_transaction=no_transaction)
            index_handler.index_add(new_object_id,
                                object_config=object_config,
                                no_transaction=no_transaction,
                                full_index_update=True)

    # If we got child objects to modify we have to check if there is a active
    # transaction (active or currently committing).
    if child_objects:
        x_transaction = None
        if not no_transaction:
            x_transaction = get_transaction(active=None)
    # Modify child objects in index _after_ parent object is updated.
    for x_uuid in child_objects:
        # Get old OID.
        x_old_oid = child_objects[x_uuid]['old_oid']
        # Get new OID.
        x_new_oid = child_objects[x_uuid]['new_oid']
        if not no_index_writes:
            # If there is a transaction try to get object from it.
            x_object_config = None
            if x_transaction:
                x_object_config = x_transaction.get_object(x_old_oid)
            # Fallback to backend if object not in transaction.
            if not x_object_config:
                x_object_config = read(x_old_oid, use_index=False)
            # Remove old OID from index.
            index_handler.index_del(object_id=x_old_oid,
                                    no_transaction=no_transaction)
            index_handler.index_add(object_id=x_new_oid,
                                    object_config=x_object_config,
                                    no_transaction=no_transaction,
                                    full_index_update=True)
        # Make sure object is also outdated in all caches because
        # changing the OID does not result in changed checksum.
        outdate_object(x_old_oid, cache_type="all")
        if not x_transaction:
            continue
        x_object = x_transaction.get_object(x_old_oid)
        if not x_object:
            continue
        # Update child object in transaction.
        x_transaction.dismiss_object(object_id=x_old_oid)
        x_transaction.add_object(object_id=x_new_oid,
                                object_config=x_object_config,
                                full_index_update=True,
                                use_index=True)
    # Update nsscache.
    if object_type in NSSCACHE_OBJECT_TYPES:
        # Get object template status.
        try:
            template = object_config['TEMPLATE']
        except:
            template = False
        if not template:
            rename_transaction.update_nsscache(object_id, "remove")
            rename_transaction.update_nsscache(new_object_id, "update")

    if cluster:
        cluster_handler.cluster_rename(object_uuid,
                                        object_id,
                                        new_object_id)

    # Commit and delete transaction.
    if transaction_replay:
        rename_transaction.replay()
    else:
        rename_transaction.commit()
    # With an running object transaction the file transaction
    # gets deleted by it.
    object_transaction = get_transaction(active=None)
    if not object_transaction:
        rename_transaction.remove()
    rename_transaction.release_lock()

    return True

def delete(object_id, no_lock=False, commit_files=None, object_uuid=None,
    no_index_writes=False, config_paths=None, no_exists_check=False,
    cluster=False, no_transaction=False, transaction_replay=False):
    """ Delete object. """
    # Name of the file transaction.
    transaction_name = "delete:%s" % object_id
    if not no_exists_check:
        if not index_get(object_id):
            if not object_exists(object_id):
                # Make sure commit files are removed.
                del_transaction = FileTransaction(transaction_name,
                                                no_index_writes=no_index_writes,
                                                commit_files=commit_files)
                del_transaction.begin()
                del_transaction.remove()
                del_transaction.release_lock()
                return False

    if config.host_type != "node":
        cluster = False
    if not multiprocessing.cluster_out_event:
        cluster = False
    if config.one_node_setup:
        cluster = False

    # Get object type.
    object_type = object_id.object_type
    if cluster:
        if object_uuid is None:
            object_uuid = get_uuid(object_id)

    if object_type in config.tree_object_types \
    and object_type != "realm" \
    and object_type != "site" \
    and object_type != "unit" \
    and object_type != "token" \
    and object_type != "session":
        if not object_id.unit:
            msg = ("Unable to delete object with incomplete OID.")
            raise OTPmeException(msg)

    # Get files/dirs to remove.
    if config_paths is None:
        config_paths = get_config_paths(object_id)

    # Get transaction.
    _transaction = None
    if not no_transaction:
        _transaction = get_transaction()
    if _transaction:
        # Add object and paths to delete.
        _transaction.delete_object(object_id,
                                config_paths=config_paths,
                                object_uuid=object_uuid,
                                cluster=cluster)
        # Transaction to handle index actions.
        index_handler = _transaction
        cluster_handler = _transaction
        # File transaction.
        del_transaction = FileTransaction(transaction_name,
                                        no_disk_writes=True,
                                        no_index_writes=no_index_writes,
                                        commit_files=commit_files)
        del_transaction.begin()
    else:
        # Get delete transaction.
        del_transaction = FileTransaction(transaction_name,
                                        no_index_writes=no_index_writes,
                                        commit_files=commit_files)
        del_transaction.begin()
        # Transaction to handle index actions.
        index_handler = del_transaction
        cluster_handler = del_transaction

        try:
            remove_files = config_paths['remove_on_delete']
        except:
            remove_files = []
        try:
            remove_dirs = config_paths['rmdir_on_delete']
        except:
            remove_dirs = []
        try:
            rmtree_dirs = config_paths['rmtree_on_delete']
        except:
            rmtree_dirs = []

        for i in remove_files:
            del_transaction.remove_file(i)

        for i in remove_dirs:
            del_transaction.remove_dir(i, recursive=True, remove_non_empty=False)

        for i in rmtree_dirs:
            del_transaction.remove_dir(i, recursive=True, remove_non_empty=True)

    # Remove object from index.
    index_handler.index_del(object_id=object_id,
                        no_transaction=no_transaction)

    # Update nsscache.
    if object_type in NSSCACHE_OBJECT_TYPES:
        # Get object template status.
        try:
            template = object_config['TEMPLATE']
        except:
            template = False
        if not template:
            del_transaction.update_nsscache(object_id, "remove")

    if cluster:
        if object_uuid:
            cluster_handler.cluster_delete(object_uuid, object_id)

    # Commit and delete transaction.
    if transaction_replay:
        del_transaction.replay()
    else:
        del_transaction.commit()
    # With an running object transaction the file transaction
    # gets deleted by it.
    object_transaction = get_transaction(active=None)
    if not object_transaction:
        del_transaction.remove()
    del_transaction.release_lock()

    return True

def get_realm_dir(realm):
    realm_dir_extension = get_object_path_settings("realm")
    realm_dir_extension = realm_dir_extension['dir_name_extension']
    realm_dir = "%s/%s.%s" % (OBJECTS_DIR, realm, realm_dir_extension)
    return realm_dir

def get_site_dir(realm, site):
    realm_dir = get_realm_dir(realm)
    site_dir_extension = get_object_path_settings("site")
    site_dir_extension = site_dir_extension['dir_name_extension']
    site_dir = "%s/%s.%s" % (realm_dir, site, site_dir_extension)
    return site_dir

def get_unit_fs_path(object_id):
    """ Get fs path of objects unit. """
    if not object_id.unit:
        msg = "Object does not have unit: %s" % object_id
        raise OTPmeException(msg)
    unit_dir_extension = get_object_path_settings("unit")
    unit_dir_extension = unit_dir_extension['dir_name_extension']
    unit_fs_path = []
    for p in object_id.unit.split("/"):
        x = "%s.%s" % (p, unit_dir_extension)
        unit_fs_path.append(x)
    unit_fs_path = "/".join(unit_fs_path)
    return unit_fs_path

def config_path_getter(object_id, dir_extension):
    """ Get fs path of tree object config dirs. """
    unit_fs_path = get_unit_fs_path(object_id)
    site_dir = get_site_dir(object_id.realm, object_id.site)
    config_dir = "%s/%s/%s.%s" % (site_dir,
                                unit_fs_path,
                                object_id.name,
                                dir_extension)
    config_paths = {}
    config_paths['config_dir'] = config_dir
    config_paths['rmdir_on_delete'] = [config_dir]
    return config_paths

def get_config_paths(object_id, object_uuid=None, use_index=True, no_lock=False):
    """ Get object config directories and files. """
    # Try to get config paths via index.
    if use_index:
        index_object = index_get_object(object_id)
        if index_object:
            config_paths = index_object.fs_paths
            config_paths = json.loads(config_paths)
            return config_paths
    if not object_uuid:
        object_uuid = get_uuid(object_id)
    # Get object type.
    object_type = object_id.object_type
    # Get config paths via getter function.
    path_getter = object_settings[object_type]['path_getter']
    config_paths = path_getter(object_id, object_uuid)
    # In-tree objects register only the config dir. We have to add the default
    # config file name.
    if object_type in config.tree_object_types:
        config_dir = config_paths['config_dir']
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths['remove_on_delete'] = [config_file]
        config_paths['config_file'] = config_file
    return config_paths

# FIXME: implement regex searching??? http://xion.io/post/code/sqlalchemy-regex-filters.html
@handle_transaction
@index_search_cache.cache_function()
def index_search(realm=None, site=None, attribute=None, value=None, values=None,
    order_by=None, reverse_order=False, attributes={}, less_than=None,
    greater_than=None, join_object_type=None, join_search_attr=None,
    join_search_val=None, join_attribute=None, return_type="uuid",
    return_attributes=None, case_sensitive=True, object_type=None,
    object_types=None, verify_acls=None, return_acls=None,
    return_raw_acls=False, max_results=0, size_limit=0, template=None,
    return_query_count=False, session=None, _debug=False, **kwargs):
    """ Search index. """
    # Import modules here to speedup import time.
    from sqlalchemy import or_
    from sqlalchemy import cast
    from sqlalchemy import desc
    from sqlalchemy import func
    from sqlalchemy import Integer
    from sqlalchemy.orm import aliased
    from sqlalchemy.orm import contains_eager
    if size_limit is None:
        size_limit = 0
    if max_results is None:
        max_results = 0
    if size_limit > 0 and max_results > 0:
        if size_limit > max_results:
            msg = "<max_results> must be lower than <size_limit>"
            raise SearchException(msg)

    if not return_type:
        if not return_attributes:
            msg = "Need <return_type> or <return_attributes>."
            raise SearchException(msg)

    if value is None and values is None and less_than is None \
    and greater_than is None and not attributes:
        msg = "Need <value>, <values>, <greater_than>, <less_than> or <attributes>."
        raise SearchException(msg)

    # Search for object types if none was given.
    if object_type is None:
        if object_types is None:
            object_types = list(config.object_types)

    # Build attributes dict.
    search_attributes = {}
    if attributes:
        search_attributes = dict(attributes)
    if attribute:
        search_attributes[attribute] = {}
        search_attributes[attribute]['value'] = value
        search_attributes[attribute]['less_than'] = less_than
        search_attributes[attribute]['greater_than'] = greater_than

    # Check if we got valid search parameters.
    for x_attr in search_attributes:
        try:
            x_value = search_attributes[x_attr]['value']
        except:
            x_value = None
        try:
            x_values = search_attributes[x_attr]['values']
        except:
            x_values = None
        try:
            x_less_than = search_attributes[x_attr]['less_than']
        except:
            x_less_than = None
        try:
            x_greater_than = search_attributes[x_attr]['greater_than']
        except:
            x_greater_than = None
        if x_attr.lower() not in map(str.lower, config.index_attributes):
            msg = "Cannot search for attribute %s: Not in index" % x_attr
            raise SearchException(msg)
        if x_value is None and x_values is None and x_less_than is None \
        and x_greater_than is None and values is None:
            msg = ("Need <value>, <values>, <less_than> or <greater_than>.")
            raise SearchException(msg)

    # Make sure objects UUID is the at first position in query result.
    if return_attributes:
        try:
            return_attributes.remove("uuid")
            return_attributes.insert(0, "uuid")
        except:
            pass
    # Build internal list with return attributes.
    _return_attributes = []
    if return_attributes:
        _return_attributes = list(return_attributes)
    elif return_type:
        if return_type not in _return_attributes:
            _return_attributes.append(return_type)
    # We always need the UUID attribute to build the result.
    if "uuid" not in _return_attributes:
        _return_attributes.insert(0, "uuid")

    # If we got more than one object type (or none) we have to start a search
    # for each object type.
    if not object_type:
        o_result = None
        for x_object_type in object_types:
            x_result = index_search(realm=realm,
                                    site=site,
                                    attribute=attribute,
                                    value=value,
                                    values=values,
                                    attributes=attributes,
                                    less_than=less_than,
                                    greater_than=greater_than,
                                    order_by=order_by,
                                    reverse_order=reverse_order,
                                    return_type=return_type,
                                    return_attributes=return_attributes,
                                    join_search_val=join_search_val,
                                    join_search_attr=join_search_attr,
                                    join_object_type=join_object_type,
                                    case_sensitive=case_sensitive,
                                    object_type=x_object_type,
                                    verify_acls=verify_acls,
                                    return_acls=return_acls,
                                    return_raw_acls=return_raw_acls,
                                    max_results=max_results,
                                    size_limit=size_limit)
            if isinstance(x_result, list):
                if not o_result:
                    o_result = []
                o_result += x_result
            if isinstance(x_result, dict):
                if not o_result:
                    o_result = {}
                for t in x_result:
                    if t not in o_result:
                        o_result[t] = {}
                    for x in x_result[t]:
                        o_result[t][x] = x_result[t][x]
            if size_limit != 0 and len(o_result) >= size_limit:
                raise SizeLimitExceeded("Size limit exceeded.")
        return o_result

    #import logging
    #logging.basicConfig()
    #logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

    # Get dogpile cache region.
    if config.dogpile_caching:
        cache_region = config.get_cache_region(object_type)

    # To prevent the "(sqlite3.OperationalError) too many SQL variables" error
    # we have to split values list in chunks and start a search for each chunk.
    max_q_values = 10240000
    if config.index_type == "sqlite3":
        max_q_values = 800
    if values is not None and len(values) > max_q_values:
        if order_by is not None:
            msg = "Cannot order results if <values> >= %s" % max_q_values
            raise SearchException(msg)
        v_result = None
        v_query_count = 0
        values = stuff.split_list(values, max_q_values)
        for x_list in values:
            x_result = index_search(realm=realm,
                                    site=site,
                                    attribute=attribute,
                                    value=value,
                                    values=x_list,
                                    attributes=attributes,
                                    less_than=less_than,
                                    greater_than=greater_than,
                                    order_by=order_by,
                                    reverse_order=reverse_order,
                                    return_type=return_type,
                                    return_attributes=return_attributes,
                                    join_search_val=join_search_val,
                                    join_search_attr=join_search_attr,
                                    join_object_type=join_object_type,
                                    case_sensitive=case_sensitive,
                                    object_type=object_type,
                                    verify_acls=verify_acls,
                                    return_acls=return_acls,
                                    return_raw_acls=return_raw_acls,
                                    return_query_count=return_query_count,
                                    max_results=max_results,
                                    size_limit=size_limit)
            if return_query_count:
                x_query_count, x_result = x_result
                v_query_count += x_query_count
            if isinstance(x_result, list):
                if not v_result:
                    v_result = []
                v_result += x_result
            if isinstance(x_result, dict):
                if not v_result:
                    v_result = {}
                for x in x_result:
                    v_result[x] = x_result[x]
            if size_limit != 0 and len(v_result) >= size_limit:
                raise SizeLimitExceeded("Size limit exceeded.")
        return v_query_count, v_result
    else:
        if order_by is None:
            order_by = "full_oid"

    # Get sqlalchemy class of object type.
    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise SearchException(msg)

    # Set "order by" attribute.
    order_by_attribute = None
    if order_by == "realm":
        order_by = IndexObject.realm
    elif order_by == "site":
        order_by = IndexObject.site
    elif order_by == "full_oid":
        order_by = IndexObject.full_oid
    elif order_by == "read_oid":
        order_by = IndexObject.read_oid
    elif order_by == "name":
        order_by = IndexObject.name
    elif order_by == "path":
        order_by = IndexObject.path
    elif order_by == "rel_path":
        order_by = IndexObject.rel_path
    elif order_by == "uuid":
        order_by = IndexObject.uuid
    elif order_by == "object_type":
        order_by = IndexObject.object_type
    elif order_by == "last_used":
        order_by = IndexObject.last_used
    else:
        order_by_attribute = order_by

    # Get base attributes.
    base_attributes = []
    if return_attributes:
        for x in return_attributes:
            if x not in config.otpme_base_attributes:
                continue
            base_attributes.append(x)

    # Set default query args.
    query_args = {}
    if realm:
        if object_type != "realm":
            query_args['realm'] = realm
    if site:
        if object_type != "realm" and object_type != "site":
            query_args['site'] = site
    #if object_type:
    #    query_args['object_type'] = object_type

    # Get query.
    if join_search_attr:
        if not join_object_type:
            msg = "Missing <join_object_type>."
            raise SearchException(msg)
        if not join_search_val:
            msg = "Missing <join_search_val>."
            raise SearchException(msg)
        try:
            JoinIndexObject, \
            JoinIndexObjectAttribute, \
            JoinIndexObjectACL = get_class(join_object_type)
        except UnknownClass:
            msg = "Unknown join object class: %s" % object_type
            raise SearchException(msg)
        # Alias tables to join (e.g. prevent "ERROR:  table name <table> specified more than once").
        JoinIndexObject = aliased(JoinIndexObject)
        JoinIndexObjectAttribute = aliased(JoinIndexObjectAttribute)
        # Join object attributes by foreign key and index objects by UUID.
        q = session.query(JoinIndexObject)
        q = q.join(JoinIndexObjectAttribute, JoinIndexObject.id==JoinIndexObjectAttribute.ioid)
        q = q.join(IndexObject, JoinIndexObjectAttribute.value==IndexObject.uuid)
        q = q.filter(getattr(JoinIndexObject, join_search_attr)==join_search_val)
        # Filter by join attribute.
        if join_attribute:
            q = q.filter(JoinIndexObjectAttribute.name==join_attribute)
    else:
        q = session.query(IndexObject)

    # Check for template.
    if template:
        q = q.filter(IndexObject.template == template)

    if query_args:
        q = q.filter_by(**query_args)

    attribute_table_joined = False
    # Handle search for a list of values (e.g. token UUIDs).
    if values:
        if attribute in config.otpme_base_attributes:
            q = q.filter(getattr(IndexObject, attribute).in_(values))
            q = q.options(contains_eager(IndexObject.attributes))
        else:
            attribute_table_joined = True
            q = q.join(IndexObject.attributes)
            q = q.filter(IndexObjectAttribute.value.in_(values))

    # Handle "normal" search by attribute and value.
    for attr in search_attributes:
        try:
            value = search_attributes[attr]['value']
        except:
            value = None
        try:
            values = search_attributes[attr]['values']
        except:
            values = None
        try:
            less_than = search_attributes[attr]['less_than']
        except:
            less_than = None
        try:
            greater_than = search_attributes[attr]['greater_than']
        except:
            greater_than = None

        if values is not None and len(values) > max_q_values:
            msg = "Too many <values> for attribute '%s'." % attr
            raise SearchException(msg)

        # Search objects with the given ACL.
        if attr == "acl":
            q = q.join(IndexObject.acls)
            x_values = []
            if value is not None:
                x_values = [value]
            if values is not None:
                x_values = values
            x_tuple = []
            for x_val in x_values:
                sql_like = str(x_val)
                if "*" in sql_like:
                    sql_like = x_val.replace("*", "%")
                    if "_" in sql_like:
                        sql_like = sql_like.replace("_", "!_")
                    x_tuple.append(IndexObjectACL.value.like(sql_like, escape="!"))
                else:
                    x_tuple.append(IndexObjectACL.value.is_(x_val))
            q = q.filter(or_(*x_tuple))

        # Search by base attributes (e.g. name).
        elif attr in config.otpme_base_attributes:
            if isinstance(value, bool):
                q = q.filter(getattr(IndexObject, attr).is_(value))
            if values is not None:
                q = q.filter(getattr(IndexObject, attr).in_(values))
                q = q.options(contains_eager(IndexObject.attributes))
            elif value is not None:
                sql_like = str(value)
                if "*" in sql_like:
                    sql_like = sql_like.replace("*", "%")
                    if "_" in sql_like:
                        sql_like = sql_like.replace("_", "!_")
                    if case_sensitive:
                        q = q.filter(getattr(IndexObject, attr).like(sql_like, escape="!"))
                    else:
                        q = q.filter(getattr(IndexObject, attr).ilike(sql_like, escape="!"))
                else:
                    if case_sensitive:
                        q = q.filter(getattr(IndexObject, attr)==value)
                    else:
                        if isinstance(value, str):
                            q = q.filter(func.lower(getattr(IndexObject, attr))==value)
                        else:
                            q = q.filter(getattr(IndexObject, attr)==value)
            elif less_than is not None:
                q = q.filter(cast(getattr(IndexObject, attr), Integer) < less_than)
            elif greater_than is not None:
                q = q.filter(cast(getattr(IndexObject, attr), Integer) > greater_than)
        # Search by LDIF attributes (e.g. uidNumber).
        else:
            if isinstance(value, bool):
                q = q.filter(IndexObject.attributes.any(name=attr, value=value))
            elif values is not None:
                if not attribute_table_joined:
                    q = q.join(IndexObject.attributes)
                    attribute_table_joined = True
                q = q.filter(IndexObjectAttribute.value.in_(values))
            elif value is not None:
                like_query = False
                sql_like = str(value)
                if "*" in sql_like:
                    like_query = True
                    sql_like = sql_like.replace("*", "%")
                    if "_" in sql_like:
                        sql_like = sql_like.replace("_", "!_")
                if like_query:
                    if case_sensitive:
                        like_filter = IndexObjectAttribute.value.like(sql_like, escape="!")
                        like_filter = IndexObject.attributes.any(like_filter, name=attr)
                        q = q.filter(like_filter)
                    else:
                        like_filter = IndexObjectAttribute.value.ilike(sql_like, escape="!")
                        like_filter = IndexObject.attributes.any(like_filter, name=attr)
                        q = q.filter(like_filter)
                else:
                    q = q.filter(IndexObject.attributes.any(name=attr, value=value))
            if less_than is not None:
                int_filter = cast(IndexObjectAttribute.value, Integer)
                int_filter = IndexObject.attributes.any(int_filter < less_than, name=attr)
                q = q.filter(int_filter)
            if greater_than is not None:
                int_filter = cast(IndexObjectAttribute.value, Integer)
                int_filter = IndexObject.attributes.any(int_filter > greater_than, name=attr)
                q = q.filter(int_filter)

    # Make sure we query only requested attributes.
    x_attrs = []
    entities = [IndexObject.id]
    for x in _return_attributes:
        # Remember LDIF attributes to return for processing below.
        if x not in config.otpme_base_attributes:
            x_attrs.append(x)
            continue
        if x == "full_oid":
            entities.append(IndexObject.full_oid)
        elif x == "read_oid":
            entities.append(IndexObject.read_oid)
        elif x == "oid":
            entities.append(IndexObject.full_oid)
        elif x == "realm":
            entities.append(IndexObject.realm)
        elif x == "site":
            entities.append(IndexObject.site)
        elif x == "uuid":
            entities.append(IndexObject.uuid)
        elif x == "path":
            entities.append(IndexObject.path)
        elif x == "rel_path":
            entities.append(IndexObject.rel_path)
        elif x == "name":
            entities.append(IndexObject.name)
        elif x == "object_type":
            entities.append(IndexObject.object_type)
        elif x == "checksum":
            entities.append(IndexObject.checksum)
        elif x == "sync_checksum":
            entities.append(IndexObject.sync_checksum)
        elif x == "last_used":
            entities.append(IndexObject.last_used)
        elif x == "template":
            entities.append(IndexObject.template)
        elif x == "ldif":
            entities.append(IndexObject.ldif)

    # Build entities tuple)
    if len(entities) == 1:
        entities.append(IndexObject.uuid)
    entities = tuple(entities)

    # Handle ACL check. Return only objects that match any or all of the
    # given ACLs.
    if verify_acls:
        # Get ACL query.
        acl_q = q.join(IndexObject.acls)
        acl_q = acl_q.filter(IndexObjectACL.value.in_(verify_acls))
        q = q.intersect(acl_q)

    # Get query result count before limiting search.
    if return_query_count:
        query_count = q.count()

    # Handle "with ACLs" search.
    if return_acls or return_raw_acls:
        # Join with ACL table.
        sub_query = q.with_entities(IndexObject.id)
        acl_q = session.query(IndexObjectACL)
        acl_q = acl_q.join(IndexObject, IndexObjectACL.ioid == IndexObject.id)
        acl_q = acl_q.filter(IndexObjectACL.ioid.in_(sub_query))

        # Handle dogpile caching.
        if config.dogpile_caching:
            acl_q = acl_q.options(FromCache(cache_region))

        # Query result build from ACLs query.
        query_result = []
        # ACLs for each object returned by query.
        object_acls = {}

        # Query to return all given ACLs of selected objects.
        sub_query = acl_q.with_entities(IndexObject.id)
        acl_q = session.query(IndexObjectACL)
        acl_q = acl_q.join(IndexObject, IndexObjectACL.ioid == IndexObject.id)
        acl_q = acl_q.filter(IndexObjectACL.ioid.in_(sub_query))
        # Select only given ACLs (verify_acls).
        if verify_acls:
            acl_q = acl_q.filter(IndexObjectACL.value.in_(verify_acls))
        acl_entities = tuple(list(entities) + [IndexObjectACL.value])
        acl_q = acl_q.with_entities(*acl_entities)

        # Set result order (sorting).
        if order_by_attribute:
            acl_q = acl_q.join(IndexObjectAttribute, IndexObject.attributes)
            acl_q = acl_q.filter(IndexObjectAttribute.name == order_by_attribute)
            if reverse_order:
                acl_q = acl_q.order_by(desc(IndexObjectAttribute.value))
            else:
                acl_q = acl_q.order_by(IndexObjectAttribute.value)
        else:
            if reverse_order:
                acl_q = acl_q.order_by(desc(order_by))
            else:
                acl_q = acl_q.order_by(order_by)

        # Query objects.
        object_count = []
        acl_result = acl_q.all()
        for x in acl_result:
            x_id = x[0]
            if x_id not in object_count:
                object_count.append(x_id)
            if max_results > 0:
                if len(object_count) > max_results:
                    break
            # Get result attributes.
            x_uuid = x[1]
            x_raw_acl = x[-1]
            # Build query result (skip ACL).
            query_tuple = x[:-1]
            if query_tuple not in query_result:
                query_result.append(query_tuple)
            # Use raw ACL if return_raw_acls is True.
            acl_id = x_raw_acl
            if return_acls:
                # Decode ACL to get ACL ID.
                _acl = otpme_acl.decode(x_raw_acl)
                acl_id = _acl.apply_id
            # Build list with ACLs.
            try:
                x_acls = object_acls[x_uuid]
            except:
                x_acls = []
            x_acls.append(acl_id)
            object_acls[x_uuid] = list(set(x_acls))
    else:
        # Query only requested attributes.
        q = q.with_entities(*entities)

        # Set result order (sorting).
        if order_by_attribute:
            q = q.join(IndexObjectAttribute, IndexObject.attributes)
            q = q.filter(IndexObjectAttribute.name == order_by_attribute)
            if reverse_order:
                #q = q.distinct(IndexObjectAttribute.value)
                q = q.order_by(desc(IndexObjectAttribute.value))
            else:
                #q = q.distinct(IndexObjectAttribute.value)
                q = q.order_by(IndexObjectAttribute.value)
        else:
            if reverse_order:
                #q = q.distinct(order_by)
                q = q.order_by(desc(order_by))
            else:
                #q = q.distinct(order_by)
                q = q.order_by(order_by)

        # Apply limit to search.
        if max_results > 0:
            q = q.limit(max_results)
        # Handle dogpile caching.
        if config.dogpile_caching:
            q = q.options(FromCache(cache_region))
        # Get index result.
        query_result = q.all()

    # Handle return type/return attributes.
    result = []
    result_db_ids = {}
    for r in query_result:
        index_id = r[0]
        x_uuid = r[1]
        # Add UUID <> Primary key mapping to search LDIF attributes below.
        if x_attrs:
            result_db_ids[index_id] = x_uuid
        # Handle size limit.
        if size_limit != 0 and len(result) >= size_limit:
            raise SizeLimitExceeded("Size limit exceeded.")
        # If the user requested return attributes we have to add all
        # result values.
        if return_attributes:
            return_value = r[1:]
        elif return_type == "uuid":
            return_value = x_uuid
        elif return_type == "name":
            return_value = r[2]
        elif return_type == "path":
            return_value = r[2]
        elif return_type == "rel_path":
            return_value = r[2]
        elif return_type == "full_oid":
            return_value = r[2]
        elif return_type == "read_oid":
            return_value = r[2]
        elif return_type == "oid":
            object_id = oid.get(object_id=r[2], full=True)
            return_value = object_id
        elif return_type == "checksum":
            return_value = r[2]
        elif return_type == "sync_checksum":
            return_value = r[2]
        elif return_type == "object_type":
            return_value = r[2]
        elif return_type == "last_used":
            return_value = r[2]
        elif return_type == "template":
            return_value = r[2]
        elif return_type == "ldif":
            return_value = r[2]
            return_value = json.loads(return_value)
        else:
            msg = "Unknown return type: %s" % return_type
            raise SearchException(msg)
        # Add return value to result.
        result.append(return_value)

    # Without return attributes requested we are done here.
    if not return_attributes:
        if return_acls or return_raw_acls:
            result = {
                    'objects'   : result,
                    'acls'      : object_acls,
                    }
        if return_query_count:
            result = query_count, result
        return result

    result_list = []
    # For multiple return attributes we have to return the result as dict.
    # Use ordered dict to keep result sorted when using <order_by>.
    result_dict = OrderedDict()
    # Get objects base attributes from result.
    for x in result:
        object_uuid = x[0]
        result_counter = 0
        # Add UUID (which is always a search entity) to result.
        if 'uuid' in return_attributes:
            if not object_uuid in result_dict:
                result_dict[object_uuid] = {}
            result_dict[object_uuid]['uuid'] = object_uuid
            result_counter += 1
        for r in x[1:]:
            attribute_name = base_attributes[result_counter]
            result_counter += 1
            if not object_uuid in result_dict:
                result_dict[object_uuid] = {}
            if attribute_name == "oid":
                v = oid.get(r)
            elif attribute_name == "ldif":
                v = json.loads(r)
            else:
                v = r
            result_dict[object_uuid][attribute_name] = v

    # Get LDIF attributes.
    if result_db_ids:
        # Join attributes with objects table.
        x_attr_q = session.query(IndexObjectAttribute)
        x_attr_q = x_attr_q.join(IndexObject.attributes)
        # Query only needed entities.
        x_attr_q = x_attr_q.with_entities(IndexObjectAttribute.ioid,
                                    IndexObjectAttribute.name,
                                    IndexObjectAttribute.value)
        # To prevent the "(sqlite3.OperationalError) too many SQL variables" error
        # we have to split query in chunks and start a search for each chunk.
        split_result_db_ids = [result_db_ids]
        if len(result_db_ids) > max_q_values:
            split_result_db_ids = stuff.split_list(result_db_ids, max_q_values)
        attr_result = []
        for x_list in split_result_db_ids:
            _x_attr_q = x_attr_q.filter(IndexObjectAttribute.ioid.in_(x_list))
            if return_attributes:
                _x_attr_q = _x_attr_q.filter(IndexObjectAttribute.name.in_(return_attributes))
            if config.dogpile_caching:
                _x_attr_q = _x_attr_q.options(FromCache(cache_region))
            x_result = _x_attr_q.all()
            attr_result += x_result
        for r in attr_result:
            ioid = r[0]
            object_uuid = result_db_ids[ioid]
            attribute_name = r[1]
            attribute_value = r[2]
            if not object_uuid in result_dict:
                result_dict[object_uuid] = {}
            if attribute_name in config.otpme_base_attributes:
                try:
                    x_val = result_dict[object_uuid][attribute_name]
                except:
                    x_val = None
                if attribute_value == x_val:
                    continue
                result_dict[object_uuid][attribute_name] = x_val
                continue
            try:
                x_val_list = result_dict[object_uuid][attribute_name]
            except:
                x_val_list = []
            if attribute_value in x_val_list:
                continue
            x_val_list.append(attribute_value)
            result_dict[object_uuid][attribute_name] = x_val_list

    # If only one return attribute is requested we return a list as result.
    if len(return_attributes) == 1:
        attr_name = return_attributes[0]
        for uuid in result_dict:
            x_result = result_dict[uuid][attr_name]
            if isinstance(x_result, list):
                result_list += x_result
            else:
                result_list.append(x_result)
        result = result_list
    else:
        result = result_dict

    if return_acls or return_raw_acls:
        result = {
                'objects'   : result,
                'acls'      : object_acls,
                }
    if return_query_count:
        result = query_count, result
    return result

@index_cache.cache_function()
def get_oid(uuid, object_type=None, object_types=None,
    realm=None, site=None, full=True,
    force_index=False, instance=False):
    """ Get OID via UUID. """
    # Get OID from transaction.
    if not force_index:
        _transaction = get_transaction(active=None)
        if _transaction:
            object_id = _transaction.get_oid(uuid, full=full, instance=instance)
            if object_id:
                return object_id
    if instance:
        return_type = "oid"
    else:
        return_type = "read_oid"
        if full:
            return_type = "full_oid"
    result = index_search(realm=realm,
                        site=site,
                        attribute="uuid",
                        value=uuid,
                        object_type=object_type,
                        object_types=object_types,
                        return_type=return_type)
    if not result:
        return
    object_id = result[0]
    return object_id

@index_cache.cache_function()
def get_uuid(object_id):
    """ Get object's UUID from cache or via read(). """
    uuid = None
    # Try to get UUID from index.
    result = index_search(attribute="read_oid",
                        value=object_id.read_oid,
                        object_type=object_id.object_type,
                        return_type="uuid")
    if result:
        uuid = result[0]
    # Get UUID from transaction if its not yet written.
    if not uuid:
        # Get transaction, active or currently committing ones.
        _transaction = get_transaction(active=None)
        if not _transaction:
            return
        try:
            x_config = _transaction.get_object(object_id, parameters=['UUID'])
            uuid = x_config['UUID']
        except:
            pass
    return uuid

@handle_transaction
def index_dump(object_id=None, uuid=None, session=None, checksum_ready=False, **kwargs):
    """ Dump all index attributes of given object. """
    if not object_id and not uuid:
        raise Exception("Need <uuid> or <object_id>.")
    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_id.object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise OTPmeException(msg)
    result = {'read_oid':object_id.read_oid}
    q = session.query(IndexObject)
    if object_id:
        x = q.filter(IndexObject.read_oid == object_id.read_oid)
    if uuid:
        x = q.filter(IndexObject.uuid == uuid)
    index_object = x.first()
    if not index_object:
        msg = "Unknown object."
        raise OTPmeException(msg)
    base_attributes = {}
    for c in IndexObject.__table__.columns:
        attr_name = c.name.replace("user.", "")
        if attr_name == "id":
            continue
        attr_val = getattr(index_object, attr_name)
        base_attributes[attr_name] = attr_val
    result['base_attributes'] = base_attributes
    q = session.query(IndexObjectAttribute)
    x = q.filter(IndexObjectAttribute.ioid == index_object.id)
    if checksum_ready:
        _object_attributes = []
        for x in x.all():
            _object_attributes.append((x.realm, x.site, x.object_type, x.name, x.value))
        attr_counter = 0
        object_attributes = {}
        for x in sorted(_object_attributes):
            object_attributes[attr_counter] = {}
            object_attributes[attr_counter]['realm'] = x[0]
            object_attributes[attr_counter]['site'] = x[1]
            object_attributes[attr_counter]['object_type'] = x[2]
            object_attributes[attr_counter]['name'] = x[3]
            object_attributes[attr_counter]['value'] = x[4]
            attr_counter += 1
        result['object_attributes'] = object_attributes
        q = session.query(IndexObjectACL)
        x = q.filter(IndexObjectACL.ioid == index_object.id)
        _object_acls = []
        for x in x.all():
            _object_acls.append((x.realm, x.site, x.object_type, x.value))
        acl_counter = 0
        object_acls = {}
        for x in sorted(_object_acls):
            object_acls[acl_counter] = {}
            object_acls[acl_counter]['realm'] = x[0]
            object_acls[acl_counter]['site'] = x[1]
            object_acls[acl_counter]['object_type'] = x[2]
            object_acls[acl_counter]['value'] = x[3]
            acl_counter += 1
        result['object_acls'] = object_acls
    else:
        object_attributes = {}
        for x in x.all():
            object_attributes[x.id] = {}
            object_attributes[x.id]['realm'] = x.realm
            object_attributes[x.id]['site'] = x.site
            object_attributes[x.id]['object_type'] = x.object_type
            object_attributes[x.id]['name'] = x.name
            object_attributes[x.id]['value'] = x.value
        result['object_attributes'] = object_attributes
        q = session.query(IndexObjectACL)
        x = q.filter(IndexObjectACL.ioid == index_object.id)
        object_acls = {}
        for x in x.all():
            object_acls[x.id] = {}
            object_acls[x.id]['realm'] = x.realm
            object_acls[x.id]['site'] = x.site
            object_acls[x.id]['object_type'] = x.object_type
            object_acls[x.id]['value'] = x.value
        result['object_acls'] = object_acls
    return result

@handle_transaction
def index_restore(index_data, session=None, **kwargs):
    try:
        read_oid = index_data['read_oid']
    except KeyError:
        msg = "Index data misses read_oid."
        raise OTPmeException(msg)
    try:
        base_attributes = index_data['base_attributes']
    except KeyError:
        msg = "Index data misses base_attributes."
        raise OTPmeException(msg)
    try:
        object_attributes = index_data['object_attributes']
    except KeyError:
        msg = "Index data misses object_attributes."
        raise OTPmeException(msg)
    try:
        object_acls = index_data['object_acls']
    except KeyError:
        msg = "Index data misses object_acls."
        raise OTPmeException(msg)
    object_id = oid.get(read_oid)
    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_id.object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise OTPmeException(msg)
    # Build attributes.
    attributes = []
    for attr_id in object_attributes:
        attr_attrs = object_attributes[attr_id]
        a = IndexObjectAttribute(**attr_attrs)
        attributes.append(a)
    # Build ACLs.
    acls = []
    for acl_id in object_acls:
        acl_attrs = object_acls[acl_id]
        a = IndexObjectACL(**acl_attrs)
        acls.append(a)
    # Build index object.
    index_object = IndexObject(attributes=attributes,
                            acls=acls,
                            **base_attributes)
    # Add object to index.
    session.add(index_object)
    session.commit()

@handle_transaction
@oid_lock(write=True)
def index_add(object_id, object_paths=None, object_config=None,
    uuid=None, checksum=None, sync_checksum=None, index_journal=[],
    use_index_journal=False, full_index_update=False, ldif_journal=[],
    full_ldif_update=False, use_ldif_journal=False, acl_journal=[],
    use_acl_journal=False, full_acl_update=False, autocommit=True,
    no_lock=False, session=None, **kwargs):
    """ Add object to search index. """
    from sqlalchemy.sql import select
    #from sqlalchemy.sql import delete
    from sqlalchemy.sql import tuple_
    if object_id.full_oid is None:
        msg = ("Object ID is missing full OID: %s" % object_id)
        raise OTPmeException(msg)
    if full_index_update and not object_config:
        msg = "Need <object_config> on full_index_update=True."
        raise OTPmeException(msg)
    if full_ldif_update and not object_config:
        msg = "Need <object_config> on full_ldif_update=True."
        raise OTPmeException(msg)
    if full_acl_update and not object_config:
        msg = "Need <object_config> on full_acl_update=True."
        raise OTPmeException(msg)

    # Gen read OID of object.
    read_oid = object_id.read_oid
    # Get object type.
    object_type = object_id.object_type
    # Get object realm.
    object_realm = object_id.realm

    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise OTPmeException(msg)

    # Get object site.
    object_site = None
    if object_type != "realm" and object_type != "site":
        object_site = object_id.site

    # Get object paths.
    if object_paths is None:
        object_paths = get_config_paths(object_id, use_index=False)
    # Get config file path.
    config_file = object_paths['config_file']

    if not config_file:
        msg = "Unable to get config file: %s" % object_id
        raise OTPmeException(msg)

    if object_config == "auto":
        try:
            object_config = filetools.read_data_file(config_file,
                                                    ['UUID',
                                                    'INDEX',
                                                    'ACLS',
                                                    'LDIF',
                                                    'TEMPLATE',
                                                    'CHECKSUM',
                                                    'SYNC_CHECKSUM'])
        except Exception as e:
            msg = "Error reading object config: %s" % e
            logger.critical(msg)
            raise OTPmeException(msg)

    # Get object data.
    last_modified = None
    if object_config:
        # Get object UUID.
        if uuid is None:
            try:
                uuid = object_config['UUID']
            except:
                uuid = None
        # Get object checksum.
        if checksum is None:
            try:
                checksum = object_config['CHECKSUM']
            except:
                checksum = None
        # Get object sync checksum.
        if sync_checksum is None:
            try:
                sync_checksum = object_config['SYNC_CHECKSUM']
            except:
                sync_checksum = None
        # Get object template status.
        try:
            template = object_config['TEMPLATE']
        except:
            template = False
        # Get object LDIF.
        try:
            object_ldif = object_config['LDIF']
        except:
            object_ldif = {}
        # Get last modified timestamp.
        try:
            last_modified = object_config['LAST_MODIFIED']
        except:
            last_modified = None

    # Check if the object already exists in the index DB.
    q = session.query(IndexObject)
    x = q.filter(IndexObject.uuid == uuid)
    index_object = x.first()
    # We also have to check if an object with the same OID exists. This should
    # not happen and means our index is corrupt. But we can fix it automatically
    # if the object does not exist anymore.
    if not index_object:
        x = q.filter(IndexObject.full_oid == object_id.full_oid)
        index_object = x.first()
        if index_object:
            x_config_file = json.loads(index_object.fs_paths)['config_file']
            if x_config_file != config_file:
                if os.path.exists(x_config_file):
                    x_uuid = filetools.read_data_file(x_config_file,
                                                    ['UUID'])['UUID']
                    msg = ("Cannot add object to index: %s: Object with same "
                            "OID exists: %s <> %s" % (object_id, uuid, x_uuid))
                    raise OTPmeException(msg)
            msg = ("Removing orphan object from index: %s" % object_id)
            logger.debug(msg)
            session.delete(index_object)
            #local_object = session.merge(index_object)
            #session.delete(local_object)
            ## Make sure we commit object deletion.
            #if autocommit:
            #    session.commit()
            index_object = None

    if not index_object:
        full_acl_update = True
        use_acl_journal = False
        full_ldif_update = True
        use_ldif_journal = False
        full_index_update = True
        use_index_journal = False

    attributes = []
    if full_index_update:
        # Get object index.
        try:
            object_index = object_config['INDEX']
        except KeyError:
            msg = "Unable to update object index: %s: Missing 'INDEX'" % object_id
            raise OTPmeException(msg)

        if index_object:
            existing_pairs = session.query(IndexObjectAttribute.name, IndexObjectAttribute.value)
            existing_pairs = existing_pairs.where(IndexObjectAttribute.ioid == index_object.id)
            existing_pairs = existing_pairs.all()
            existing_pairs = {(row.name, row.value) for row in existing_pairs}
            new_pairs = {(name, value) for name, values in object_index.items() for value in values}
            pairs_to_delete = existing_pairs - new_pairs
            pairs_to_add = new_pairs - existing_pairs
            if pairs_to_delete:
                del_q = session.query(IndexObjectAttribute)
                del_q = del_q.filter(IndexObjectAttribute.ioid == index_object.id)
                del_q = del_q.filter(tuple_(IndexObjectAttribute.name, IndexObjectAttribute.value).in_(pairs_to_delete))
                del_q.delete(synchronize_session=False)
            if pairs_to_add:
                for x in pairs_to_add:
                    x_name = x[0]
                    x_val = x[1]
                    a = IndexObjectAttribute(realm=object_realm,
                                            site=object_site,
                                            object_type=object_type,
                                            name=x_name, value=x_val)
                    # Reference attribute to existing index object.
                    a.ioid = index_object.id
                    session.add(a)
        else:
            # Add new attributes.
            for n in object_index:
                # Add attribute.
                values = object_index[n]
                for v in values:
                    a = IndexObjectAttribute(realm=object_realm,
                                            site=object_site,
                                            object_type=object_type,
                                            name=n, value=v)
                    # Add attribute to list of attributes for the new index object.
                    attributes.append(a)
                    #local_object = session.merge(a)
                    #session.add(local_object)

        if autocommit:
            session.commit()

    if use_index_journal and index_journal:
        # Get existing attributes.
        existing_attrs = []
        if index_object:
            sql_stmt = select(IndexObjectAttribute.name, IndexObjectAttribute.value)
            sql_stmt = sql_stmt.where(IndexObjectAttribute.ioid == index_object.id)
            existing_attrs = session.execute(sql_stmt)
            existing_attrs = existing_attrs.all()
        # Handle index journal.
        deleted_attrs = []
        for x_entry in index_journal:
            x_entry_type = x_entry[1]
            x_attribute = x_entry[2]

            # Del attribute.
            if x_entry_type == "del":
                if not index_object:
                    continue
                try:
                    x_value = x_entry[3]
                except IndexError:
                    x_value = None
                q = session.query(IndexObjectAttribute)
                q = q.filter(IndexObjectAttribute.ioid == index_object.id)
                q = q.filter(IndexObjectAttribute.name == x_attribute)
                if x_value:
                    q = q.filter(IndexObjectAttribute.value == x_value)
                result = list(q.all())
                if result:
                    if x_value:
                        deleted_attrs.append((x_attribute, x_value))
                    else:
                        deleted_attrs.append(x_attribute)
                for a in result:
                    session.delete(a)

            # Add attributes.
            if x_entry_type == "add":
                x_value = x_entry[3]
                if x_attribute not in deleted_attrs:
                    if (x_attribute, x_value) not in deleted_attrs:
                        if (x_attribute, x_value) in existing_attrs:
                            continue
                a = IndexObjectAttribute(realm=object_realm,
                                        site=object_site,
                                        object_type=object_type,
                                        name=x_attribute,
                                        value=x_value)
                # If the object already exists in the DB we just have to add the
                # new/changed attribute.
                if index_object:
                    # Reference attribute to existing index object.
                    a.ioid = index_object.id
                    session.add(a)
                else:
                    # Add attribute to list of attributes for the new index object.
                    attributes.append(a)

    if full_acl_update:
        # Get object ACLs.
        try:
            object_acls = object_config['ACLS']
        except KeyError:
            object_acls = []
            full_acl_update = False

    # Add/del ACLs of existing object (update index).
    acls = []
    clear_acl_cache = False
    if full_acl_update and object_acls:
        clear_acl_cache = True
        if index_object:
            existing_acls = session.query(IndexObjectACL.value)
            existing_acls = existing_acls.where(IndexObjectACL.ioid == index_object.id)
            existing_acls = existing_acls.all()
            existing_acls = {row.value for row in existing_acls}
            new_acls = set(object_acls)
            acls_to_delete = existing_acls - new_acls
            acls_to_add = new_acls - existing_acls
            if acls_to_delete:
                del_q = session.query(IndexObjectACL)
                del_q = del_q.filter(IndexObjectACL.ioid == index_object.id)
                del_q = del_q.filter(IndexObjectACL.value.in_(acls_to_delete))
                del_q.delete(synchronize_session=False)
            if acls_to_add:
                for raw_acl in acls_to_add:
                    a = IndexObjectACL(realm=object_realm,
                                    site=object_site,
                                    object_type=object_type,
                                    value=raw_acl)
                    # Reference ACL to existing index object.
                    a.ioid = index_object.id
                    session.add(a)
        else:
            for raw_acl in object_acls:
                a = IndexObjectACL(realm=object_realm,
                                site=object_site,
                                object_type=object_type,
                                value=raw_acl)
                acls.append(a)

        if autocommit:
            session.commit()

    if use_acl_journal and acl_journal:
        # Get existing attributes.
        deleted_acls = []
        existing_acls = []
        if index_object:
            sql_stmt = select(IndexObjectACL.value)
            sql_stmt = sql_stmt.where(IndexObjectACL.ioid == index_object.id)
            existing_acls = session.execute(sql_stmt)
            existing_acls = existing_acls.all()
        # Handle ACL journal.
        clear_acl_cache = True
        for x_entry in acl_journal:
            x_entry_type = x_entry[1]
            x_raw_acl = x_entry[2]

            if x_entry_type == "del":
                if not index_object:
                    continue
                q = session.query(IndexObjectACL)
                q = q.filter(IndexObjectACL.ioid == index_object.id)
                q = q.filter(IndexObjectACL.value == x_raw_acl)
                result = list(q.all())
                if result:
                    deleted_acls.append(x_raw_acl)
                for a in result:
                    session.delete(a)

            # Add attributes.
            if x_entry_type == "add":
                if x_raw_acl not in deleted_acls:
                    if (x_raw_acl,) in existing_acls:
                        continue
                a = IndexObjectACL(realm=object_realm,
                                site=object_site,
                                object_type=object_type,
                                value=x_raw_acl)
                # If the object already exists in the DB we just have to add the
                # new/changed ACL.
                if index_object:
                    # Reference attribute to existing index object.
                    a.ioid = index_object.id
                    session.add(a)
                else:
                    # Add attribute to list of ACLs for the new index object.
                    acls.append(a)

        if autocommit:
            session.commit()

    # Get object LDIF from index DB.
    update_object_ldif = False
    if full_ldif_update:
        if object_ldif:
            update_object_ldif = True
        else:
            full_ldif_update = False

    if use_ldif_journal and index_object and ldif_journal:
        update_object_ldif = True
        object_ldif = json.loads(index_object.ldif)
        for x in ldif_journal:
            x_entry_action = x[1]
            x_entry_data = x[2]
            if x_entry_action == "del":
                for x_data in x_entry_data:
                    x_attr = x_data[0]
                    try:
                        x_val = x_data[1]
                    except IndexError:
                        try:
                            object_ldif.pop(x_attr)
                        except KeyError:
                            pass
                    else:
                        try:
                            cur_vals = object_ldif[x_attr]
                        except KeyError:
                            continue
                        try:
                            cur_vals.remove(x_val)
                        except ValueError:
                            pass
                        if len(cur_vals) == 0:
                            try:
                                object_ldif.pop(x_attr)
                            except KeyError:
                                pass
            elif x_entry_action == "add":
                x_entry_position = x[3]
                for x_data in x_entry_data:
                    x_attr = x_data[0]
                    x_val = x_data[1]
                    try:
                        cur_vals = object_ldif[x_attr]
                    except KeyError:
                        cur_vals = []
                        object_ldif[x_attr] = cur_vals
                    if x_entry_position == -1:
                        cur_vals.append(x_val)
                    else:
                        cur_vals.insert(x_entry_position, x_val)
            else:
                msg = "Unknown action for LDIF journal: %s" % x_entry_action
                raise OTPmeException(msg)

    if full_ldif_update:
        update_object_ldif = True

    # Get object data (e.g. OTPme attributes and fs paths).
    object_name = object_id.name
    object_path = object_id.path
    object_rel_path = object_id.rel_path
    object_paths = json.dumps(object_paths)
    # Sort object LDIF.
    if object_ldif:
        sorted_ldif = OrderedDict()
        for key in sorted(object_ldif):
            sorted_ldif[key] = object_ldif[key]
        try:
            sorted_ldif.move_to_end("dn", last=False)
        except  KeyError:
            pass
        try:
            sorted_ldif.move_to_end("modifyTimestamp")
        except  KeyError:
            pass
        object_ldif = dict(sorted_ldif)
    object_ldif = json.dumps(object_ldif)

    # If the index object already exists we have to make sure that all
    # attributes are updated (e.g on object rename).
    if index_object:
        if index_object.realm != object_realm:
            index_object.realm = object_realm
        if index_object.site != object_site:
            index_object.site = object_site
        if index_object.name != object_name:
            index_object.name = object_name
        if index_object.read_oid != object_id.read_oid:
            index_object.read_oid = object_id.read_oid
        if index_object.full_oid != object_id.full_oid:
            index_object.full_oid = object_id.full_oid
        if index_object.object_type != object_type:
            index_object.object_type = object_type
        if index_object.path != object_path:
            index_object.path = object_path
        if index_object.rel_path != object_rel_path:
            index_object.rel_path = object_rel_path
        if index_object.fs_paths != object_paths:
            index_object.fs_paths = object_paths
        if index_object.checksum != checksum:
            index_object.checksum = checksum
        if index_object.sync_checksum != sync_checksum:
            index_object.sync_checksum = sync_checksum
        if index_object.template != template:
            index_object.template = template
        if last_modified:
            index_object.last_modified = last_modified
        if update_object_ldif:
            if index_object.ldif != object_ldif:
                index_object.ldif = object_ldif
    else:
        index_object = IndexObject(uuid=uuid,
                                realm=object_realm,
                                site=object_site,
                                name=object_name,
                                full_oid=object_id.full_oid,
                                read_oid=read_oid,
                                object_type=object_type,
                                path=object_path,
                                rel_path=object_rel_path,
                                attributes=attributes,
                                acls=acls,
                                fs_paths=object_paths,
                                checksum=checksum,
                                sync_checksum=sync_checksum,
                                ldif=object_ldif,
                                last_modified=last_modified,
                                template=template)
        # Add object to index.
        session.add(index_object)
        #local_object = session.merge(index_object)
        #session.add(local_object)

    # Commit changes.
    if autocommit:
        session.commit()

    # Make sure caches get cleared.
    clear_index_caches(object_id)
    if clear_acl_cache:
        if index_object.uuid:
            index_acl_cache.invalidate(index_object.uuid)

@handle_transaction
def index_del(object_id, no_lock=False,
    autocommit=True, session=None, **kwargs):
    """ Delete object from index. """
    # FIXME: does this work with index_get_object() instead of the code below?? -> remove
    # Get index object.
    index_object = index_get_object(object_id)
    # Make sure caches get cleared.
    if index_object:
        # Delete object from DB.
        session.delete(index_object)
        if autocommit:
            session.commit()
        # Clear ACL cache.
        if index_object.uuid:
            index_acl_cache.invalidate(index_object.uuid)
    # Make sure caches get cleared.
    clear_index_caches(object_id)

@index_cache.cache_function()
def index_get(object_id, no_lock=False):
    """ Get object config file path. """
    index_object = index_get_object(object_id)
    if not index_object:
        return
    config_paths = json.loads(index_object.fs_paths)
    return config_paths['config_file']

# FIXME: caching of this function does not work. why?
@handle_transaction
@index_cache.cache_function()
def index_get_object(object_id=None, object_type=None,
    uuid=None, session=None, **kwargs):
    """ Get index object from DB. """
    if not object_id and not uuid:
        raise Exception("Need <object_id> or <uuid>.")

    if not uuid and not object_type and not object_id:
        msg = "Need <object_id> or <object_type>."
        raise OTPmeException(msg)

    if uuid and not object_id:
        object_id = get_oid(uuid, instance=True)

    if not object_id:
        return

    object_type = object_id.object_type

    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise OTPmeException(msg)

    # Get query.
    q = session.query(IndexObject)

    if object_id:
        # Get read OID of object.
        read_oid = object_id.read_oid
        # Name uniq objects must be searched by object type/name because they may
        # be referenced via their realtive read OID (e.g. user|realm/site/root).
        object_type = object_id.object_type
        if object_type in config.name_uniq_objects:
            object_realm = None
            if object_type != "realm":
                object_realm = object_id.realm
            object_site = None
            if object_type != "realm" and object_type != "site":
                object_site = object_id.site
            object_name = object_id.name
            if object_realm:
                q = q.filter(IndexObject.realm == object_realm)
            if object_site:
                q = q.filter(IndexObject.site == object_site)
            x = q.filter(IndexObject.object_type == object_type,
                            IndexObject.name == object_name)
        else:
            x = q.filter(IndexObject.read_oid == read_oid)
    else:
        x = q.filter(IndexObject.uuid == uuid)

    # Get index object.
    index_object = x.first()

    if not index_object:
        return

    ## Add session to index object that could be used to e.g. delete the object.
    #index_object.session = session

    return index_object

def rebuild_object_index(object_type, objects, after=[]):
    """ Rebuild search index of given object type. """
    if object_type not in objects:
        return
    for x in after:
        if x not in objects:
            continue
        return False
    for x in objects[object_type]:
        object_id = x[0]
        config_file = x[1]
        log_current_object.message = "Processing %s" % object_id.object_type
        log_current_object(config_file)
        index_add(object_id=object_id,
                object_config="auto",
                full_index_update=True,
                full_ldif_update=True,
                full_acl_update=True)
    objects.pop(object_type)

def index_rebuild():
    """ Rebuild index. """
    from otpme.lib import init_otpme
    from otpme.lib.register import register_modules
    from otpme.lib.backends.file.index import INDEX_DIR
    global init
    # Register modules.
    register_modules()

    logger.info("Starting index rebuild...")

    # Get index module.
    _index = config.get_index_module()

    # Backup last used timestamps.
    index_rebuild_data = None
    index_rebuild_data_file = os.path.join(config.spool_dir, "rebuild.json")
    if os.path.exists(INDEX_DIR):
        if not _index.status():
            _index.start()
        # Make sure DB classes are loaded.
        init()
        if os.path.exists(index_rebuild_data_file):
            index_rebuild_data = filetools.read_file(index_rebuild_data_file)
            index_rebuild_data = json.loads(index_rebuild_data)
        else:
            last_used_data = index_search(attribute="uuid",
                                            value="*",
                                            return_attributes=["uuid",
                                                            'object_type',
                                                            "last_used"])
            index_rebuild_data = {}
            for x_uuid in dict(last_used_data):
                x_last_used = last_used_data[x_uuid]['last_used']
                if x_last_used is None:
                    continue
                x_object_type = last_used_data[x_uuid]['object_type']
                try:
                    x_objects = index_rebuild_data[x_object_type]
                except KeyError:
                    x_objects = {}
                    index_rebuild_data[x_object_type] = x_objects
                x_objects[x_uuid] = x_last_used
            file_content = json.dumps(index_rebuild_data)
            filetools.create_file(index_rebuild_data_file, file_content)

        # Stop index DB. This also clears current connections.
        _index.stop()

    _index.command("drop")
    _index.command("init")

    # Make sure DB is created etc.
    init()

    objects_dir = get_data_dir("objects")

    all_objects = {}
    log_current_object.counter = 0
    log_current_object.file_count = 0
    for i in os.walk(objects_dir):
        config_dir = i[0]
        if config_dir == objects_dir:
            continue
        object_id = get_oid_from_path(config_dir)
        object_type = object_id.object_type
        try:
            object_settings[object_type]['index_rebuild']['tree']
        except:
            msg = "Missing rebuild function for object type: %s" % object_type
            raise OTPmeException(msg)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        log_current_object.file_count += 1
        try:
            objects = all_objects[object_type]
        except:
            objects = []
        objects.append((object_id, config_file))
        all_objects[object_type] = objects

    # Rebuild index of in-tree objects.
    while True:
        for object_type in object_settings:
            try:
                rebuild_function = object_settings[object_type]['index_rebuild']['tree']
            except:
                continue
            rebuild_function(all_objects)
        if not all_objects:
            break

    # Init OTPme.
    config.use_api = True
    init_otpme()

    msg = ("Searching out of tree objects (OTPs, signatures etc.)...")
    logger.debug(msg)

    # Rebuild index of in-tree objects.
    for object_type in object_settings:
        try:
            rebuild_function = object_settings[object_type]['index_rebuild']['flat']
        except:
            continue
        rebuild_function()

    # Set last used timestamps.
    if index_rebuild_data:
        for object_type in index_rebuild_data:
            last_used_data = index_rebuild_data[object_type]
            set_last_used_times(object_type, last_used_data)

    # Remove last used data file.
    if os.path.exists(index_rebuild_data_file):
        filetools.delete(index_rebuild_data_file)

    _index.command("create_db_indices")

    logger.info("Finished index rebuild.")
    return True

@oid_from_path_cache.cache_function()
def get_oid_from_path(path):
    oid_getters = []
    for object_type in object_settings:
        x_getter = object_settings[object_type]['oid_getter']
        if not x_getter:
            continue
        oid_getters.append(x_getter)
    for x_getter in oid_getters:
        object_id = x_getter(path)
        if not object_id:
            continue
        break
    return object_id

def get_sites(realm, search_regex=None):
    """ Get sites of given realm. """
    site_list = []

    if search_regex:
        sitename_re = re.compile(search_regex)

    realm_oid = oid.get(object_type="realm", name=realm)
    realm_dir = get_config_paths(realm_oid)['config_dir']

    if not os.path.exists(realm_dir):
        return site_list

    # Get list of all sites via directory listing.
    for s in filetools.list_dir(realm_dir):
        if not s.endswith("site"):
            continue
        x = '^(.*)\.site'
        site_name = re.sub(x, r'\1', s)
        site_oid = oid.get(object_type="site", realm=realm, name=site_name)
        if not object_exists(site_oid):
            continue
        if search_regex:
            if sitename_re.match(site_oid.name):
                site_list.append(site_oid)
        else:
            site_list.append(site_oid)
    # Sort site list.
    site_list.sort()
    return site_list

def get_last_used(uuid, **kwargs):
    index_object = index_get_object(uuid=uuid)
    if not index_object:
        return
    last_used = index_object.last_used
    if last_used is None:
        last_used = 0
    return last_used

@handle_transaction
def set_last_used_times(object_type, updates, session=None, **kwargs):
    from sqlalchemy import case
    from sqlalchemy import update
    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise SearchException(msg)

    when_conditions = [
        (IndexObject.uuid == uuid, last_used)
        for uuid, last_used in updates.items()
    ]

    stmt = update(IndexObject)
    stmt = stmt.where(IndexObject.uuid.in_(updates.keys()))
    stmt = stmt.values(last_used=case(*when_conditions))

    session.execute(stmt)
    session.commit()

@handle_transaction
def set_last_used(object_type, uuid, timestamp,
    session=None, cluster=True, **kwargs):
    from sqlalchemy import update
    from otpme.lib.daemon.clusterd import cluster_sync_object
    try:
        IndexObject, \
        IndexObjectAttribute, \
        IndexObjectACL = get_class(object_type)
    except UnknownClass:
        msg = "Unknown object class: %s" % object_type
        raise SearchException(msg)
    # Update last used timestamp.
    stmt = update(IndexObject)
    stmt = stmt.where(IndexObject.uuid == uuid)
    stmt = stmt.values(last_used=timestamp)
    session.execute(stmt)
    # Commit change.
    session.commit()
    if not cluster:
        return
    if config.host_type != "node":
        return
    object_id = get_oid(uuid, instance=True)
    cluster_sync_object(action="last_used_write",
                        object_uuid=uuid,
                        object_id=object_id,
                        object_data=timestamp,
                        wait_for_write=False)

def get_last_used_times(object_types):
    last_used_data = {}
    for object_type in object_types:
        result = index_search(realm=config.realm,
                            site=config.site,
                            attribute="uuid",
                            value="*",
                            object_type=object_type,
                            return_attributes=["uuid", "last_used"])
        if not result:
            continue
        if object_type not in last_used_data:
            last_used_data[object_type] = {}
        for x_uuid in result:
            x_last_used = result[x_uuid]['last_used']
            if x_last_used is None:
                continue
            last_used_data[object_type][x_uuid] = x_last_used
    return last_used_data

@handle_transaction
def set_checksum(object_id, checksum=None, sync_checksum=None, session=None, **kwargs):
    index_object = index_get_object(object_id=object_id)
    if not index_object:
        return
    object_changed = False
    if checksum:
        if index_object.checksum != checksum:
            object_changed = True
            index_object.checksum = checksum
    if sync_checksum:
        if index_object.sync_checksum != sync_checksum:
            object_changed = True
            index_object.sync_checksum = sync_checksum
    if not object_changed:
        return
    index_object = session.merge(index_object)
    session.add(index_object)
    session.commit()
