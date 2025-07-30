# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import pprint

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import filetools
from otpme.lib import multiprocessing
from otpme.lib.cache.lru import LRUCache
from otpme.lib.pickle import PickleHandler
from otpme.lib.cache.funccache import FuncCache

from otpme.lib.exceptions import *

ACL_CACHE = "acl"
PROCESS_CACHE = "instance"
MULTIPROCESSING_CACHE = "multiprocessing"

ACL_CACHE_LOCK_TYPE = "cache.acl"
LIST_CACHE_LOCK_TYPE = "cache.list"

default_callback = config.get_callback()

last_process_cache_clear_time = 0.0

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
        'otpme.lib.cache.redis',
        'otpme.lib.cache.dogpile',
        'otpme.lib.cache.memcached',
        'otpme.lib.cache.memcachedb',
        ]

def register():
    """ Register modules. """
    from otpme.lib.register import _register_modules
    # Register lock types.
    locking.register_lock_type(ACL_CACHE_LOCK_TYPE, module=__file__)
    locking.register_lock_type(LIST_CACHE_LOCK_TYPE, module=__file__)
    # Register shared objects.
    multiprocessing.register_shared_dict("acl_cache")
    multiprocessing.register_shared_dict("instance_cache", pickle=True)
    multiprocessing.register_shared_list("acl_cache_clear_queue")
    multiprocessing.register_shared_dict("function_cache_clear_trigger")
    # Register cache modules.
    _register_modules(modules)

# All modified (cached) instances.
modified_objects = {}
modified_objects_cache = {}

# Function/method caches.
search_cache = FuncCache(name="search_cache",
                        default_cache="default",
                        copy_cache=True)
pass_hash_cache = FuncCache(name="pass_hash_cache",
                            default_cache="default",
                            copy_cache=True,
                            maxsize=40960,
                            shared=True)
ldap_schema_cache = FuncCache(name="ldap_schema_files",
                            default_cache="default")
oid_from_path_cache = FuncCache(name="oid_from_path_cache",
                                default_cache="default")
index_cache = FuncCache(name="index_cache",
                        default_cache="default",
                        ignore_args=['session'],
                        ignore_classes=['OTPmeOid'])
# Get cache handler.
process_cache = LRUCache()

caches = []
# Methods to configure on init().
ldif_cache = FuncCache(name="ldif_cache")
config_cache = FuncCache(name="config_cache")
#instance_cache = FuncCache(name="instance_cache")
index_acl_cache = FuncCache(name="index_acl_cache")
unit_members_cache = FuncCache(name="unit_members")
object_list_cache = FuncCache(name="object_list_cache")
ldap_search_cache = FuncCache(name="ldap_search_cache")
supported_acls_cache = FuncCache(name="supported_acls")
assigned_role_cache = FuncCache(name="assigned_role", shared=True)
assigned_token_cache = FuncCache(name="assigned_token", shared=True)
index_search_cache = FuncCache(name="index_search_cache", copy_cache=True)

def enable():
    """ Enable caches. """
    from otpme.lib import config
    config.cache_enabled = True

def disable():
    """ Disable cache. """
    from otpme.lib import config
    config.cache_enabled = False

def init():
    """ Init caches. """
    from otpme.lib import config
    global caches
    global ldif_cache
    global config_cache
    #global instance_cache
    global index_acl_cache
    global ldap_search_cache
    global object_list_cache
    global index_search_cache
    global assigned_role_cache
    global assigned_token_cache
    global supported_acls_cache
    ## Add instance cache with per object type caching.
    #def get_object_type(func_args, func_kwargs):
    #    """ Get object type from function args. """
    #    try:
    #        object_type = func_kwargs['object_type']
    #    except:
    #        try:
    #            object_id = func_kwargs['object_id']
    #        except:
    #            msg = "Unable to find object ID."
    #            raise NoMatch(msg)
    #        try:
    #            object_type = object_id.object_type
    #        except:
    #            msg = "Unable to find object type in func args."
    #            raise NoMatch(msg)
    #    return object_type

    #object_caches = {}
    #for x in config.cache_objects:
    #    maxsize = config.cache_objects[x]
    #    # Caching disabled for this object type.
    #    if maxsize is False:
    #        continue
    #    object_caches[x] = {}
    #    object_caches[x]['maxsize'] = maxsize
    #    object_caches[x]['cache_type'] = "lru"
    #    object_caches[x]['ignore_classes'] = ['OTPmeBaseObject', 'OTPmeOid']
    #instance_cache._cache_kwargs['caches'] = object_caches
    #instance_cache._cache_kwargs['cache_name_func'] = get_object_type

    # Add search cache with separate cache for tree, data and session objects.
    def get_cache_name(func_args, func_kwargs):
        """ Get object type from function args to build cache name. """
        try:
            object_type = func_kwargs['object_type']
        except:
            object_type = None
        if not object_type:
            msg = "Unable to find object type in function args."
            raise NoMatch(msg)
        cache_name = None
        if object_type == "session":
            cache_name = object_type
        elif object_type in config.tree_object_types:
            cache_name = "tree_object"
        else:
            cache_name = "data_object"
        return cache_name

    object_caches = {}
    object_caches['session'] = {}
    object_caches['session']['cache_type'] = "lru"
    object_caches['session']['ignore_args'] = ["session"]
    object_caches['session']['ignore_classes'] = ["OTPmeOid"]
    object_caches['data_object'] = {}
    object_caches['data_object']['cache_type'] = "lru"
    object_caches['data_object']['ignore_args'] = ["session"]
    object_caches['data_object']['ignore_classes'] = ["OTPmeOid"]
    object_caches['tree_object'] = {}
    object_caches['tree_object']['cache_type'] = "lru"
    object_caches['tree_object']['ignore_args'] = ["session"]
    object_caches['tree_object']['ignore_classes'] = ["OTPmeOid"]
    index_search_cache._cache_kwargs['caches'] = object_caches
    index_search_cache._cache_kwargs['cache_name_func'] = get_cache_name

    # LDAP searcb cache used in ldaptor.
    def get_uniq_method_name(cls, func_name, func_args, func_kwargs):
        """ Get uniq class name. """
        method_id = ("%s.%s().%s()"
                    % (cls.__module__,
                    cls.__class__.__name__,
                    func_name))
        return method_id
    ldap_search_cache.cache_key_func = get_uniq_method_name
    ldap_search_cache._cache_kwargs['copy_cache'] = True
    #ldap_search_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']

    # Add ACL cache with separate per object UUID.
    def get_cache_name(func_args, func_kwargs):
        """ Get object UUID function args to build cache name. """
        cache_name = func_kwargs['o_uuid']
        return cache_name
    index_acl_cache._cache_kwargs['cache_name_func'] = get_cache_name
    index_acl_cache._cache_kwargs['ignore_args'] = ['session', 'acl_class']

    # Add list cache with separate cache for tree, data and session objects.
    def get_uniq_method_name(cls, func_name, func_args, func_kwargs):
        """ Get uniq class name. """
        object_type = func_args[0]
        method_id = "%s:%s:%s:%s" % (cls.__module__,
                            cls.__class__.__name__,
                            func_name,
                            object_type)
        return method_id
    def get_cache_name(func_args, func_kwargs):
        """ Get object type from function args to build cache name. """
        object_type = func_args[0]
        return object_type
    object_list_cache.cache_key_func = get_uniq_method_name
    object_list_cache._cache_kwargs['cache_name_func'] = get_cache_name

    # Add object list caches.
    def get_uniq_method_name(cls, func_name, func_args, func_kwargs):
        """ Get uniq class name. """
        method_id = ("%s (%s.%s().%s())"
                    % (cls.oid.full_oid,
                    cls.__module__,
                    cls.__class__.__name__,
                    func_name))
        return method_id
    # LDIF cache.
    ldif_cache.cache_key_func = get_uniq_method_name
    ldif_cache._cache_kwargs['ignore_args'] = ['callback']
    ldif_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']
    # Config cache.
    config_cache.cache_key_func = get_uniq_method_name
    config_cache._cache_kwargs['ignore_args'] = ['callback']
    config_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']
    # Supported ACLs cache.
    supported_acls_cache.cache_key_func = get_uniq_method_name
    supported_acls_cache._cache_kwargs['ignore_args'] = ['callback']
    supported_acls_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']
    # Assigned role cache.
    assigned_role_cache.cache_key_func = get_uniq_method_name
    assigned_role_cache._cache_kwargs['ignore_args'] = ['callback']
    assigned_role_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']
    # Assigned token cache.
    assigned_token_cache.cache_key_func = get_uniq_method_name
    assigned_token_cache._cache_kwargs['ignore_args'] = ['callback']
    assigned_token_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']
    # Unit members cache.
    unit_members_cache.cache_key_func = get_uniq_method_name
    unit_members_cache._cache_kwargs['ignore_args'] = ['callback']
    unit_members_cache._cache_kwargs['ignore_classes'] = ['OTPmeBaseObject']

    # All caches to clear on flush().
    caches = [
            ldif_cache,
            index_cache,
            search_cache,
            #instance_cache,
            # ACL cache gets cleared by UUID and expiry.
            #index_acl_cache,
            pass_hash_cache,
            object_list_cache,
            ldap_schema_cache,
            index_search_cache,
            unit_members_cache,
            oid_from_path_cache,
            assigned_role_cache,
            assigned_token_cache,
            supported_acls_cache,
            ]

def set_cache_clear_time(clear_time):
    if not os.path.exists(config.cache_clear_file):
        filetools.touch(config.cache_clear_file)
    os.utime(config.cache_clear_file, (clear_time, clear_time))

def get_cache_clear_time():
    if not os.path.exists(config.cache_clear_file):
        filetools.touch(config.cache_clear_file)
    clear_time = os.path.getmtime(config.cache_clear_file)
    return clear_time

# Shared cache uses pickle and pickle is to slow!!!!!    
def add_instance(instance, skip_shared_cache=True):
    """ Update instance caches. """
    from otpme.lib import config
    if not config.cache_enabled:
        return
    if not instance.oid:
        msg = "Unable to add object without OID: %s" % instance
        raise OTPmeException(msg)
    if not instance.oid.read_oid:
        msg = "Unable to add object without read OID: %s" % instance.oid
        raise OTPmeException(msg)
    if not instance.oid.full_oid:
        msg = "Unable to add object without full OID: %s" % instance.oid
        raise OTPmeException(msg)
    read_oid = instance.oid.read_oid
    full_oid = instance.oid.full_oid
    object_type = instance.type
    object_checksum = instance.checksum

    ## Clear object cache.
    #instance_cache.invalidate(object_type)
    # Clear search cache.
    search_cache.invalidate()
    if object_type in config.tree_object_types:
        # Clear ldif cache.
        ldif_cache.invalidate()
        # Clear LDAP cache.
        ldap_search_cache.invalidate()

    # We will not update multiprocessing cache with an modified object.
    if instance._modified:
        skip_shared_cache = True
    # Non-pickable objects cannot be cached between processes or on-disk.
    if not instance.pickable:
        skip_shared_cache = True

    # Check current cache object checksum.
    try:
        old_checksum = process_cache[read_oid]['CHECKSUM']
    except:
        old_checksum = None

    # Update process cache.
    update_process_cache = False
    if object_checksum != old_checksum:
        update_process_cache = True

    if read_oid not in process_cache:
        update_process_cache = True

    if update_process_cache:
        new_instance_cache = {
                             'OID'                  : full_oid,
                             'TYPE'                 : instance.type,
                             'INSTANCE'             : instance,
                             'CHECKSUM'             : object_checksum,
                            }
        process_cache[read_oid] = new_instance_cache

    if skip_shared_cache:
        return

    # Update multiprocessing cache.
    try:
        old_checksum = multiprocessing.instance_cache[read_oid]['CHECKSUM']
    except:
        old_checksum = None

    # Check current instance object checksum.
    if object_checksum != old_checksum:
        # Add object to cache.
        new_cache_entry = {
                            'OID'                   : full_oid,
                            'INSTANCE'              : instance,
                            'CHECKSUM'              : object_checksum,
                        }
        try:
            expire_time = instance.cache_expire_time
        except AttributeError:
            expire_time = None
        if expire_time is None:
            multiprocessing.instance_cache[read_oid] = new_cache_entry
        else:
            multiprocessing.instance_cache.add(key=read_oid,
                                            value=new_cache_entry,
                                            expire=expire_time)

def get_instance(object_id, cache_type=None):
    """ Get instance from object cache. """
    from otpme.lib import config
    from otpme.lib import backend
    global last_process_cache_clear_time
    if not config.cache_enabled:
        return
    logger = config.logger
    read_oid = object_id.read_oid

    instance = get_modified_object(object_id)
    if instance:
        return instance

    check_process_cache = True
    check_multiprocessing_cache = True
    if cache_type and cache_type != PROCESS_CACHE:
        check_process_cache = False
    if cache_type and cache_type != MULTIPROCESSING_CACHE:
        check_multiprocessing_cache = False

    # Try to get instance cache entry.
    if check_process_cache:
        clear_time = get_cache_clear_time()
        if last_process_cache_clear_time != clear_time:
            clear(cache_type=PROCESS_CACHE, update_clear_time=False)
            last_process_cache_clear_time = clear_time
        try:
            cache_entry = process_cache[read_oid]
            _cache_type = PROCESS_CACHE
            cache_name = "memory"
        except:
            cache_entry = None
        # For modified objects from process cache we do
        # not need any further checking.
        try:
            _instance = cache_entry['INSTANCE']
        except:
            _instance = None
        #if _instance and _instance._modified:
        if _instance:
            return _instance
        else:
            cache_entry = None

    # Try to get multiprocessing cache entry.
    if not cache_entry and check_multiprocessing_cache:
        try:
            cache_entry = multiprocessing.instance_cache[read_oid]
            _cache_type = MULTIPROCESSING_CACHE
            cache_name = "multiprocessing"
        except:
            cache_entry = None

    # Get checksums of cached object.
    try:
        cached_checksum = cache_entry['CHECKSUM']
    except:
        return None

    # Remove outdated cache entry.
    object_outdated = False
    object_checksum = backend.get_checksum(object_id)
    if cached_checksum != object_checksum:
        object_outdated = True

    if object_outdated:
        if _cache_type == PROCESS_CACHE:
            try:
                process_cache.pop(read_oid)
            except:
                pass

        if _cache_type == MULTIPROCESSING_CACHE:
            try:
                multiprocessing.instance_cache.pop(read_oid)
            except:
                pass

        return None

    if config.debug_level("object_caching") > 0:
        msg = ("Reading object from %s cache: %s"
                    % (cache_name, read_oid))
        if cache_name == "memory":
            logger.info(msg)
        if cache_name == "multiprocessing":
            logger.warning(msg)

    # Get instance from cache entry.
    instance = cache_entry['INSTANCE']

    skip_shared_cache = False
    if _cache_type == MULTIPROCESSING_CACHE:
        # If the instance comes from the shared (multiprocessing) cache
        # we can update it in the cache of this process but should not write
        # it back/again in the multiprocessing cache.
        skip_shared_cache = True

    if object_id.read_oid != instance.oid.read_oid:
        return None

    # Update instance caches with object we got from other cache.
    if _cache_type != PROCESS_CACHE:
        add_instance(instance=instance,
                    skip_shared_cache=skip_shared_cache)
    return instance

def dump_instance_cache(object_id=None, search_regex=None):
    """ Dump instance cache. """
    object_ids = []
    if object_id:
        if not object_id in multiprocessing.instance_cache:
            raise Exception("Object ID not in cache: %s" % object_id)
        object_ids.append(object_id)
    else:
        if search_regex:
            search_re = re.compile(search_regex)
        for o in multiprocessing.instance_cache:
            add_object = True
            if search_regex:
                if not search_re.match(o):
                    add_object = False
            if add_object:
                object_ids.append(o)

    pickle_handler = PickleHandler("auto", encode=False)

    data = {}
    for o in object_ids:
        checksum = multiprocessing.instance_cache[o]['CHECKSUM']
        instance = multiprocessing.instance_cache[o]['INSTANCE']
        instance = pickle_handler.loads(instance)
        object_config = instance.object_config
        entry = {
                    'CHECKSUM'      : checksum,
                    'OBJECT_CONFIG' : object_config,
                }
        data[o] = entry

    dump_data = pprint.pformat(data)
    return dump_data

def add_acl(object_uuid, token_uuid, acl, status):
    """ Add ACL status to cache. """
    try:
        object_acl_cache = multiprocessing.acl_cache[object_uuid]
    except:
        object_acl_cache = {}
    try:
        token_acl_cache = object_acl_cache[token_uuid]
    except:
        token_acl_cache = {}

    token_acl_cache[acl] = status
    object_acl_cache[token_uuid] = token_acl_cache
    multiprocessing.acl_cache[object_uuid] = object_acl_cache

def get_acl(object_uuid, token_uuid, acl):
    """ Get object ACL result from cache. """
    # Make sure outdated ACL caches are removed.
    clear_outdated_acl_cache()
    try:
        object_acl_cache = multiprocessing.acl_cache[object_uuid]
    except:
        object_acl_cache = {}
    try:
        access_status = object_acl_cache[token_uuid][acl]
    except:
        access_status = None
    return access_status

def outdate_acl_cache(object_uuid=None, token_uuid=None):
    """ Make sure ACL caches are cleared. """
    clear_tuple = (object_uuid, token_uuid)
    try:
        _list = multiprocessing.acl_cache_clear_queue
    except:
        _list = []
    if clear_tuple in _list:
        return
    multiprocessing.acl_cache_clear_queue.append(clear_tuple)

def clear_outdated_acl_cache():
    """ Remove outdated ACL from cache. """
    lock = locking.acquire_lock(lock_type=ACL_CACHE_LOCK_TYPE, lock_id="clear")
    for clear_tuple in list(multiprocessing.acl_cache_clear_queue):
        try:
            multiprocessing.acl_cache_clear_queue.remove(clear_tuple)
        except ValueError:
            pass
        object_uuid = clear_tuple[0]
        token_uuid = clear_tuple[1]
        clear_acl_cache(object_uuid=object_uuid, token_uuid=token_uuid)
    lock.release_lock()

def clear_acl_cache(object_uuid=None, token_uuid=None):
    """ Clear objects ACL cache. """
    if object_uuid:
        object_uuids = [object_uuid]
    else:
        object_uuids = list(multiprocessing.acl_cache)

    for uuid in object_uuids:
        if token_uuid:
            try:
                object_acl_cache = multiprocessing.acl_cache[uuid]
            except:
                object_acl_cache = {}
            try:
                object_acl_cache.pop(token_uuid)
            except:
                pass
            multiprocessing.acl_cache[uuid] = object_acl_cache
        else:
            try:
                multiprocessing.acl_cache.pop(uuid)
            except:
                pass

def dump_acl_cache(object_id=None, search_regex=None):
    """ Dump ACL cache. """
    from otpme.lib import backend
    data = {}
    for uuid in multiprocessing.acl_cache:
        object_oid = backend.get_oid(uuid)
        if object_id:
            if object_oid != object_id:
                continue
        if search_regex:
            search_re = re.compile(search_regex)
            if not search_re.match(object_oid):
                continue
        acls = {}
        for acl_uuid in multiprocessing.acl_cache[uuid]:
            acl_oid = backend.get_oid(acl_uuid)
            acl_data = multiprocessing.acl_cache[uuid][acl_uuid]
            acls[acl_oid] = acl_data
        data[object_oid] = acls

    dump_data = pprint.pformat(data)
    return dump_data

def add_modified_object(o):
    """ Add modified object to cache. """
    read_oid = o.oid.read_oid
    proc_id = multiprocessing.get_id()
    if not proc_id in modified_objects:
        modified_objects[proc_id] = []
    if not proc_id in modified_objects_cache:
        modified_objects_cache[proc_id] = {}
    if not read_oid in modified_objects[proc_id]:
        modified_objects[proc_id].append(read_oid)
    modified_objects_cache[proc_id][read_oid] = o
    add_instance(instance=o, skip_shared_cache=True)

def get_modified_object(object_id):
    """ Get cached (modified) object. """
    global modified_objects
    global modified_objects_cache
    read_oid = object_id.read_oid
    proc_id = multiprocessing.get_id()
    try:
        o = modified_objects_cache[proc_id][read_oid]
    except:
        return
    return o

def remove_modified_object(object_id):
    """ Get cached object. """
    global modified_objects
    global modified_objects_cache
    read_oid = object_id.read_oid
    proc_id = multiprocessing.get_id()
    try:
        modified_objects[proc_id].remove(read_oid)
    except:
        pass
    try:
        modified_objects_cache[proc_id].pop(read_oid)
    except:
        pass
    clear(object_id=object_id, cache_type=PROCESS_CACHE, keep_modified=False)

def flush(commit=True, callback=default_callback, quiet=True):
    """ Clear all method caches. """
    from otpme.lib import oid
    from otpme.lib import config
    global modified_objects
    global modified_objects_cache

    logger = config.logger

    if not quiet:
        msg = "Flushing caches..."
        logger.debug(msg)

    proc_id = multiprocessing.get_id()
    try:
        _modified_objects = modified_objects[proc_id]
    except:
        _modified_objects = []

    # Write changed objects.
    for x in list(_modified_objects):
        object_id = oid.get(x)
        o = get_modified_object(object_id)
        remove_modified_object(object_id)
        if not o or not o._modified:
            continue
        if commit:
            msg = "Writing modified object: %s" % o
            logger.debug(msg)
            o._write(callback=callback)
        else:
            msg = "Discarding changes of modified object: %s" % o
            logger.debug(msg)
            clear(object_id=o.oid, cache_type=PROCESS_CACHE, keep_modified=False)

    # Flush caches.
    for x in caches:
        if config.debug_level() > 5:
            msg = "Flushing cache: %s" % x.name
            logger.debug(msg)
        x.invalidate()

def clear(object_id=None, cache_type=None,
    keep_modified=True, update_clear_time=True, quiet=True):
    """ Clear caches. """
    from otpme.lib import oid
    from otpme.lib import config
    global last_process_cache_clear_time
    logger = config.logger
    if not quiet:
        msg = "Clearing caches..."
        logger.debug(msg)
    clear_cache_types = [
                        MULTIPROCESSING_CACHE,
                        PROCESS_CACHE,
                        ACL_CACHE,
                        ]
    if cache_type is not None:
        clear_cache_types = [cache_type]

    if PROCESS_CACHE in clear_cache_types:
        if update_clear_time:
            clear_time = time.time()
            last_process_cache_clear_time = clear_time
            set_cache_clear_time(clear_time)

    if object_id is None:
        if ACL_CACHE in clear_cache_types:
            clear_acl_cache()
            if len(clear_cache_types) == 1:
                return

    # Get OIDs to clear.
    object_ids = []
    if object_id is not None:
        object_ids.append(object_id)
    else:
        if MULTIPROCESSING_CACHE in clear_cache_types:
            for x in dict(multiprocessing.instance_cache):
                x_oid = oid.get(x)
                if x_oid in object_ids:
                    continue
                object_ids.append(x_oid)
        if PROCESS_CACHE in clear_cache_types:
            for x in dict(process_cache):
                x_oid = oid.get(x)
                if x_oid in object_ids:
                    continue
                object_ids.append(x_oid)

    caches_cleared = {}
    clean_success = False
    for x_oid in object_ids:
        # Clear process cache.
        if PROCESS_CACHE in clear_cache_types:
            clear_instance = True
            # Keep modified object (e.g. used in running job).
            if keep_modified:
                try:
                    cache_entry = process_cache[x_oid.read_oid]
                    x_instance = cache_entry['INSTANCE']
                    if x_instance._modified:
                        clear_instance = False
                except KeyError:
                    clear_instance = False
            if clear_instance:
                try:
                    process_cache.pop(x_oid.read_oid)
                    try:
                        caches_cleared[PROCESS_CACHE] += 1
                    except:
                        caches_cleared[PROCESS_CACHE] = 1
                    clean_success = True
                except KeyError:
                    pass
        # Clear multiprocessing instance cache.
        if MULTIPROCESSING_CACHE in clear_cache_types:
            try:
                multiprocessing.instance_cache.pop(x_oid.read_oid)
                try:
                    caches_cleared[MULTIPROCESSING_CACHE] += 1
                except:
                    caches_cleared[MULTIPROCESSING_CACHE] = 1
                clean_success = True
            except KeyError:
                pass

    if clean_success:
        if config.debug_level("object_caching") > 2:
            for x_cache in caches_cleared:
                x_count = caches_cleared[x_cache]
                msg = ("Cleared %s objects from %s cache."
                        % (x_count, x_cache))
                logger.debug(msg)
    return clean_success
