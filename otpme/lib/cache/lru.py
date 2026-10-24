# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib.exceptions import *

class LRUCache(dict):
    """ Handle cache access by proc ID. """
    def __init__(self, cache=None):
        if cache is None:
            cache = {}
        self.cache = cache
        self.lru_data = {}
        # One cache for the whole process, and a daemon that serves its
        # connections in threads (authd, syncd) adds to it from all of
        # them. Without the lock one thread removes what another one is
        # just sorting out or removing itself, and that is a KeyError.
        self.lock = threading.RLock()
        # A new one in a forked child: one held by another thread at the
        # fork would be held there for good, and nobody is left to free it.
        os.register_at_fork(after_in_child=self.new_lock)
        #self.iter_list = None

    def new_lock(self):
        self.lock = threading.RLock()

    #def __iter__(self):
    #    # Get proc ID.
    #    proc_id = self.get_proc_id()
    #    # Get cache.
    #    self.iter_list = sorted(self.cache)
    #    return self

    #def next(self):
    #    try:
    #        current_item = self.iter_list.pop(0)
    #    except:
    #        raise StopIteration()
    #    return current_item

    def __setitem__(self, object_id, item):
        self.add(object_id, item)

    def __getitem__(self, object_id):
        item = self.get(object_id)
        return item

    #def __repr__(self):
    #    return repr(self.__dict__)

    def __len__(self):
        return len(self.cache)

    def __delitem__(self, object_id):
        self.delete(object_id)

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.lru_data.clear()

    #def copy(self):
    #    return self.__dict__.copy()

    def has_key(self, object_id):
        return object_id in self.cache

    #def update(self, *args, **kwargs):
    #    return self.__dict__.update(*args, **kwargs)

    def keys(self):
        return self.cache.keys()

    def values(self):
        return self.cache.values()

    def items(self):
        return self.cache.items()

    def pop(self, *args):
        return self.delete(*args)

    def __contains__(self, item):
        return item in self.cache

    def __iter__(self):
        return iter(self.cache)

    def add(self, object_id, object_data):
        """ Add object to cache. """
        with self.lock:
            self._add(object_id, object_data)

    def _add(self, object_id, object_data):
        from otpme.lib import config
        self.cache[object_id] = object_data
        object_type = object_data['TYPE']
        # Add timestamp.
        if object_type not in self.lru_data:
            self.lru_data[object_type] = {}
        self.lru_data[object_type][object_id] = time.time()
        # Handle cache limits.
        cache_limit = config.cache_objects[object_type]
        if isinstance(cache_limit, bool):
            return
        # Count objects.
        object_count = len(self.lru_data[object_type])
        # Remove old objects from cache if cache limit is reached.
        if object_count <= cache_limit:
            return
        # Remove 1/4 of the cache. A whole number: with a limit of
        # OBJECT_CACHES that is not divisible by 4 the count was never
        # reached, and every object of the type went.
        remove_count = max(1, cache_limit // 4)
        # Sort by access time.
        sort_func = lambda x: str(self.lru_data[object_type][x])
        sorted_oids = sorted(self.lru_data[object_type], key=sort_func)
        # Remove outdated objects.
        counter = 0
        for x in sorted_oids:
            if counter == remove_count:
                break
            self.delete(x)
            counter += 1

    def get(self, object_id):
        """ Get cache. """
        with self.lock:
            object_data = self.cache[object_id]
            # Cache hit.
            object_type = object_data['TYPE']
            self.lru_data[object_type][object_id] = time.time()
            return object_data

    def delete(self, object_id):
        """ Del object from cache. """
        with self.lock:
            object_data = self.cache.pop(object_id)
            object_type = object_data['TYPE']
            self.lru_data[object_type].pop(object_id)
            return object_data

