# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

class LRUCache(dict):
    """ Handle cache access by proc ID. """
    def __init__(self, cache={}):
        self.cache = cache
        self.lru_data = {}
        #self.iter_list = None

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
        self.cache.clear()

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
        # Remove 1/4 of the cache.
        remove_count = cache_limit / 4
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
        object_data = self.cache[object_id]
        # Cache hit.
        object_type = object_data['TYPE']
        self.lru_data[object_type][object_id] = time.time()
        return object_data

    def delete(self, object_id):
        """ Del object from cache. """
        object_data = self.cache.pop(object_id)
        object_type = object_data['TYPE']
        self.lru_data[object_type].pop(object_id)
        return object_data

