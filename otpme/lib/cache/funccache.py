# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import functools
import collections
from functools import wraps

try:
    import simdjson as json
except Exception:
    try:
        import ujson as json
    except Exception:
        import json

#from cachetools import keys
#from cachetools.rr import RRCache
from cachetools import LRUCache
#from cachetools.lfu import LFUCache
#from cachetools.ttl import TTLCache

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib import multiprocessing

#from otpme.lib.pickle import PickleHandler

from otpme.lib.exceptions import *

#debug_caches = []

_CacheInfo = collections.namedtuple('CacheInfo', [
    'hits', 'misses', 'maxsize', 'currsize'
])

def result_is_empty(result):
    """ Whether a result says "nothing found".

    A negative answer is not kept. None never was -- the cache stores a
    result only if it "is not None", and reads a miss as None as well --
    but the search functions do not say "nothing" with None. They say it
    with an empty list (index_search() returns its result_list), and an
    empty list went in and was handed back out, so an object another
    process wrote after the miss stayed invisible here for good. That is
    what a sync worker ran into: the user its token belongs to was
    written by another worker, and this one went on reporting the parent
    as missing.

    Only containers count. A function answering False or 0 is answering,
    not declining.
    """
    if result is None:
        return True
    if isinstance(result, (list, dict, tuple, set)):
        return len(result) == 0
    return False

class Cache(object):
    """ Cache class. """
    def __init__(self, name, cache_type="lru", maxsize=256, ignore_args=None,
        ignore_classes=None, cache_name_var=None, cache_name_func=None,
        default_cache=None, caches=None, shared=False, copy_cache=False):
        if ignore_args is None:
            ignore_args = []
        if ignore_classes is None:
            ignore_classes = []
        self.name = name
        self._stats = {}
        self._caches = {}
        self.last_clear = {}
        self._shared_caches = {}
        self.caches = caches
        self.shared = shared
        self.maxsize = maxsize
        self.cache_type = cache_type
        self.copy_cache = copy_cache
        self.ignore_args = ignore_args
        self.default_cache = default_cache
        self.ignore_classes = ignore_classes
        self.cache_name_var = cache_name_var
        self.cache_name_func = cache_name_func
        if not self.default_cache:
            if not self.cache_name_var:
                if not self.cache_name_func:
                    msg = _("Invalid cache configuration. Need <default_cache>, <cache_name_var> or <cache_name_func>.")
                    raise OTPmeException(msg)
        # We cannot use pickle cache as e.g. in search cache with return_type="instance"
        # this will result in an new object (new id().
        #if self.copy_cache:
        #    self.pickle_handler = PickleHandler("auto")

    def init_cache(self, cache_name=None):
        """ Init cache. """
        from otpme.lib import config
        if cache_name is None:
            cache_name = self.default_cache
        try:
            cache_type = self.caches[cache_name]['cache_type']
        except Exception:
            cache_type = self.cache_type
        try:
            maxsize = self.caches[cache_name]['maxsize']
        except Exception:
            maxsize = self.maxsize
        if cache_type == "lru":
            cache_class = LRUCache
        else:
            msg = _("Unknown cache type: {cache_type}")
            msg = msg.format(cache_type=cache_type)
            raise OTPmeException(msg)
        # Add new cache.
        new_cache = cache_class(maxsize)
        # NOTE: Enable to check if caches get cleared!
        #global debug_caches
        #debug_caches.append((self.name, cache_name, new_cache))
        #for x in debug_caches:
        #    x_name = x[0]
        #    x_cname = x[1]
        #    x_cache = x[2]
        #    if len(x_cache) < 512:
        #        continue
        #    print("III", x_name, x_cname, len(x_cache))
        if cache_name not in self._caches:
            self._caches[cache_name] = {}
        self._caches[cache_name]['cache'] = new_cache
        self._stats[cache_name] = [0, 0]
        if config.debug_level("func_cache_adds") > 0 \
        or config.debug_level("func_cache_hits") > 0:
            log_msg = _("Initialized cache: {name} ({cache_name}): {cache_type}:maxsize={maxsize}", log=True)[1]
            log_msg = log_msg.format(name=self.name, cache_name=cache_name, cache_type=cache_type, maxsize=maxsize)
            config.logger.debug(log_msg)
        return new_cache

    def get_cache_name(self, func_args, func_kwargs):
        """ Try to get cache_name from function args. """
        cache_name = None
        if self.cache_name_var is not None:
            try:
                if isinstance(self.cache_name_var, str):
                    cache_name = func_kwargs[self.cache_name_var]
                else:
                    cache_name = func_args[self.cache_name_var]
            except Exception:
                pass
        if self.cache_name_func is not None:
            try:
                cache_name = self.cache_name_func(func_args, func_kwargs)
            except NoMatch:
                pass
        if cache_name is None:
            cache_name = self.default_cache
        if cache_name is None:
            msg = _("Invalid cache configuration. Need <default_cache>, <cache_name_var> or <cache_name_func>.")
            raise OTPmeException(msg)
        return cache_name

    def get_cache(self, cache_name=None):
        """ Get cache. """
        if cache_name is None:
            cache_name = self.default_cache
        try:
            _cache = self._caches[cache_name]['cache']
        except Exception:
            msg = _("Unknown cache: {cache_name}")
            msg = msg.format(cache_name=cache_name)
            raise OTPmeException(msg) from None
        return _cache

    def get_shared_cache(self, cache_name):
        shared_cache_name = f"funccache.{cache_name}"
        try:
            _shared_cache = self._shared_caches[shared_cache_name]
        except Exception:
            _shared_cache = multiprocessing.get_dict(shared_cache_name)
            self._shared_caches[shared_cache_name] = _shared_cache
        return _shared_cache

    def decorator(self, func, class_method=False, check_valid=None):
        """ Decorator to be added to function/method.

        check_valid: asked whether a value found in one of the caches
        is still good, which is the case unless somebody invalidated
        the cache since it was put there. It is asked here and not
        before the lookup because the answer costs a roundtrip to the
        shared cache: a call that finds nothing has nothing to ask
        about, and that is most of them while walking a tree.
        """
        def wrapper(*args, **kwargs):
            from otpme.lib import config
            """ Wrapper to cache function/method
            results by args/kwargs. """
            result = None
            check_cache = False
            update_cache = False
            use_shared_cache = False
            check_shared_cache = False
            # FIXME: How to implement cache expiry?
            shared_cache_expire = None
            update_shared_cache = False
            # Get method name.
            name_kwarg = "_otpme_func_name"
            method_name = kwargs.pop(name_kwarg)

            # Get cache parameters.
            cache_name = self.get_cache_name(args, kwargs)
            if cache_name is not None:
                if self.shared:
                    check_shared_cache = True
                    use_shared_cache = True
                try:
                    ignore_args = self.caches[cache_name]['ignore_args']
                except Exception:
                    ignore_args = self.ignore_args
                try:
                    ignore_classes = self.caches[cache_name]['ignore_classes']
                except Exception:
                    ignore_classes = self.ignore_classes

                f_args = list(args)
                f_kwargs = dict(kwargs)
                if class_method:
                    f_args.pop(0)

                # Generate key from func/method name and args.
                arguments = {
                            'args'      : tuple(f_args),
                            'kwargs'    : dict(f_kwargs),
                            }
                try:
                    k = stuff.args_to_hash(arguments,
                                    ignore_args=ignore_args,
                                    ignore_classes=ignore_classes)
                except Exception as e:
                    msg = _("Failed to parse function args: {name} ({cache_name}): {method_name}: {e}")
                    msg = msg.format(name=self.name, cache_name=cache_name, method_name=method_name, e=e)
                    raise OTPmeException(msg) from e
                # Build key to cache result.
                k = f"{method_name}.{k}"
                # Try to get cache.
                try:
                    _cache = self.get_cache(cache_name)
                    check_cache = True
                except Exception:
                    # Init new cache if none exists. This is required to allow
                    # caches that do not exist on cache creation (e.g. by
                    # UUID caches).
                    check_cache = False
                    _cache = self.init_cache(cache_name)

            # Get shared cache.
            _shared_cache = None
            if check_shared_cache:
                _shared_cache = self.get_shared_cache(cache_name)

            # Asked once per call, and only where a cache had
            # something to give.
            checked = None
            def cached_value_valid():
                nonlocal checked
                if checked is None:
                    if check_valid is None:
                        checked = True
                    else:
                        checked = check_valid(cache_name)
                return checked

            # Try to get result from cache.
            result = None
            if check_cache:
                try:
                    result = _cache[k]
                    if not cached_value_valid():
                        # Somebody invalidated this cache while the
                        # value sat in it, so it went with the cache.
                        result = None
                        raise KeyError(k)
                    if self.copy_cache:
                        #result = self.pickle_handler.loads(result)
                        try:
                            result = json.loads(result)
                        except TypeError:
                            pass
                    # Logging.
                    log_hit = False
                    if config.debug_level("func_cache_hits") > 0:
                        log_hit = True
                        if config.debug_func_caches \
                        and self.name not in config.debug_func_caches:
                            log_hit = False
                    if log_hit:
                        log_msg = _("Got value from cache: {self.name}: ({cache_name}): {method_name}", log=True)[1]
                        log_msg = log_msg.format(self.name, cache_name=cache_name, method_name=method_name)
                        if config.debug_level("func_cache_hits") > 2:
                            log_msg = f"{log_msg}: {result}"
                        config.logger.debug(log_msg)
                    try:
                        self._stats[cache_name][0] += 1
                    except Exception:
                        pass
                except KeyError:
                    try:
                        self._stats[cache_name][1] += 1
                    except Exception:
                        pass

            # Try to get result from shared cache.
            if check_shared_cache and result is None:
                try:
                    result = _shared_cache.get(k)
                    if not cached_value_valid():
                        # See above.
                        result = None
                        raise KeyError(k)
                    # Update local cache from shared cache.
                    if cache_name is not None:
                        update_cache = True
                    # Logging.
                    log_hit = False
                    if config.debug_level("func_cache_hits") > 0:
                        log_hit = True
                        if config.debug_func_caches \
                        and self.name not in config.debug_func_caches:
                            log_hit = False
                    if log_hit:
                        log_msg = _("Got value from shared cache: {self.name}: ({cache_name}): {method_name}", log=True)[1]
                        log_msg = log_msg.format(self.name, cache_name=cache_name, method_name=method_name)
                        if config.debug_level("func_cache_hits") > 2:
                            log_msg = f"{log_msg}: {result}"
                        config.logger.debug(log_msg)
                    try:
                        self._stats[cache_name][0] += 1
                    except Exception:
                        pass
                except KeyError:
                    try:
                        self._stats[cache_name][1] += 1
                    except Exception:
                        pass

            # Run func/method if no cache hit was available.
            if result is None:
                result = func(*args, **kwargs)

            if not result_is_empty(result):
                if cache_name is not None:
                    update_cache = True
                    if use_shared_cache:
                        update_shared_cache = True

            if update_shared_cache:
                if _shared_cache is None:
                    _shared_cache = self.get_shared_cache(cache_name)

            # Add result to cache.
            if update_cache:
                try:
                    if self.copy_cache:
                        #_cache[k] = self.pickle_handler.dumps(result)
                        try:
                            _cache[k] = json.dumps(result)
                        except TypeError:
                            # Not JSON-serializable (e.g. contains instances/OIDs).
                            # Skip caching rather than store a raw reference that
                            # callers could mutate and poison the cache with.
                            pass
                    else:
                        _cache[k] = result
                    # Logging.
                    log_add = False
                    if config.debug_level("func_cache_adds") > 0:
                        log_add = True
                        if config.debug_func_caches \
                        and self.name not in config.debug_func_caches:
                            log_add = False
                    if log_add:
                        log_msg = _("Added value to cache: {self.name}: ({cache_name}): {method_name}", log=True)[1]
                        log_msg = log_msg.format(self.name, cache_name=cache_name, method_name=method_name)
                        if config.debug_level("func_cache_adds") > 2:
                            log_msg = f"{log_msg}: {result}"
                        config.logger.debug(log_msg)
                except ValueError:
                    # Value too large.
                    pass

            # Add result to shared cache.
            if update_shared_cache:
                try:
                    _shared_cache.add(k, result, expire=shared_cache_expire)
                    # Logging.
                    log_add = False
                    if config.debug_level("func_cache_adds") > 0:
                        log_add = True
                        if config.debug_func_caches \
                        and self.name not in config.debug_func_caches:
                            log_add = False
                    if log_add:
                        log_msg = _("Added value to shared cache: {self.name}: ({cache_name}): {method_name}", log=True)[1]
                        log_msg = log_msg.format(self.name, cache_name=cache_name, method_name=method_name)
                        if config.debug_level("func_cache_adds") > 2:
                            log_msg = f"{log_msg}: {result}"
                        config.logger.debug(log_msg)
                except ValueError:
                    # Value too large.
                    pass

            # Return result.
            return result

        # Update func/method.
        functools.update_wrapper(wrapper, func)
        if not hasattr(wrapper, '__wrapped__'):
            # Python 2.7
            wrapper.__wrapped__ = func
        wrapper.cache_info = self.cache_info
        wrapper.clear_cache = self.clear_cache

        # Return wrapper method.
        return wrapper

    def cache_info(self, cache_name=None):
        """ Get cache info. """
        if cache_name is None:
            cache_name = self.default_cache
        try:
            _cache = self.get_cache(cache_name)
        except Exception:
            return
        try:
            hits, misses = self._stats[cache_name]
        except Exception:
            msg = _("Unknown cache: {cache_name}")
            msg = msg.format(cache_name=cache_name)
            raise OTPmeException(msg) from None
        maxsize = _cache.maxsize
        currsize = _cache.currsize
        return _CacheInfo(hits, misses, maxsize, currsize)

    def _clear_cache(self, cache_name):
        """ Clear cache. """
        from otpme.lib import config
        # Get local cache
        try:
            _cache = self.get_cache(cache_name)
        except Exception:
            pass
        else:
            if config.debug_level("func_cache_adds") > 0 \
            or config.debug_level("func_cache_hits") > 0:
                log_msg = _("Clearing cache: {name}: ({cache_name})", log=True)[1]
                log_msg = log_msg.format(name=self.name, cache_name=cache_name)
                config.logger.debug(log_msg)
            # Clear local cache.
            try:
                _cache.clear()
            finally:
                try:
                    self._stats[cache_name][:] = [0, 0]
                except Exception:
                    pass
        if not self.shared:
            return
        # Clear shared cache.
        _shared_cache = self.get_shared_cache(cache_name)
        _shared_cache.clear()

    def clear_cache(self, cache_name=None):
        """ Clear cache. """
        if cache_name is None:
            # Set last clear time.
            self.last_clear["all"] = time.time()
            if self._caches:
                caches = list(self._caches)
            else:
                caches = [self.default_cache]
        else:
            caches = [cache_name]
        for x in caches:
            self._clear_cache(x)
            # Set last clear time.
            self.last_clear[x] = time.time()

class FuncCache(object):
    """ Class to cache function/method results. """
    def __init__(self, name, cache_key_func=None, clear_on_object_types=None, **cache_kwargs):
        self.name = name
        self._caches = {}
        self._cache_kwargs = cache_kwargs
        self.cache_key_func = cache_key_func
        self.clear_on_object_types = clear_on_object_types
        # Make sure cache args are valid.
        Cache(self.name, **self._cache_kwargs)

    @property
    def logger(self):
        from otpme.lib import config
        return config.logger

    def get_cache(self):
        """ Get or init cache by thread ID. """
        thread_id = multiprocessing.get_thread_id()
        #thread_id = "test"
        try:
            _cache = self._caches[thread_id]
        except Exception:
            _cache = Cache(self.name, **self._cache_kwargs)
            self._caches[thread_id] = _cache
        return _cache

    def cache_method(self):
        """ Decorator for class methods. """
        result = self.cache(class_method=True)
        return result

    def cache_function(self):
        """ Decorator functions. """
        result = self.cache()
        return result

    def cache(self, class_method=False):
        """ Wrapper to make sure cache is cleared if requested. """
        def wrapper(f):
            @wraps(f)
            def wrapped(*f_args, **f_kwargs):
                from otpme.lib import config
                try:
                    no_func_cache = f_kwargs['_no_func_cache']
                except KeyError:
                    no_func_cache = False
                # Just run the function if caching is disabled.
                if no_func_cache or not config.cache_enabled:
                    # Get method/function name.
                    try:
                        result = f(*f_args, **f_kwargs)
                    except OTPmeException:
                        raise
                    except Exception as e:
                        raise
                    return result
                # Get cache of this thread.
                _cache = self.get_cache()

                def check_valid(wanted_cache):
                    """ Is what a cache just gave us still good?

                    invalidate() writes the time it ran into a shared
                    dict, and a value that was cached before that time
                    is stale. Reading it is a roundtrip to the shared
                    cache, and this used to be done at the top of
                    every call of every cached function -- for caches
                    that keep nothing shared at all, and whether or
                    not the call found anything. A walk over a tree
                    finds nothing in the cache and paid it for every
                    object.

                    So the question is asked where an answer is
                    needed: something was found and we have to know
                    whether to believe it. With nothing found the
                    function runs anyway.

                    Every cache the trigger names is thrown away, not
                    only the one asked about -- the others hold stale
                    values too, and this is where we know. Returns
                    False when the value the caller found went with
                    them.
                    """
                    try:
                        clear_trigger = multiprocessing.function_cache_clear_trigger[self.name].copy()
                    except KeyError:
                        return True
                    if not clear_trigger:
                        return True
                    still_valid = True
                    for cache_name in clear_trigger:
                        clear_time = clear_trigger[cache_name]
                        try:
                            cache_last_clear = _cache.last_clear[cache_name]
                        except Exception:
                            cache_last_clear = None
                        if cache_last_clear is not None:
                            if clear_time < cache_last_clear:
                                continue
                        if cache_name == "all":
                            cache_name = None
                        if cache_name is None or cache_name == wanted_cache:
                            still_valid = False
                        _cache.clear_cache(cache_name=cache_name)
                    return still_valid

                # Get method/function name.
                func_name = f.__name__
                if class_method:
                    if not self.cache_key_func:
                        msg = _("Cannot cache class method without <cache_key_func>.")
                        raise OTPmeException(msg)
                    # For classes we have to create a uniq name that can be used
                    # as cache key (e.g. the OID).
                    cls = f_args[0]
                    func_name = self.cache_key_func(cls, func_name, f_args, f_kwargs)

                # Add method/function name to be used as cache key.
                f_kwargs['_otpme_func_name'] = func_name

                # Get cache decorator.
                cf = _cache.decorator(f, class_method=class_method,
                                    check_valid=check_valid)
                # Call method.
                result = cf(*f_args, **f_kwargs)
                return result
            return wrapped
        return wrapper

    def invalidate(self, cache_name=None, object_type=None, shared=True):
        """ Invalidate the cache.

        Whether this process uses caches (config.cache_enabled) does
        not come into it. Telling everybody else that what they hold
        is stale is not the same as holding something oneself: a
        process that writes objects with its own caches switched off
        would otherwise leave the caches of every other process
        standing, and that is true for the caches that keep nothing
        shared as well -- they are invalidated across processes by the
        same trigger.
        """
        _cache = self.get_cache()
        if cache_name is None:
            if object_type:
                c_args = ()
                c_kwargs = {'object_type':object_type}
                cache_name = _cache.get_cache_name(c_args, c_kwargs)
        trigger_name = cache_name
        if trigger_name is None:
            trigger_name = "all"
        if shared:
            # Make sure we update the clear trigger to get other processes notified.
            if trigger_name == "all":
                # Nothing to read first. This trigger says that every
                # cache of this name is stale, whatever anybody else
                # wrote before: a reader that finds it throws all of its
                # caches away, which is more than any of the finer
                # triggers would have made it do. So they can go with it.
                #
                # It is worth the special case because it is the only
                # trigger there is in the write path -- a written object
                # invalidates around two dozen caches, none of them by
                # name -- and reading the old value before writing the
                # new one is a roundtrip to the shared cache each time.
                clear_trigger = {}
            else:
                try:
                    clear_trigger = multiprocessing.function_cache_clear_trigger[self.name].copy()
                except Exception:
                    clear_trigger = {}
            clear_trigger[trigger_name] = time.time()
            # Expire clear trigger after 1h. This is required for caches based on
            # object UUID which would otherwise grow forever.
            multiprocessing.function_cache_clear_trigger.add(self.name,
                                                            clear_trigger,
                                                            expire=3600)
        # Get cache of this thread.
        _cache.clear_cache(cache_name)
