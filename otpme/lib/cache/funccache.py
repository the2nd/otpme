# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import functools
import collections
from functools import wraps

#from cachetools import keys
#from cachetools.rr import RRCache
from cachetools import LRUCache
#from cachetools.lfu import LFUCache
#from cachetools.ttl import TTLCache

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import multiprocessing
from otpme.lib.pickle import PickleHandler

from otpme.lib.exceptions import *

#debug_caches = []

_CacheInfo = collections.namedtuple('CacheInfo', [
    'hits', 'misses', 'maxsize', 'currsize'
])

class Cache(object):
    """ Cache class. """
    def __init__(self, name, cache_type="lru", maxsize=256, ignore_args=[],
        ignore_classes=[], cache_name_var=None, cache_name_func=None,
        caches=None, default_cache=None, shared=False, copy_cache=False):
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
        if self.copy_cache:
            self.pickle_handler = PickleHandler("auto", encode=False)

    def init_cache(self, cache_name=None):
        """ Init cache. """
        from otpme.lib import config
        if cache_name is None:
            cache_name = self.default_cache
        try:
            cache_type = self.caches[cache_name]['cache_type']
        except:
            cache_type = self.cache_type
        try:
            maxsize = self.caches[cache_name]['maxsize']
        except:
            maxsize = self.maxsize
        if cache_type == "lru":
            cache_class = LRUCache
        else:
            msg = "Unknown cache type: %s" % cache_type
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
        if not cache_name in self._caches:
            self._caches[cache_name] = {}
        self._caches[cache_name]['cache'] = new_cache
        self._stats[cache_name] = [0, 0]
        if config.debug_level("func_cache_adds") > 0 \
        or config.debug_level("func_cache_hits") > 0:
            msg = ("Initialized cache: %s (%s): %s:maxsize=%s"
                % (self.name, cache_name, cache_type, maxsize))
            config.logger.debug(msg)
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
            except:
                pass
        if self.cache_name_func is not None:
            try:
                cache_name = self.cache_name_func(func_args, func_kwargs)
            except NoMatch:
                pass
        if cache_name is None:
            cache_name = self.default_cache
        return cache_name

    def get_cache(self, cache_name=None):
        """ Get cache. """
        if cache_name is None:
            cache_name = self.default_cache
        try:
            _cache = self._caches[cache_name]['cache']
        except:
            msg = "Unknown cache: %s" % cache_name
            raise OTPmeException(msg)
        return _cache

    def get_shared_cache(self, cache_name):
        shared_cache_name = "funccache.%s" % cache_name
        try:
            _shared_cache = self._shared_caches[shared_cache_name]
        except:
            _shared_cache = multiprocessing.get_dict(shared_cache_name)
            self._shared_caches[shared_cache_name] = _shared_cache
        return _shared_cache

    def decorator(self, func, class_method=False):
        """ Decorator to be added to function/method. """
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
                try:
                    ignore_args = self.caches[cache_name]['ignore_args']
                except:
                    ignore_args = self.ignore_args
                try:
                    ignore_classes = self.caches[cache_name]['ignore_classes']
                except:
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
                    msg = ("Failed to parse function args: %s (%s): %s: %s"
                            % (self.name, cache_name, method_name, e))
                    raise OTPmeException(msg)
                # Build key to cache result.
                k = "%s.%s" % (method_name, k)
                # Try to get cache.
                try:
                    _cache = self.get_cache(cache_name)
                    check_cache = True
                except:
                    # Init new cache if none exists. This is required to allow
                    # caches that do not exist on cache creation (e.g. by
                    # UUID caches).
                    check_cache = False
                    _cache = self.init_cache(cache_name)

            # Get shared cache.
            _shared_cache = None
            if check_shared_cache:
                _shared_cache = self.get_shared_cache(cache_name)

            # Try to get result from cache.
            if check_cache:
                try:
                    result = _cache[k]
                    if self.copy_cache:
                        result = self.pickle_handler.loads(result)
                    # Logging.
                    log_hit = False
                    if config.debug_level("func_cache_hits") > 0:
                        log_hit = True
                        if config.debug_func_caches \
                        and self.name not in config.debug_func_caches:
                            log_hit = False
                    if log_hit:
                        msg = ("Got value from cache: %s: (%s): %s"
                                % (self.name, cache_name, method_name))
                        if config.debug_level("func_cache_hits") > 2:
                            msg = "%s: %s" % (msg, result)
                        config.logger.debug(msg)
                    try:
                        self._stats[cache_name][0] += 1
                    except:
                        pass
                except KeyError:
                    try:
                        self._stats[cache_name][1] += 1
                    except:
                        pass

            # Try to get result from shared cache.
            if check_shared_cache:
                try:
                    result = _shared_cache.get(k)
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
                        msg = ("Got value from shared cache: %s: (%s): %s"
                                % (self.name, cache_name, method_name))
                        if config.debug_level("func_cache_hits") > 2:
                            msg = "%s: %s" % (msg, result)
                        config.logger.debug(msg)
                    try:
                        self._stats[cache_name][0] += 1
                    except:
                        pass
                except KeyError:
                    try:
                        self._stats[cache_name][1] += 1
                    except:
                        pass

            # Run func/method if no cache hit was available.
            if result is None:
                result = func(*args, **kwargs)

            if result is not None:
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
                        _cache[k] = self.pickle_handler.dumps(result)
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
                        msg = ("Added value to cache: %s: (%s): %s"
                                % (self.name, cache_name, method_name))
                        if config.debug_level("func_cache_adds") > 2:
                            msg = "%s: %s" % (msg, result)
                        config.logger.debug(msg)
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
                        msg = ("Added value to shared cache: %s: (%s): %s"
                                % (self.name, cache_name, method_name))
                        if config.debug_level("func_cache_adds") > 2:
                            msg = "%s: %s" % (msg, result)
                        config.logger.debug(msg)
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
        except:
            return
        try:
            hits, misses = self._stats[cache_name]
        except:
            msg = "Unknown cache: %s" % cache_name
            raise OTPmeException(msg)
        maxsize = _cache.maxsize
        currsize = _cache.currsize
        return _CacheInfo(hits, misses, maxsize, currsize)

    def _clear_cache(self, cache_name):
        """ Clear cache. """
        from otpme.lib import config
        # Get local cache
        try:
            _cache = self.get_cache(cache_name)
        except:
            return
        if config.debug_level("func_cache_adds") > 0 \
        or config.debug_level("func_cache_hits") > 0:
            msg = ("Clearing cache: %s: (%s)" % (self.name, cache_name))
            config.logger.debug(msg)
        # Clear local cache.
        try:
            _cache.clear()
        finally:
            try:
                self._stats[cache_name][:] = [0, 0]
            except:
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
            caches = list(self._caches)
        else:
            caches = [cache_name]
        for x in caches:
            self._clear_cache(x)
            # Set last clear time.
            self.last_clear[x] = time.time()

class FuncCache(object):
    """ Class to cache function/method results. """
    def __init__(self, name, cache_key_func=None, **cache_kwargs):
        self.name = name
        self._caches = {}
        self._cache_kwargs = cache_kwargs
        self.cache_key_func = cache_key_func

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
        except:
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
                try:
                    clear_trigger = multiprocessing.function_cache_clear_trigger[self.name].copy()
                except KeyError:
                    clear_trigger = None

                # Get cache of this thread.
                _cache = self.get_cache()

                # Make sure we clear the cache if needed.
                if clear_trigger:
                    for cache_name in clear_trigger:
                        clear_time = clear_trigger[cache_name]
                        try:
                            cache_last_clear = _cache.last_clear[cache_name]
                        except:
                            cache_last_clear = None
                        if cache_last_clear is not None:
                            if clear_time < cache_last_clear:
                                continue
                        if cache_name == "all":
                            cache_name = None
                        _cache.clear_cache(cache_name=cache_name)

                # Get method/function name.
                func_name = f.__name__
                if class_method:
                    if not self.cache_key_func:
                        msg = "Cannot cache class method without <cache_key_func>."
                        raise OTPmeException(msg)
                    # For classes we have to create a uniq name that can be used
                    # as cache key (e.g. the OID).
                    cls = f_args[0]
                    func_name = self.cache_key_func(cls, func_name, f_args, f_kwargs)

                # Add method/function name to be used as cache key.
                f_kwargs['_otpme_func_name'] = func_name

                # Get cache decorator.
                cf = _cache.decorator(f, class_method=class_method)
                # Call method.
                result = cf(*f_args, **f_kwargs)
                return result
            return wrapped
        return wrapper

    def invalidate(self, cache_name=None):
        """ Invalidate the cache. """
        from otpme.lib import config
        if not config.cache_enabled:
            return
        trigger_name = cache_name
        if trigger_name is None:
            trigger_name = "all"
        # Make sure we update the clear trigger to get other processes notified.
        try:
            clear_trigger = multiprocessing.function_cache_clear_trigger[self.name].copy()
        except:
            clear_trigger = {}
        clear_trigger[trigger_name]  = time.time()
        # Expire clear trigger after 1h. This is required for caches based on
        # object UUID which would otherwise grow forever.
        multiprocessing.function_cache_clear_trigger.add(self.name,
                                                        clear_trigger,
                                                        expire=3600)
        # Get cache of this thread.
        _cache = self.get_cache()
        _cache.clear_cache(cache_name)
