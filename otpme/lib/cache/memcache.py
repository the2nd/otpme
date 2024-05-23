# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Module for handling memcached/memcachedb caching.

http://sendapatch.se/projects/pylibmc/reference.html
"""
import os
import sys
import time
try:
    import pylibmc
except ImportError:
    # Ignore missing module (e.g. other cache type configured.
    pass
#import memcache

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib.pickle import PickleHandler
from otpme.lib.multiprocessing import SharedDict
from otpme.lib.multiprocessing import SharedList

from otpme.lib.exceptions import *

NC_BIN = "nc"

class MemcacheHandler(object):
    """ Memcache handler. """
    def __init__(self, name, start_function, socket, pidfile, lock_type):
        self.name = name
        self.socket = socket
        self.pidfile = pidfile
        self.lock_type = lock_type
        self.logger = config.logger
        self.start_function = start_function

    def get_pid(self):
        try:
            pid = filetools.read_file(self.pidfile)
        except:
            pid = None
        return pid

    def start(self):
        msg = "Starting %s..." % self.name
        self.logger.info(msg)
        return self.start_function()

    def wait_for_start(self, timeout=5):
        timeout = timeout * 10
        msg = "Waiting for %s to start up..." % self.name
        self.logger.info(msg)
        counter = 0
        while not self.status():
            counter += 1
            if counter >= timeout:
                return False
            time.sleep(0.1)
        return True

    def status(self):
        pid = self.get_pid()
        if pid is None:
            return False
        return stuff.check_pid(pid)

    def stop(self):
        if not self.status():
            msg = "%s not running." % self.name
            raise NotRunning(msg)
        msg = "Stopping %s..." % self.name
        self.logger.info(msg)
        pid = self.get_pid()
        stuff.kill_pid(pid, timeout=10)
        if not os.path.exists(self.socket):
            return
        os.remove(self.socket)

    def wait_for_shutdown(self, timeout=5):
        timeout = timeout * 10
        msg = "Waiting for %s to shut down..." % self.name
        self.logger.info(msg)
        counter = 0
        while self.status():
            counter += 1
            if counter >= timeout:
                return False
            time.sleep(0.1)
        return True

    def get_pool(self):
        """ Get connection pool. """
        def pool_getter():
            mc = pylibmc.Client([self.socket])
            pool = pylibmc.ThreadMappedPool(mc)
            return pool
        return pool_getter

    def get_list(self, name, pool=None, clear=False, locking=False):
        if pool is None:
            pool = self.get_pool()
        _list = MemcacheList(name=name,
                            pool=pool,
                            clear=clear,
                            locking=locking,
                            lock_type=self.lock_type)
        return _list

    def get_dict(self, name, pool=None, clear=False, locking=False):
        if pool is None:
            pool = self.get_pool()
        _dict = MemcacheDict(name=name,
                            pool=pool,
                            clear=clear,
                            locking=locking,
                            lock_type=self.lock_type)
        return _dict

    def flushall(self):
        #mc = memcache.Client(["unix:/tmp/memcachedb.sock"], debug=False)
        mc = pylibmc.Client([self.socket])
        mc.flush_all()

    def cli(self):
        cli_cmd = [NC_BIN, "-U", self.socket]
        cli_opts = sys.argv[2:]
        cli_cmd += cli_opts
        system_command.run(command=cli_cmd,
                            user=config.user,
                            group=config.group,
                            call=True)

class MemcacheClient(object):
    def __init__(self, pool_getter, compression=None):
        self.pools = {}
        self.compression = compression
        self.logger = config.logger
        self.pool_getter = pool_getter
        self.connection_error_logged = False
        pickel_type = config.pickle_cache_module
        self.pickle_handler = PickleHandler(pickel_type, encode=True)

    @property
    def pool(self):
        pid = os.getpid()
        try:
            pool = self.pools[pid]
        except:
            pool = self.pool_getter()
            self.pools[pid] = pool
        return pool

    def get(self, key):
        try:
            with self.pool.reserve() as mc:
                value = mc.get(key)
        except pylibmc.Error as e:
            if not self.connection_error_logged:
                msg = "Memcache get error: %s" % e
                self.connection_error_logged = True
                self.logger.critical(msg)
            raise KeyError(msg)
        except pylibmc.ConnectionError as e:
            if not self.connection_error_logged:
                msg = "Memcache connection error: %s" % e
                self.connection_error_logged = True
                self.logger.critical(msg)
            raise KeyError(msg)
        if value is None:
            raise KeyError(key)
        # Decompress value.
        if self.compression:
            value = stuff.decompress(value, self.compression)
        # Unpickle data.
        value = self.pickle_handler.loads(value)
        return value

    def set(self, key, value, **kwargs):
        # Pickle data.
        value = self.pickle_handler.dumps(value)
        # Compress value.
        if self.compression:
            value = stuff.compress(value, self.compression)
        #cas = self.self.pool.gets(key)
        #if cas is not None:
        #    self.pool.cas(key, value, cas, **kwargs)
        #else:
        #    self.pool.set(key, value, **kwargs)
        #with self.pool.reserve() as mc:
        #    cas = mc.gets(key)
        #    mc.sets(key, value, cas, **kwargs)
        try:
            with self.pool.reserve() as mc:
                mc.set(key, value, **kwargs)
        except pylibmc.Error as e:
            if self.connection_error_logged:
                return
            msg = "Memcache set error: %s" % e
            self.connection_error_logged = True
            self.logger.critical(msg)
        except pylibmc.ConnectionError as e:
            if self.connection_error_logged:
                return
            msg = "Memcache connection error: %s" % e
            self.connection_error_logged = True
            self.logger.critical(msg)

    def delete(self, key, **kwargs):
        try:
            with self.pool.reserve() as mc:
                mc.delete(key, **kwargs)
        except pylibmc.Error as e:
            if self.connection_error_logged:
                return
            msg = "Memcache delete error: %s" % e
            self.logger.critical(msg)
            return
        except pylibmc.ConnectionError as e:
            if self.connection_error_logged:
                return
            msg = "Memcache connection error: %s" % e
            self.logger.critical(msg)
            return

class MemcacheDict(SharedDict):
    """ A simple memcached dict. """
    def __init__(self, name, pool, locking=False, lock_type="memcached",
        clear=False, refresh_keys=False, compression=None):
        super(MemcacheDict, self).__init__(name)
        self.client = MemcacheClient(pool, compression=compression)
        self.dict_keys_key = "%s.dict_keys" % self.name
        self.refresh_keys = refresh_keys
        self.lock_type = lock_type
        self.locking = locking
        self._lock = None
        if clear:
            self.clear()

    def lock(self):
        """
        Lock complete dict (prevent race when changing list contained in dict).
        """
        from otpme.lib import locking
        lock_id = "memcached-dict-%s" % self.name
        self._lock = locking.acquire_lock(lock_type=self.lock_type,
                                            lock_id=lock_id)

    def release(self):
        if not self._lock:
            return
        self._lock.release_lock()

    def clear(self):
        for x in self.keys():
            try:
                self.delete(x)
            except KeyError:
                pass
        dict_keys_key = self.dict_keys_key
        self.client.delete(dict_keys_key)

    def keys(self):
        keys = self.get_dict_keys()
        for x in list(keys):
            key = self.get_key_id(x)
            try:
                self.client.get(key)
            except:
                keys.remove(x)
        return keys

    def values(self):
        values = []
        for x in self.keys():
            # Ignore keys removed while selecting items.
            try:
                value = self.get(x)
            except KeyError:
                continue
            values.append(value)
        return values

    def items(self):
        items = []
        for key in self.keys():
            # Ignore keys removed while selecting items.
            try:
                value = self.get(key)
            except KeyError:
                continue
            item = (key, value)
            items.append(item)
        return items

    def get_dict_keys(self):
        dict_keys_key = self.dict_keys_key
        try:
            dict_keys = self.client.get(dict_keys_key)
            keys = dict_keys[self.name]
        except:
            keys = []
        return keys

    def set_dict_keys(self, keys):
        dict_keys_key = self.dict_keys_key
        try:
            dict_keys = self.client.get(dict_keys_key)
        except:
            dict_keys = {}
        dict_keys[self.name] = keys
        self.client.set(key=dict_keys_key,
                        value=dict_keys,
                        min_compress_len=1024000,
                        compress_level=1)

    def add_dict_key(self, key):
        from otpme.lib import locking
        if self.locking:
            _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=self.name)
        try:
            our_keys = self.get_dict_keys()
            if key in our_keys:
                return
            our_keys.append(key)
            self.set_dict_keys(our_keys)
        finally:
            if self.locking:
                _lock.release_lock()

    def del_dict_key(self, key):
        from otpme.lib import locking
        if self.locking:
            _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=self.name)
        try:
            our_keys = self.get_dict_keys()
            try:
                our_keys.remove(key)
            except:
                return
            self.set_dict_keys(our_keys)
        finally:
            if self.locking:
                _lock.release_lock()

    def add(self, key, value, expire=None):
        from otpme.lib import locking
        if expire is None:
            expire = 0
        if self.locking:
            _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=key)
        try:
            _key = self.get_key_id(key)
            self.client.set(key=_key,
                            value=value,
                            time=expire,
                            min_compress_len=512000,
                            compress_level=1)
            self.add_dict_key(key)
            # Save key expire time.
            if self.refresh_keys:
                if expire > 0:
                    expire_key = self.get_key_expire_id(key)
                    self.client.set(expire_key, expire)
        finally:
            if self.locking:
                _lock.release_lock()

    def get(self, key):
        # Get value.
        _key = self.get_key_id(key)
        try:
            value = self.client.get(_key)
        except:
            raise KeyError(key)
        # Check for key expiry refresh.
        if self.refresh_keys:
            expire_key = self.get_key_expire_id(key)
            try:
                key_expire = self.client.get(expire_key)
            except:
                key_expire = None
            if key_expire is not None:
                self.client.touch(_key, key_expire)
        return value

    def delete(self, key):
        try:
            deleted_item = self.get(key)
            self.del_dict_key(key)
            _key = self.get_key_id(key)
            self.client.delete(_key)
        finally:
            # Remove key expire.
            if self.refresh_keys:
                expire_key = self.get_key_expire_id(key)
                self.client.delete(expire_key)
        return deleted_item

class MemcacheList(SharedList):
    """ A simple memcached list. """
    def __init__(self, name, pool, clear=False, compression=None,
        lock_type="memcached", **kwargs):
        super(MemcacheList, self).__init__(name)
        self.lock_type = lock_type
        self.client = MemcacheClient(pool, compression=compression)
        if clear:
            self.clear()

    @property
    def list(self):
        try:
            _list = self.client.get(self.name)
        except:
            _list = []
        return _list

    @list.setter
    def list(self, _list):
        self.client.set(self.name, _list)

    def clear(self):
        self.client.delete(self.name)

    def insert(self, i, value):
        from otpme.lib import locking
        _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=self.name)
        try:
            _list = self.list
            _list.insert(i, value)
            self.list = _list
        finally:
            _lock.release_lock()

    def append(self, value):
        from otpme.lib import locking
        _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=self.name)
        try:
            _list = self.list
            _list.append(value)
            self.list = _list
        finally:
            _lock.release_lock()

    def remove(self, value):
        from otpme.lib import locking
        _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=self.name)
        try:
            _list = self.list
            _list.remove(value)
            self.list = _list
        finally:
            _lock.release_lock()
