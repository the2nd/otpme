# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Module for handling of redis caching.

https://redis-py.readthedocs.io/en/stable/
"""
import os
import sys
import time
from dogpile.cache.region import make_region
from otpme.lib.cache.dogpile import md5_key_mangler
from otpme.lib.cache.dogpile import CustomInvalidationStrategy
try:
    import redis
except ImportError:
    # Ignore missing module (e.g. other cache type configured.)
    pass
try:
    from redis.connection import UnixDomainSocketConnection
except ImportError:
    # Ignore missing module (e.g. other cache type configured.)
    pass

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
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import system_command
from otpme.lib.pickle import PickleHandler
from otpme.lib.multiprocessing import SharedDict
from otpme.lib.multiprocessing import SharedList

from otpme.lib.exceptions import *

LOCK_TYPE = "redis"
REGISTER_AFTER = []
REGISTER_BEFORE = []

DATABASES = 16
LOGLEVEL = "notice"
SOCKET_PERMS = "700"
CONF_FILE_NAME = "redis.conf"
REDIS_SOCKET_NAME = "redis.sock"
MAXMEMORY = "128M"
MAXMEMORY_POLICY = "lru"
MAXMEMORY_SAMPLES = 5
LFU_LOG_FACTOR = "10"
LFU_DECAY_TIME = "1"
CACHE_DIR = os.path.join(config.cache_dir, "redis")
LOGFILE = os.path.join(config.log_dir, "redis.log")
ETC_CONF_FILE = os.path.join(config.config_dir, CONF_FILE_NAME)

def register():
    """ Register module. """
    from otpme.lib import locking
    locking.register_lock_type(LOCK_TYPE, module=__file__)
    config.register_config_var("redis_socket", str, None,
                        config_file_parameter="REDIS_SOCKET")
    config.register_config_var("redis_server_bin", str, "redis-server",
                        config_file_parameter="REDIS_SERVER_BIN")
    config.register_config_var("redis_cli_bin", str, "redis-cli",
                        config_file_parameter="REDIS_CLI_BIN")
    config.register_config_var("redis_maxmemory", str, MAXMEMORY,
                        config_file_parameter="REDIS_MAXMEMORY")
    config.register_config_var("redis_maxmemory_policy", str, MAXMEMORY_POLICY,
                        config_file_parameter="REDIS_MAXMEMORY_POLICY")
    config.register_config_var("redis_maxmemory_samples", int, MAXMEMORY_SAMPLES,
                        config_file_parameter="REDIS_MAXMEMORY_SAMPLES")
    config.register_config_var("redis_lfu_log_factor", str, LFU_LOG_FACTOR,
                        config_file_parameter="REDIS_LFU_LOG_FACTOR")
    config.register_config_var("redis_lfu_decay_time", str, LFU_DECAY_TIME,
                        config_file_parameter="REDIS_LFU_DECAY_TIME")
    config.register_config_var("redis_persistence", bool, False,
                        config_file_parameter="REDIS_PERSISTENCE")
    config.register_config_var("redis_cache_dir", str, CACHE_DIR,
                        config_file_parameter="REDIS_CACHE_DIR")
    config.register_config_var("redis_loglevel", str, LOGLEVEL,
                        config_file_parameter="REDIS_LOGLEVEL")
    config.register_config_var("redis_databases", int, DATABASES,
                        config_file_parameter="REDIS_DATABASES")

def gen_redis_conf():
    redis_conf = []
    port_opt = "port 0"
    #port_opt = "port 6379"
    #bind_opt = "bind 127.0.0.1"
    daemonize_opt = "daemonize yes"
    databases_opt = "databases %s" % config.redis_databases
    socket_opt = "unixsocket %s" % get_socket()
    maxmemory_opt = "maxmemory %s" % config.redis_maxmemory
    maxmemory_samples_opt = "maxmemory-samples %s" % config.redis_maxmemory_samples
    lfu_log_factor = "lfu-log-factor %s" % config.redis_lfu_log_factor
    lfu_decay_time = "lfu-decay-time %s" % config.redis_lfu_decay_time
    socketperm_opt = "unixsocketperm %s" % SOCKET_PERMS
    logfile_opt = "logfile %s" % LOGFILE
    loglevel_opt = "loglevel %s" % config.redis_loglevel
    redis_conf.append(port_opt)
    #redis_conf.append(bind_opt)
    redis_conf.append(daemonize_opt)
    redis_conf.append(databases_opt)
    redis_conf.append(maxmemory_opt)
    redis_conf.append(socketperm_opt)
    redis_conf.append(socket_opt)
    redis_conf.append(logfile_opt)
    redis_conf.append(loglevel_opt)
    if config.redis_persistence:
        save_opt1 = "save 900 1"
        save_opt2 = "save 300 10"
        save_opt3 = "save 60 10000"
        appendonly_opt = "appendonly yes"
        rdbcompression_opt = "rdbcompression no"
        rdbchecksum_opt = "rdbchecksum no"
        appendfsync_opt = "appendfsync everysec"
        dir_opt = "dir %s" % config.redis_cache_dir
        stop_writes_on_bgsave_error_opt = "stop-writes-on-bgsave-error yes"
        redis_conf.append(save_opt1)
        redis_conf.append(save_opt2)
        redis_conf.append(save_opt3)
        redis_conf.append(rdbcompression_opt)
        redis_conf.append(rdbchecksum_opt)
        redis_conf.append(appendfsync_opt)
        redis_conf.append(stop_writes_on_bgsave_error_opt)
    else:
        save_opt = "save ''"
        appendonly_opt = "appendonly no"
        dir_opt = "dir %s" % config.tmp_dir
        redis_conf.append(save_opt)
    if config.redis_maxmemory_policy == "lfu":
        redis_conf.append(lfu_log_factor)
        redis_conf.append(lfu_decay_time)
        maxmemory_policy_opt = "maxmemory-policy volatile-lfu"
    if config.redis_maxmemory_policy == "lru":
        redis_conf.append(maxmemory_samples_opt)
        maxmemory_policy_opt = "maxmemory-policy volatile-lru"
    redis_conf.append(maxmemory_policy_opt)
    redis_conf.append(appendonly_opt)
    redis_conf.append(dir_opt)
    return redis_conf

def get_socket():
    """ Get redis socket. """
    redis_socket = config.redis_socket
    if redis_socket is None:
        redis_socket = os.path.join(config.sockets_dir, REDIS_SOCKET_NAME)
    return redis_socket

def command(command):
    """ Handle redis command. """
    if command == "start":
        start()
        return wait_for_start()
    elif command == "wait":
        return wait_for_start()
    elif command == "stop":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return stop()
    elif command == "status":
        msg = "Redis not running."
        if not status():
            raise NotRunning()
    elif command == "restart":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        try:
            stop()
        except NotRunning:
            pass
        wait_for_shutdown()
        start()
        wait_for_start()
    elif command == "cli":
        if not status():
            msg = "Redis not running."
            raise NotRunning(msg)
        redis_cli()
    else:
        msg = "Unknown redis command: %s" % command
        raise OTPmeException(msg)

def init_cache_dir():
    from otpme.lib import filetools
    directories = ({
                CACHE_DIR   : 0o700,
                })

    if config.handle_files_dirs:
        # Make sure DB dir exists.
        filetools.ensure_fs_permissions(directories=directories, files=None)
    else:
        for x in directories:
            if os.path.exists(x):
                continue
            msg = ("No such file or directory: %s" % x)
            raise OTPmeException(msg)

def wait_for_start(timeout=5):
    timeout = timeout * 10
    logger = config.logger
    msg = "Waiting for redis to start up..."
    logger.info(msg)
    counter = 0
    while not status():
        counter += 1
        if counter >= timeout:
            return False
        time.sleep(0.1)
    return True

def wait_for_shutdown(timeout=5):
    timeout = timeout * 10
    logger = config.logger
    msg = "Waiting for redis to shut down..."
    logger.info(msg)
    counter = 0
    while status():
        counter += 1
        if counter >= timeout:
            return False
        time.sleep(0.1)
    return True

def status():
    redis_socket = get_socket()
    status_cmd = [config.redis_cli_bin, "-s", redis_socket, "ping"]
    return_code = system_command.run(command=status_cmd,
                                user=config.user,
                                group=config.group,
                                stdout=None,
                                stderr=None,
                                call=True)
    if return_code == 0:
        return True
    return False

def redis_cli():
    # Get cache cli opts.
    cli_opts = sys.argv[2:]
    redis_socket = get_socket()
    cli_cmd = [config.redis_cli_bin, "-s", redis_socket]
    cli_cmd += cli_opts
    return_code = system_command.run(command=cli_cmd,
                                user=config.user,
                                group=config.group,
                                call=True)
    if return_code == 0:
        return True
    return False

def start():
    if status():
        msg = "Redis already running."
        raise AlreadyRunning(msg)
    # Get logger.
    logger = config.logger
    msg = "Starting redis..."
    logger.info(msg)
    # Make sure cache dir exists.
    if config.redis_persistence:
        init_cache_dir()
    redis_socket = get_socket()
    if os.path.exists(redis_socket):
        msg = "Removing stale socket: %s" % redis_socket
        logger.info(msg)
        os.remove(redis_socket)
    conf_file = "-"
    echo_conf = True
    if os.path.exists(ETC_CONF_FILE):
        echo_conf = False
        conf_file = ETC_CONF_FILE
        msg = "Using config file: %s" % ETC_CONF_FILE
        logger.debug(msg)
    start_cmd = [ config.redis_server_bin, conf_file, ]
    proc = system_command.run(command=start_cmd,
                                    user=config.user,
                                    group=config.group,
                                    close_fds=True,
                                    return_proc=True)
    if echo_conf:
        redis_conf = gen_redis_conf()
        _redis_conf = "\n".join(redis_conf)
        _redis_conf = _redis_conf.encode()
        proc.stdin.write(_redis_conf)
    # Start pipe.
    proc.communicate()
    # Wait for process to finish.
    proc.wait()
    return_code = proc.returncode
    if return_code == 0:
        return True
    return False

def stop():
    if not status():
        msg = "Redis not running."
        raise NotRunning(msg)
    # Get logger.
    logger = config.logger
    msg = "Stopping redis..."
    logger.info(msg)
    redis_socket = get_socket()
    stop_cmd = [config.redis_cli_bin, "-s", redis_socket, "shutdown"]
    return_code = system_command.run(command=stop_cmd,
                            user=config.user,
                            group=config.group,
                            stdout=None,
                            stderr=None,
                            call=True)
    if return_code != 0:
        raise NotRunning()

def flushall(raise_exceptions=False):
    # Get logger.
    logger = config.logger
    msg = "Flushing redis cache..."
    logger.debug(msg)
    pool = get_pool()
    redis_db = RedisHandler(connection_pool=pool,
                        raise_exceptions=raise_exceptions,
                        db=0)
    redis_db.flushall()

def get_pool():
    """ Get connection pool. """
    redis_socket = get_socket()
    pool = redis.ConnectionPool(path=redis_socket,
            connection_class=UnixDomainSocketConnection)
    return pool

def get_dict(name, pool=None, clear=False, **kwargs):
    if pool is None:
        pool = get_pool()
    redis_dict = RedisDict(name=name,
                        pool=pool,
                        clear=clear,
                        raise_exceptions=['get'],
                        **kwargs)
    return redis_dict

def get_list(name, pool=None, clear=False, **kwargs):
    if pool is None:
        pool = get_pool()
    redis_list = RedisList(name=name,
                        pool=pool,
                        clear=clear,
                        raise_exceptions=['get'],
                        **kwargs)
    return redis_list

class RedisHandler(object):
    def __init__(self, raise_exceptions=False, **kwargs):
        self.redis_db = redis.Redis(**kwargs)
        self.logger = config.logger
        if isinstance(raise_exceptions, list):
            self.raise_exceptions = raise_exceptions
        elif raise_exceptions is True:
            self.raise_exceptions = [
                                    'config_set',
                                    'scan_iter',
                                    'exists',
                                    'delete',
                                    'set',
                                    'get',
                                    ]
        else:
            self.raise_exceptions = []
        self.connection_error_logged = False
        # config_set() does not work with unix socket pool????
        redis_socket = get_socket()
        self.redis_ctrl = redis.Redis(unix_socket_path=redis_socket, db=0)

    def config_set(self, *args, **kwargs):
        try:
            return self.redis_ctrl.config_set(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "config_set" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

    def scan_iter(self, *args, **kwargs):
        try:
            result = []
            for x in list(self.redis_db.scan_iter(*args, **kwargs)):
                x = x.decode()
                result.append(x)
            return result
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "scan_iter" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)
        return []

    def set(self, *args, **kwargs):
        try:
            return self.redis_db.set(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "set" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

    def exists(self, *args, **kwargs):
        try:
            return self.redis_db.exists(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "exists" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)
        return False

    def get(self, *args, **kwargs):
        try:
            return self.redis_db.get(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "get" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

    def delete(self, *args, **kwargs):
        try:
            return self.redis_db.delete(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "delete" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

    def ttl(self, *args, **kwargs):
        try:
            return self.redis_db.ttl(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "ttl" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

    def expire(self, *args, **kwargs):
        try:
            return self.redis_db.expire(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "expire" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

    def flushall(self, *args, **kwargs):
        try:
            return self.redis_db.flushall(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg = "Redis error: %s" % e
            if "flushall" in self.raise_exceptions:
                raise KeyError(msg)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(msg)

class RedisDict(SharedDict):
    """ A simple redis dict. """
    def __init__(self, name, pool, locking=None, clear=False,
        raise_exceptions=False, refresh_keys=False,
        compression=None, pickle=False):
        super(RedisDict, self).__init__(name)
        self.name = name
        self.pickle = pickle
        self.pickle_handler = None
        self.locking = locking
        self.compression = compression
        self.dict_data_key = "dict_data"
        self.refresh_keys = refresh_keys
        #self.logger = config.logger
        self.pool = pool
        self.redis_db = RedisHandler(connection_pool=pool,
                                    raise_exceptions=raise_exceptions,
                                    db=0)
        # Make sure redis persistence is disabled.
        if not config.redis_persistence:
            self.redis_db.config_set("appendonly" ,"no")
            self.redis_db.config_set("save" ,"")
        if self.pickle:
            pickel_type = config.pickle_cache_module
            self.pickle_handler = PickleHandler(pickel_type, encode=True)
        self._lock = None
        #self.redis_db.config_rewrite()
        if clear:
            self.clear()

    def lock(self):
        """
        Lock complete dict (prevent race when changing list contained in dict).
        """
        from otpme.lib import locking
        lock_id = "redis-dict-%s" % self.name
        self._lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                            lock_id=lock_id)

    def release(self):
        if not self._lock:
            return
        self._lock.release_lock()

    def clear(self):
        search_regex = "%s.*" % self.name
        keys = self.redis_db.scan_iter(search_regex)
        if not keys:
            return
        self.redis_db.delete(*keys)

    def keys(self):
        keys = []
        search_regex = "%s.%s.*" % (self.name, self.dict_data_key)
        replace_regex = "%s.%s.(.*)" % (self.name, self.dict_data_key)
        _keys = self.redis_db.scan_iter(search_regex)
        for x in _keys:
            key = re.sub(replace_regex, r'\1', x)
            keys.append(key)
        return keys

    def values(self):
        values = []
        search_regex = "%s.%s.*" % (self.name, self.dict_data_key)
        _keys = self.redis_db.scan_iter(search_regex)
        for x in _keys:
            value = self._get(x)
            values.append(value)
        return values

    def items(self):
        items = []
        search_regex = "%s.%s.*" % (self.name, self.dict_data_key)
        replace_regex = "%s.%s.(.*)" % (self.name, self.dict_data_key)
        _keys = self.redis_db.scan_iter(search_regex)
        for x in _keys:
            key = re.sub(replace_regex, r'\1', x)
            try:
                value = self._get(x)
            except KeyError:
                continue
            item = (key, value)
            items.append(item)
        return items

    def add(self, key, value, expire=None, **kwargs):
        from otpme.lib import locking
        _key = self.get_key_id(key)
        if self.locking:
            _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=_key)
        try:
            # Add key.
            self._add(_key, value, expire=expire, **kwargs)
            if self.refresh_keys:
                # Set key expire time.
                if expire is not None:
                    expire_key = self.get_key_expire_id(key)
                    self.redis_db.set(expire_key, expire, ex=expire)
        finally:
            if self.locking:
                _lock.release_lock()

    def get(self, key, **kwargs):
        from otpme.lib import locking
        _key = self.get_key_id(key)
        # Check for key expiry refresh.
        if self.locking:
            _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=_key)
        try:
            if self.refresh_keys:
                expire_key = self.get_key_expire_id(key)
                try:
                    key_expire = self.redis_db.get(expire_key)
                except:
                    key_expire = None
                if key_expire is not None:
                    self.redis_db.expire(_key, key_expire)
            return self._get(_key, **kwargs)
        finally:
            if self.locking:
                _lock.release_lock()

    def _add(self, key, value, expire=None):
        # Pickle data.
        if self.pickle:
            value = self.pickle_handler.dumps(value)
        else:
            value = json.dumps(value)
        # Compress value.
        if self.compression:
            value = stuff.compress(value, self.compression)
        #self.redis_db.mset({key:value})
        if expire is None:
            self.redis_db.set(key, value)
        else:
            self.redis_db.set(key, value, ex=expire)

    def _get(self, key):
        if not self.redis_db.exists(key):
            raise KeyError(key)
        # Get value.
        value = self.redis_db.get(key)
        if value is None:
            raise KeyError(key)
        # Decompress value.
        if self.compression:
            value = stuff.decompress(value, self.compression)
        # Unpickle data.
        if self.pickle:
            value = self.pickle_handler.loads(value)
        else:
            value = json.loads(value)
        return value

    def delete(self, key):
        from otpme.lib import locking
        _key = self.get_key_id(key)
        if self.locking:
            _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=_key)
        try:
            deleted_item = self.get(key)
            self.redis_db.delete(_key)
        finally:
            # Remove expire key.
            if self.refresh_keys:
                expire_key = self.get_key_expire_id(key)
                self.redis_db.delete(expire_key)
            if self.locking:
                _lock.release_lock()
        return deleted_item

    def close(self):
        self.pool.disconnect()

class RedisList(SharedList):
    """ A simple redis list. """
    def __init__(self, name, pool, clear=False, pickle=False,
        compression=None, raise_exceptions=False, **kwargs):
        super(RedisList, self).__init__(name)
        #self.logger = config.logger
        self.pool = pool
        self.pickle = pickle
        self.pickle_handler = None
        self.compression = compression
        self.redis_db = RedisHandler(connection_pool=pool,
                                    raise_exceptions=raise_exceptions,
                                    db=0)
        # Make sure redis persistence is disabled.
        if not config.redis_persistence:
            self.redis_db.config_set("appendonly" ,"no")
            self.redis_db.config_set("save" ,"")
        #self.redis_db.config_rewrite()
        if self.pickle:
            pickel_type = config.pickle_cache_module
            self.pickle_handler = PickleHandler(pickel_type, encode=True)
        if clear:
            self.clear()

    @property
    def list(self):
        try:
            _list = self.redis_db.get(self.name)
            # Decompress list.
            if self.compression:
                _list = stuff.decompress(_list, self.compression)
            # Unpickle data.
            if self.pickle:
                _list = self.pickle_handler.loads(_list)
            else:
                _list = json.loads(_list)
        except:
            _list = []
        return _list

    @list.setter
    def list(self, _list):
        # Pickle data.
        if self.pickle:
            _list = self.pickle_handler.dumps(_list)
        else:
            _list = json.dumps(_list)
        # Compress list.
        if self.compression:
            _list = stuff.compress(_list, self.compression)
        #self.redis_db.mset({self.name:_list})
        self.redis_db.set(self.name, _list)
        return _list

    def clear(self):
        self.redis_db.delete(self.name)

    def insert(self, i, value):
        from otpme.lib import locking
        _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=self.name)
        try:
            _list = self.list
            _list.insert(i, value)
            self.list = _list
        finally:
            _lock.release_lock()

    def append(self, value):
        from otpme.lib import locking
        _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=self.name)
        try:
            _list = self.list
            _list.insert(len(self.list), value)
            self.list = _list
        finally:
            _lock.release_lock()

    def remove(self, value):
        from otpme.lib import locking
        _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=self.name)
        try:
            _list = self.list
            _list.remove(value)
            self.list = _list
        finally:
            _lock.release_lock()

    def close(self):
        self.pool.disconnect()

class RedisInvalidationStrategy(CustomInvalidationStrategy):
    def __init__(self, region, redis_pool, **kwargs):
        super(RedisInvalidationStrategy, self).__init__(region, **kwargs)
        self.redis_db = RedisHandler(connection_pool=redis_pool,
                                    raise_exceptions=False,
                                    db=0)
    def invalidate(self, hard=None):
        super(RedisInvalidationStrategy, self).invalidate(hard=hard)
        # Do real cache invalidation.
        search_regex = "dogpile.%s.*" % self.region
        keys = self.redis_db.scan_iter(search_regex)
        if not keys:
            return
        self.redis_db.delete(*keys)

def get_dogpile_region(name, expire=7200):
    redis_pool = get_pool()
    redis_config = {
                    #'host': 'localhost',
                    #'port': 6379,
                    'db': 0,
                    'redis_expiration_time': expire,
                    'distributed_lock': True,
                    'thread_local_lock': False,
                    'connection_pool': redis_pool,
                    }
    def key_mangler(key):
        return md5_key_mangler(prefix=name, key=key)
    cache_invalidator = RedisInvalidationStrategy(region=name,
                                        redis_pool=redis_pool)
    region = make_region(key_mangler=key_mangler)
    region = region.configure("dogpile.cache.redis",
                            arguments=redis_config,
                            region_invalidator=cache_invalidator)
    return region
