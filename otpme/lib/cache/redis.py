# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Module for handling of redis caching.

https://redis-py.readthedocs.io/en/stable/
"""
import os
import sys
import time

from otpme.lib.cache.dogpile import md5_key_mangler
from otpme.lib.cache.dogpile import CustomInvalidationStrategy

# Heavy third-party imports are deferred to first use; importing this module
# must stay cheap for CLI clients that never touch redis caching.
redis = None
UnixDomainSocketConnection = None
make_region = None

def _load_redis():
    global redis, UnixDomainSocketConnection
    if redis is not None:
        return
    import redis as _r
    from redis.connection import UnixDomainSocketConnection as _UDSC
    redis = _r
    UnixDomainSocketConnection = _UDSC

def _load_make_region():
    global make_region
    if make_region is not None:
        return
    from dogpile.cache.region import make_region as _mr
    make_region = _mr

try:
    import simdjson as json
except Exception:
    try:
        import ujson as json
    except Exception:
        import json
try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

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

# Ensure persistence-disable config_set() runs only once per process.
_persistence_configured = False

def _ensure_persistence_disabled(redis_db):
    global _persistence_configured
    if _persistence_configured:
        return
    if config.redis_persistence:
        _persistence_configured = True
        return
    redis_db.config_set("appendonly", "no")
    redis_db.config_set("save", "")
    _persistence_configured = True

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
    databases_opt = f"databases {config.redis_databases}"
    socket_opt = f"unixsocket {get_socket()}"
    maxmemory_opt = f"maxmemory {config.redis_maxmemory}"
    maxmemory_samples_opt = f"maxmemory-samples {config.redis_maxmemory_samples}"
    lfu_log_factor = f"lfu-log-factor {config.redis_lfu_log_factor}"
    lfu_decay_time = f"lfu-decay-time {config.redis_lfu_decay_time}"
    socketperm_opt = f"unixsocketperm {SOCKET_PERMS}"
    logfile_opt = f"logfile {LOGFILE}"
    loglevel_opt = f"loglevel {config.redis_loglevel}"
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
        dir_opt = f"dir {config.redis_cache_dir}"
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
        dir_opt = f"dir {config.tmp_dir}"
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
            msg = _("Please stop otpme daemon first.")
            raise OTPmeException(msg)
        return stop()
    elif command == "status":
        msg = _("Redis not running.")
        if not status():
            raise NotRunning()
    elif command == "restart":
        if stuff.controld_status():
            msg = _("Please stop otpme daemon first.")
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
            msg = _("Redis not running.")
            raise NotRunning(msg)
        redis_cli()
    else:
        msg = _("Unknown redis command: {command}")
        msg = msg.format(command=command)
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
            msg = _("No such file or directory: {directory}")
            msg = msg.format(directory=x)
            raise OTPmeException(msg)

def wait_for_start(timeout=5):
    timeout = timeout * 10
    logger = config.logger
    log_msg = _("Waiting for redis to start up...", log=True)[1]
    logger.info(log_msg)
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
    log_msg = _("Waiting for redis to shut down...", log=True)[1]
    logger.info(log_msg)
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
        msg = _("Redis already running.")
        raise AlreadyRunning(msg)
    # Get logger.
    logger = config.logger
    log_msg = _("Starting redis...", log=True)[1]
    logger.info(log_msg)
    # Make sure cache dir exists.
    if config.redis_persistence:
        init_cache_dir()
    redis_socket = get_socket()
    if os.path.exists(redis_socket):
        log_msg = _("Removing stale socket: {socket_path}", log=True)[1]
        log_msg = log_msg.format(socket_path=redis_socket)
        logger.info(log_msg)
        os.remove(redis_socket)
    conf_file = "-"
    echo_conf = True
    if os.path.exists(ETC_CONF_FILE):
        echo_conf = False
        conf_file = ETC_CONF_FILE
        log_msg = _("Using config file: {config_file}", log=True)[1]
        log_msg = log_msg.format(config_file=ETC_CONF_FILE)
        logger.debug(log_msg)
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
        msg = _("Redis not running.")
        raise NotRunning(msg)
    # Get logger.
    logger = config.logger
    log_msg = _("Stopping redis...", log=True)[1]
    logger.info(log_msg)
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
    log_msg = _("Flushing redis cache...", log=True)[1]
    logger.debug(log_msg)
    pool = get_pool()
    redis_db = RedisHandler(connection_pool=pool,
                        raise_exceptions=raise_exceptions,
                        db=0)
    redis_db.flushall()

def get_pool():
    """ Get connection pool. """
    _load_redis()
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
        _load_redis()
        self.redis_db = redis.Redis(**kwargs)
        self.logger = config.logger
        if isinstance(raise_exceptions, list):
            self.raise_exceptions = raise_exceptions
        elif raise_exceptions is True:
            self.raise_exceptions = [
                                    'config_set',
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
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "config_set" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

# No scan_iter() here on purpose. SCAN walks the whole keyspace
# whatever MATCH is given -- the pattern only decides what comes back
# -- so anything that calls it once per object pays for every key in
# redis, and pays more the fuller redis gets. Whoever needs to know
# which keys a dict holds asks the set it keeps (RedisDict).

    def set(self, *args, **kwargs):
        try:
            return self.redis_db.set(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "set" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def exists(self, *args, **kwargs):
        try:
            return self.redis_db.exists(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "exists" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)
        return False

    def get(self, *args, **kwargs):
        try:
            return self.redis_db.get(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "get" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def mget(self, *args, **kwargs):
        try:
            return self.redis_db.mget(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "mget" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)
        return []

    def delete(self, *args, **kwargs):
        try:
            return self.redis_db.delete(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "delete" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def sadd(self, *args, **kwargs):
        try:
            return self.redis_db.sadd(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "sadd" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def srem(self, *args, **kwargs):
        try:
            return self.redis_db.srem(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "srem" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def smembers(self, *args, **kwargs):
        try:
            result = []
            for x in self.redis_db.smembers(*args, **kwargs):
                result.append(x.decode())
            return result
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "smembers" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)
        return []

    def ttl(self, *args, **kwargs):
        try:
            return self.redis_db.ttl(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "ttl" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def expire(self, *args, **kwargs):
        try:
            return self.redis_db.expire(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "expire" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

    def flushall(self, *args, **kwargs):
        try:
            return self.redis_db.flushall(*args, **kwargs)
        except (redis.ConnectionError, redis.ResponseError) as e:
            msg, log_msg = _("Redis error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if "flushall" in self.raise_exceptions:
                raise KeyError(msg) from e
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)

class RedisDict(SharedDict):
    """ A simple redis dict. """
    def __init__(self, name, pool, locking=None, clear=False,
        raise_exceptions=False, refresh_keys=False,
        compression=None, pickle=False):
        super().__init__(name)
        self.name = name
        self.pickle = pickle
        self.pickle_handler = None
        self.locking = locking
        self.compression = compression
        self.dict_data_key = "dict_data"
        # The keys we wrote, as a redis set. clear() used to find them
        # with SCAN, which walks the whole keyspace however few keys
        # this dict has -- MATCH only filters what comes back. That is
        # paid per clear(), and the function caches clear themselves on
        # every write of an object (FuncCache.invalidate()), so a
        # command that walks a tree spent most of its time scanning
        # redis, and more of it the fuller redis got.
        self.keys_set_id = f"{self.name}.keys"
        self.refresh_keys = refresh_keys
        #self.logger = config.logger
        self.pool = pool
        self.redis_db = RedisHandler(connection_pool=pool,
                                    raise_exceptions=raise_exceptions,
                                    db=0)
        # Make sure redis persistence is disabled (once per process).
        _ensure_persistence_disabled(self.redis_db)
        if self.pickle:
            pickel_type = config.pickle_cache_module
            self.pickle_handler = PickleHandler(pickel_type)
        self._lock = None
        #self.redis_db.config_rewrite()
        if clear:
            self.clear()

    def lock(self):
        """
        Lock complete dict (prevent race when changing list contained in dict).
        """
        from otpme.lib import locking
        lock_id = f"redis-dict-{self.name}"
        self._lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                            lock_id=lock_id)

    def release(self):
        if not self._lock:
            return
        self._lock.release_lock()

    def clear(self):
        keys = self.redis_db.smembers(self.keys_set_id)
        if keys:
            # A key that expired in the meantime is gone already and
            # deleting it does nothing, so the set does not have to be
            # kept free of them. It goes with them anyway.
            self.redis_db.delete(*keys)
        self.redis_db.delete(self.keys_set_id)

    def _known_keys(self):
        """ The keys the writes put in the set, as the caller named them.

        From the set and not from a SCAN, for the reason above. A key
        that has expired since it was written is still in here; the
        three methods below ask redis for the values and drop the ones
        that are not there anymore, which is one roundtrip and tells
        them the same thing a scan would have.
        """
        prefix = f"{self.name}.{self.dict_data_key}."
        keys = []
        for x in self.redis_db.smembers(self.keys_set_id):
            if not x.startswith(prefix):
                continue
            keys.append(x[len(prefix):])
        return keys

    def keys(self):
        keys = self._known_keys()
        if not keys:
            return []
        # The values are not wanted here, only whether they are there,
        # so this does not go through get_multi() and its decoding.
        _keys = [self.get_key_id(x) for x in keys]
        values = self.redis_db.mget(_keys)
        result = []
        for x_key, x_value in zip(keys, values):
            if x_value is None:
                continue
            result.append(x_key)
        return result

    def values(self):
        return list(self.get_multi(self._known_keys()).values())

    def items(self):
        return list(self.get_multi(self._known_keys()).items())

    def add(self, key, value, expire=None, **kwargs):
        from otpme.lib import locking
        _key = self.get_key_id(key)
        if self.locking:
            _lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=_key)
        try:
            # Add key.
            self._add(_key, value, expire=expire, **kwargs)
            # Remember it, so clear() finds it without a scan.
            self.redis_db.sadd(self.keys_set_id, _key)
            if self.refresh_keys:
                # Set key expire time.
                if expire is not None:
                    expire_key = self.get_key_expire_id(key)
                    self.redis_db.set(expire_key, expire, ex=expire)
                    self.redis_db.sadd(self.keys_set_id, expire_key)
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
                except Exception:
                    key_expire = None
                if key_expire is not None:
                    self.redis_db.expire(_key, key_expire)
            return self._get(_key, **kwargs)
        finally:
            if self.locking:
                _lock.release_lock()

    def get_multi(self, keys):
        """ Get many keys in one roundtrip.

        Returns what is there, missing keys are simply not in the
        result. Callers that need all of them have to check.
        """
        keys = list(keys)
        if not keys:
            return {}
        _keys = [self.get_key_id(x) for x in keys]
        values = self.redis_db.mget(_keys)
        result = {}
        for x_key, x_value in zip(keys, values):
            if x_value is None:
                continue
            if self.compression:
                x_value = stuff.decompress(x_value, self.compression)
            if self.pickle:
                x_value = self.pickle_handler.loads(x_value)
            else:
                x_value = json.loads(x_value)
            result[x_key] = x_value
        return result

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
        # Get value (single roundtrip; None means missing key since
        # _add() always serializes values via pickle/json).
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
            self.redis_db.srem(self.keys_set_id, _key)
        finally:
            # Remove expire key.
            if self.refresh_keys:
                expire_key = self.get_key_expire_id(key)
                self.redis_db.delete(expire_key)
                self.redis_db.srem(self.keys_set_id, expire_key)
            if self.locking:
                _lock.release_lock()
        return deleted_item

    def close(self):
        self.pool.disconnect()

class RedisList(SharedList):
    """ A simple redis list. """
    def __init__(self, name, pool, clear=False, pickle=False,
        compression=None, raise_exceptions=False, **kwargs):
        super().__init__(name)
        #self.logger = config.logger
        self.pool = pool
        self.pickle = pickle
        self.pickle_handler = None
        self.compression = compression
        self.redis_db = RedisHandler(connection_pool=pool,
                                    raise_exceptions=raise_exceptions,
                                    db=0)
        # Make sure redis persistence is disabled (once per process).
        _ensure_persistence_disabled(self.redis_db)
        #self.redis_db.config_rewrite()
        if self.pickle:
            pickel_type = config.pickle_cache_module
            self.pickle_handler = PickleHandler(pickel_type)
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
        except Exception:
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
        super().__init__(region, **kwargs)
        self.redis_db = RedisHandler(connection_pool=redis_pool,
                                    raise_exceptions=False,
                                    db=0)
    def invalidate(self, hard=None):
        # The timestamp the base class writes is what makes the
        # entries of this region invalid: dogpile asks
        # is_invalidated() with the time an entry was created and
        # throws away everything older. So nothing has to be deleted
        # here, and what was deleted here cost a SCAN over the whole
        # redis keyspace per call -- these keys are written by
        # dogpile's own backend, so there is no set of them to go by.
        # They carry the expiry the region was configured with
        # (redis_expiration_time, see get_dogpile_region()), so redis
        # reclaims them by itself.
        super().invalidate(hard=hard)

def get_dogpile_region(name, expire=7200):
    _load_make_region()
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
