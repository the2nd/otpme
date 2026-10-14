# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Module for handling memcached caching.

http://sendapatch.se/projects/pylibmc/reference.html
"""
import os
import re
import sys
import time
import zlib
try:
    import pylibmc
except ImportError:
    # Ignore missing module (e.g. other cache type configured.
    pass
#import memcache

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
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib.pickle import PickleHandler
from otpme.lib.multiprocessing import SharedDict
from otpme.lib.multiprocessing import SharedList

from otpme.lib.exceptions import *

NC_BIN = "nc"

# The list of keys a dict holds lives in this many items, not in one.
# memcached takes at most a megabyte per item, and the list of a well
# filled cache goes past that: 12800 keys of 80 characters already do.
# Spreading it lifts that ceiling, and two processes writing different
# keys mostly append to different items.
KEY_LIST_SHARDS = 16
# How many keys go into one get_multi()/delete_multi().
MULTI_BLOCK_SIZE = 500
# Rewrite one of those items once it holds this many lines that are not
# needed any more. Appending a key again is cheaper than first asking
# whether it is already in there, so lines repeat and lines of deleted
# keys stay; both are cleaned up here instead of being avoided.
KEY_LIST_SPARE_LINES = 128
# What memcached takes as a key: no longer than this, and no space, no
# control character and nothing above ascii in it. The two brackets were
# replaced before this was written down and stay replaced.
MAX_KEY_LEN = 250
INVALID_KEY_CHARS = re.compile(r"[^!-'*-~]")

def get_blocks(items, size):
    """ The items in blocks of at most the given size. """
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]

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
        except Exception:
            pid = None
        return pid

    def start(self):
        log_msg = _("Starting {name}...", log=True)[1]
        log_msg = log_msg.format(name=self.name)
        self.logger.info(log_msg)
        return self.start_function()

    def wait_for_start(self, timeout=5):
        timeout = timeout * 10
        log_msg = _("Waiting for {name} to start up...", log=True)[1]
        log_msg = log_msg.format(name=self.name)
        self.logger.info(log_msg)
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
            msg = _("{name} not running.")
            msg = msg.format(name=self.name)
            raise NotRunning(msg)
        log_msg = _("Stopping {name}...", log=True)[1]
        log_msg = log_msg.format(name=self.name)
        self.logger.info(log_msg)
        pid = self.get_pid()
        stuff.kill_pid(pid, timeout=10)
        if not os.path.exists(self.socket):
            return
        os.remove(self.socket)

    def wait_for_shutdown(self, timeout=5):
        timeout = timeout * 10
        log_msg = _("Waiting for {name} to shut down...", log=True)[1]
        log_msg = log_msg.format(name=self.name)
        self.logger.info(log_msg)
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
            # With cas, so the list of keys a dict holds can be
            # rewritten without losing a key that another process
            # appended while we were reading it. It costs nothing
            # measurable on the other commands.
            mc = pylibmc.Client([self.socket], behaviors={"cas": True})
            pool = pylibmc.ThreadMappedPool(mc)
            return pool
        return pool_getter

    def get_list(self, name, pool=None, clear=False, locking=False, pickle=False):
        if pool is None:
            pool = self.get_pool()
        _list = MemcacheList(name=name,
                            pool=pool,
                            clear=clear,
                            pickle=pickle,
                            locking=locking,
                            lock_type=self.lock_type)
        return _list

    def get_dict(self, name, pool=None, clear=False, locking=False, pickle=False):
        if pool is None:
            pool = self.get_pool()
        _dict = MemcacheDict(name=name,
                            pool=pool,
                            clear=clear,
                            pickle=pickle,
                            locking=locking,
                            lock_type=self.lock_type)
        return _dict

    def flushall(self):
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
    def __init__(self, pool_getter, compression=None, pickle=False):
        self.pools = {}
        self.pickle = pickle
        self.pickle_handler = None
        self.compression = compression
        self.logger = config.logger
        self.pool_getter = pool_getter
        self.connection_error_logged = False
        if self.pickle:
            pickel_type = config.pickle_cache_module
            self.pickle_handler = PickleHandler(pickel_type)

    @property
    def pool(self):
        pid = os.getpid()
        try:
            pool = self.pools[pid]
        except Exception:
            pool = self.pool_getter()
            self.pools[pid] = pool
        return pool

    def drop_pool(self):
        """ Throw away the connections of this process. """
        self.pools.pop(os.getpid(), None)

    def run(self, method, *args, **kwargs):
        """ Run a memcached command, once more on a dead connection.

        A pooled connection outlives the memcached it was made to: a
        restart of memcached, or its connection limit turning us away,
        leaves every long lived process holding one that is gone. The
        first command on it fails, and it would go on failing as long as
        the pool hands the same connection out again. So drop the pool
        of this process and try once with a new connection, which is
        what a client would get if it had just started.

        The second failure is the callers to deal with -- then memcached
        really is not answering.
        """
        try:
            with self.pool.reserve() as mc:
                return getattr(mc, method)(*args, **kwargs)
        except (pylibmc.Error, pylibmc.ConnectionError) as e:
            log_msg = _("Memcache {method} failed, reconnecting: {error}", log=True)[1]
            log_msg = log_msg.format(method=method, error=e)
            self.logger.warning(log_msg)
            self.drop_pool()
        with self.pool.reserve() as mc:
            result = getattr(mc, method)(*args, **kwargs)
        # It answered again, so the next failure is worth a line of its
        # own rather than being swallowed as "already logged".
        self.connection_error_logged = False
        return result

    @classmethod
    def sanitize_key(cls, key):
        """ A key memcached will take.

        It refuses a space, a control character and anything longer than
        250 characters, and it does so by failing the whole command. That
        used to be handled in set() alone, and only for three characters:
        a key with a space in it was written under one name and looked
        for under another -- a miss every time, and a silent one.

        A key that had to be changed gets a checksum of the original
        behind it, so that two keys that differ only in the characters
        replaced here do not turn into one, and a key cut to length keeps
        what told it apart from the others.
        """
        if len(key) <= MAX_KEY_LEN and not INVALID_KEY_CHARS.search(key):
            return key
        checksum = f"{zlib.crc32(key.encode()):08x}"
        key = INVALID_KEY_CHARS.sub("_", key)
        # The checksum and the dot in front of it have to fit, too.
        if len(key) > MAX_KEY_LEN - 9:
            key = key[:MAX_KEY_LEN - 9]
        return f"{key}.{checksum}"

    def get(self, key):
        key = self.sanitize_key(key)
        try:
            value = self.run("get", key)
        except pylibmc.Error as e:
            msg, log_msg = _("Memcache get error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)
            raise KeyError(msg) from e
        except pylibmc.ConnectionError as e:
            msg, log_msg = _("Memcache connection error: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            if not self.connection_error_logged:
                self.connection_error_logged = True
                self.logger.critical(log_msg)
            raise KeyError(msg) from e
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

    def get_multi_raw(self, keys):
        """ Get many keys in one roundtrip, values as they lie there.

        Missing keys are simply not in the result, same as memcached
        answers them. Answered by the names the caller gave, not by the
        ones memcached was asked for: sanitize_key() may have changed
        them.
        """
        keys = list(keys)
        if not keys:
            return {}
        key_map = {}
        for x_key in keys:
            key_map[self.sanitize_key(x_key)] = x_key
        try:
            values = self.run("get_multi", list(key_map))
        except (pylibmc.Error, pylibmc.ConnectionError) as e:
            if not self.connection_error_logged:
                self.connection_error_logged = True
                log_msg = _("Memcache get_multi error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            return {}
        result = {}
        for x_key, x_value in values.items():
            if x_value is None:
                continue
            result[key_map.get(x_key, x_key)] = x_value
        return result

    def get_multi(self, keys):
        """ Get many keys in one roundtrip. """
        result = {}
        for x_key, x_value in self.get_multi_raw(keys).items():
            if self.compression:
                x_value = stuff.decompress(x_value, self.compression)
            if self.pickle:
                x_value = self.pickle_handler.loads(x_value)
            else:
                x_value = json.loads(x_value)
            result[x_key] = x_value
        return result

    def exists_multi(self, keys):
        """ Which of these keys are still there, in one roundtrip.

        The values are not wanted, only whether they are there, so
        nothing is decompressed or decoded on the way.
        """
        return set(self.get_multi_raw(keys))

    def encode_value(self, value):
        """ A value the way set() and replace() store it. """
        # Pickle data.
        if self.pickle:
            value = self.pickle_handler.dumps(value)
        else:
            value = json.dumps(value)
        # Compress value.
        if self.compression:
            value = stuff.compress(value, self.compression)
        return value

    def replace(self, key, value, **kwargs):
        """ Write a value, but only over one that is there.

        Says whether it was written. False also where memcached could
        not be asked: the caller then goes the way of a new key, which
        is the safe one.
        """
        key = self.sanitize_key(key)
        value = self.encode_value(value)
        try:
            return bool(self.run("replace", key, value, **kwargs))
        except (pylibmc.Error, pylibmc.ConnectionError):
            return False

    def set(self, key, value, **kwargs):
        key = self.sanitize_key(key)
        value = self.encode_value(value)
        #cas = self.self.pool.gets(key)
        #if cas is not None:
        #    self.pool.cas(key, value, cas, **kwargs)
        #else:
        #    self.pool.set(key, value, **kwargs)
        #with self.pool.reserve() as mc:
        #    cas = mc.gets(key)
        #    mc.sets(key, value, cas, **kwargs)
        try:
            self.run("set", key, value, **kwargs)
        except pylibmc.Error as e:
            if self.connection_error_logged:
                return
            key_len = len(key) if isinstance(key, (bytes, str)) else -1
            value_len = len(value) if isinstance(value, (bytes, str)) else -1
            log_msg = _("Memcache set error: {error} (key_len={key_len}, value_len={value_len}, key_preview={preview!r})", log=True)[1]
            log_msg = log_msg.format(error=e, key_len=key_len, value_len=value_len, preview=key[:80] if isinstance(key, (bytes, str)) else key)
            self.connection_error_logged = True
            self.logger.critical(log_msg)
        except pylibmc.ConnectionError as e:
            if self.connection_error_logged:
                return
            log_msg = _("Memcache connection error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.connection_error_logged = True
            self.logger.critical(log_msg)

    def raw_gets(self, key):
        """ A value as it lies there, with the cas id memcached has for it.

        The list of keys a dict holds is bookkeeping and not something
        anybody cached, and it is appended to as text, so it does not go
        through the encoding the values get.

        The cas id says which version of the item we read. Handing it
        back to raw_cas() writes only if nobody changed the item since,
        which is how the list can be rewritten without losing a key that
        somebody appended in the meantime. It is None when the client was
        built without cas support; a caller that needs it has to leave
        the item alone then.
        """
        key = self.sanitize_key(key)
        try:
            value, cas_id = self.run("gets", key)
        except ValueError:
            # "gets without cas behavior".
            try:
                value = self.run("get", key)
            except (pylibmc.Error, pylibmc.ConnectionError):
                return None, None
            cas_id = None
        except (pylibmc.Error, pylibmc.ConnectionError) as e:
            if not self.connection_error_logged:
                self.connection_error_logged = True
                log_msg = _("Memcache raw get error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            return None, None
        if isinstance(value, bytes):
            value = value.decode()
        return value, cas_id

    def raw_cas(self, key, value, cas_id):
        """ Write a raw value if the item is still the one we read.

        Says whether it was written. See raw_gets().
        """
        key = self.sanitize_key(key)
        try:
            return bool(self.run("cas", key, value, cas_id))
        except (pylibmc.Error, pylibmc.ConnectionError) as e:
            if not self.connection_error_logged:
                self.connection_error_logged = True
                log_msg = _("Memcache cas error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            return False

    def raw_add(self, key, value):
        """ Write a raw value, but only if nobody else did first.

        Says whether it was us. Where two processes start the list of
        keys at the same time, one of them learns that it lost and
        appends to the other's instead of writing over it.
        """
        key = self.sanitize_key(key)
        try:
            return bool(self.run("add", key, value))
        except (pylibmc.Error, pylibmc.ConnectionError) as e:
            if not self.connection_error_logged:
                self.connection_error_logged = True
                log_msg = _("Memcache add error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            return False

    def raw_append(self, key, value):
        """ Put a raw value after what is there, in one atomic call.

        Says whether there was something to append to. memcached does
        this itself, so two processes appending at the same time both
        get their line in -- which a read, a change and a write back
        cannot promise.
        """
        key = self.sanitize_key(key)
        try:
            return bool(self.run("append", key, value))
        except (pylibmc.Error, pylibmc.ConnectionError) as e:
            if not self.connection_error_logged:
                self.connection_error_logged = True
                log_msg = _("Memcache append error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            return False

    def delete_multi(self, keys):
        """ Take many keys out, in as few roundtrips as it takes. """
        keys = [self.sanitize_key(x) for x in keys]
        for block in get_blocks(keys, MULTI_BLOCK_SIZE):
            try:
                self.run("delete_multi", block)
            except (pylibmc.Error, pylibmc.ConnectionError) as e:
                if not self.connection_error_logged:
                    self.connection_error_logged = True
                    log_msg = _("Memcache delete_multi error: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg)
                return

    def delete(self, key, **kwargs):
        key = self.sanitize_key(key)
        try:
            self.run("delete", key, **kwargs)
        except pylibmc.Error as e:
            if self.connection_error_logged:
                return
            log_msg = _("Memcache delete error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            return
        except pylibmc.ConnectionError as e:
            if self.connection_error_logged:
                return
            log_msg = _("Memcache connection error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            return

class MemcacheDict(SharedDict):
    """ A simple memcached dict. """
    def __init__(self, name, pool, locking=False, lock_type="memcached",
        clear=False, refresh_keys=False, compression=None, pickle=False):
        super().__init__(name)
        self.client = MemcacheClient(pool, compression=compression, pickle=pickle)
        # The keys we wrote. memcached has nothing to walk its keys with,
        # so the dict has to write down what it put in. The name below is
        # a prefix: the list itself sits in KEY_LIST_SHARDS items beside
        # each other and is appended to.
        self.dict_keys_key = f"{self.name}.dict_keys"
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
        lock_id = f"memcached-dict-{self.name}"
        self._lock = locking.acquire_lock(lock_type=self.lock_type,
                                            lock_id=lock_id)

    def release(self):
        if not self._lock:
            return
        self._lock.release_lock()

    def clear(self):
        keys = self.get_dict_keys()
        if keys:
            # A key that expired in the meantime is gone already and
            # deleting it does nothing, so the list does not have to be
            # kept free of them. It goes with them anyway.
            value_keys = [self.get_key_id(x) for x in keys]
            if self.refresh_keys:
                value_keys += [self.get_key_expire_id(x) for x in keys]
            self.client.delete_multi(value_keys)
        # The last one is where the list used to live before it was
        # split up; an upgraded memcached still holds it.
        self.client.delete_multi(self.get_dict_keys_keys()
                                + [self.dict_keys_key])

    def keys(self):
        keys = self.get_dict_keys()
        if not keys:
            return []
        gone = self.get_gone_keys(keys)
        if not gone:
            return keys
        # Now we know which of the remembered keys expired or were
        # deleted. Taking them out of the list is what keeps it from
        # growing for as long as memcached runs.
        if len(gone) > KEY_LIST_SPARE_LINES:
            self.drop_dict_keys(gone)
        return [x for x in keys if x not in gone]

    def values(self):
        return list(self.get_multi(self.get_dict_keys()).values())

    def items(self):
        return list(self.get_multi(self.get_dict_keys()).items())

    def get_dict_keys_key(self, shard):
        return f"{self.dict_keys_key}.{shard}"

    def get_dict_keys_keys(self):
        return [self.get_dict_keys_key(x) for x in range(KEY_LIST_SHARDS)]

    @staticmethod
    def get_key_shard(key):
        # crc32 and not hash(): every process has to put a key in the
        # same place, and hash() of a string does not.
        #
        # Not every key is a string. The cluster queues use a timestamp
        # (float) as the key, and a dict takes anything hashable. Such a
        # key goes in the way it is written to the list, so both ways to
        # that list agree on the shard.
        if not isinstance(key, str):
            key = json.dumps(key)
        return zlib.crc32(key.encode()) % KEY_LIST_SHARDS

    def read_dict_keys_shard(self, raw):
        """ The keys of one item of the list, each one once.

        Answers with the keys and with how many lines they came from,
        which is what tells the callers whether it is worth rewriting.
        """
        keys = []
        seen = set()
        lines = 0
        for line in raw.split("\n"):
            if not line:
                continue
            lines += 1
            try:
                key = json.loads(line)
            except Exception:
                # A line memcached cut off because the item was full.
                continue
            if key in seen:
                continue
            seen.add(key)
            keys.append(key)
        return keys, lines

    def get_dict_keys(self):
        """ The keys the writes remembered, each one once.

        The lines are read as they were appended, so a key can be in
        there more than once. Where that got out of hand the item is
        rewritten, which is also what gets rid of the lines of keys that
        were deleted since.
        """
        raw_values = self.client.get_multi_raw(self.get_dict_keys_keys())
        keys = []
        for shard in range(KEY_LIST_SHARDS):
            raw = raw_values.get(self.get_dict_keys_key(shard))
            if not raw:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode()
            shard_keys, lines = self.read_dict_keys_shard(raw)
            keys += shard_keys
            if lines - len(shard_keys) > KEY_LIST_SPARE_LINES:
                self.rewrite_dict_keys(shard)
        return keys

    def rewrite_dict_keys(self, shard, check=None):
        """ Write one item of the list again, with each key in it once.

        Reads it again to get the cas id memcached has for it, so the
        write only happens if nobody appended to it in between. If
        somebody did, this does nothing and the next caller tries again.

        The keys in check are the ones a reader found nothing under any
        more. They are asked for once more here, after the read, and only
        those still not there are left out. Both of those are what makes
        this safe: a key another process is writing right now is either
        already there when we ask -- then we keep it -- or its write
        appends to this item afterwards, and then our cas does not go
        through. Dropping a key that is in fact live would take a live
        entry out of the dict without deleting it, and nothing would ever
        hand it out or clear it again.
        """
        shard_key = self.get_dict_keys_key(shard)
        raw, cas_id = self.client.raw_gets(shard_key)
        if not raw or cas_id is None:
            return False
        keys, lines = self.read_dict_keys_shard(raw)
        if check:
            gone = self.get_gone_keys([x for x in keys if x in check])
            if gone:
                keys = [x for x in keys if x not in gone]
        if len(keys) == lines:
            return False
        if not keys:
            # Nothing left to remember, so the item itself can go. A
            # delete cannot say "only if unchanged", but a write of an
            # empty one can, and an empty item is appended to just like a
            # missing one.
            return self.client.raw_cas(shard_key, "", cas_id)
        new_raw = "".join([json.dumps(x) + "\n" for x in keys])
        return self.client.raw_cas(shard_key, new_raw, cas_id)

    def get_gone_keys(self, keys):
        """ Which of these keys there is nothing under any more. """
        gone = set()
        for block in get_blocks(keys, MULTI_BLOCK_SIZE):
            key_ids = {}
            for x_key in block:
                key_ids[self.get_key_id(x_key)] = x_key
            there = self.client.exists_multi(key_ids)
            for x_key_id, x_key in key_ids.items():
                if x_key_id in there:
                    continue
                gone.add(x_key)
        return gone

    def drop_dict_keys(self, keys):
        """ Forget the given keys, wherever in the list they sit. """
        shards = set()
        for x_key in keys:
            shards.add(self.get_key_shard(x_key))
        for shard in shards:
            self.rewrite_dict_keys(shard, check=keys)

    def add_dict_key(self, key):
        """ Remember a key, without reading the list first.

        One append, which memcached does by itself and does not have to
        be locked. It used to read the whole list, put the key in it and
        write it back: a roundtrip of the whole list per write, so it got
        slower the fuller the dict was, and of two processes doing it at
        the same time one lost its key. The price is that the same key
        can end up in there twice, which the readers sort out.
        """
        shard = self.get_key_shard(key)
        shard_key = self.get_dict_keys_key(shard)
        line = json.dumps(key) + "\n"
        if self.client.raw_append(shard_key, line):
            return
        # Nothing there to append to, so we are the first.
        if self.client.raw_add(shard_key, line):
            return
        # Either somebody else was first between those two calls, or the
        # item is as full as memcached takes. Rewriting it drops the
        # repeated lines and makes room; if that was not it either, the
        # append says so in the log.
        self.rewrite_dict_keys(shard)
        self.client.raw_append(shard_key, line)

    def add(self, key, value, expire=None):
        from otpme.lib import locking
        if expire is None:
            expire = 0
        if self.locking:
            _lock = locking.acquire_lock(lock_type=self.lock_type, lock_id=key)
        try:
            _key = self.get_key_id(key)
            # A key that is there is in the list of keys already, so
            # only a new one is appended to it. Appending every time made
            # the list grow by the same few keys with every write -- the
            # clear triggers of the function caches are written two dozen
            # times per object -- and memcached copies the whole item on
            # every append: a list of some MB made each of those writes
            # a copy of some MB.
            stored = self.client.replace(key=_key,
                                        value=value,
                                        time=expire,
                                        min_compress_len=512000,
                                        compress_level=1)
            if not stored:
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
        except Exception:
            raise KeyError(key) from None
        # Check for key expiry refresh.
        if self.refresh_keys:
            expire_key = self.get_key_expire_id(key)
            try:
                key_expire = self.client.get(expire_key)
            except Exception:
                key_expire = None
            if key_expire is not None:
                self.client.touch(_key, key_expire)
        return value

    def get_multi(self, keys):
        """ Get many keys in as few roundtrips as it takes.

        Returns what is there, missing keys are simply not in the
        result. Callers that need all of them have to check. No expiry
        refresh here: that would be a touch per key and undo the point
        of asking for them together.
        """
        result = {}
        for block in get_blocks(keys, MULTI_BLOCK_SIZE):
            key_map = {}
            for x_key in block:
                key_map[self.get_key_id(x_key)] = x_key
            try:
                values = self.client.get_multi(list(key_map))
            except Exception:
                continue
            for x_key, x_value in values.items():
                result[key_map[x_key]] = x_value
        return result

    def delete(self, key):
        """ Take a key out.

        The key stays in the list of keys we wrote; keys() and clear()
        both cope with a key that has nothing under it any more, and
        keys() takes it out of the list once enough of them have piled
        up. Doing it here would mean reading and writing a part of that
        list per delete.
        """
        try:
            deleted_item = self.get(key)
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
        lock_type="memcached", pickle=False, **kwargs):
        super().__init__(name)
        self.lock_type = lock_type
        self.client = MemcacheClient(pool, compression=compression, pickle=pickle)
        if clear:
            self.clear()

    @property
    def list(self):
        try:
            _list = self.client.get(self.name)
        except Exception:
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
