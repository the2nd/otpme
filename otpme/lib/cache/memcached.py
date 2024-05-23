# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import system_command
from otpme.lib.cache.memcache import MemcacheHandler

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
LOCK_TYPE = "memcached"

SOCKET_PERMS = "700"
MEMCACHED_MAXMEM = "128"
MEMCACHED_THREADS = "32"
MEMCACHED_MAX_OBJECT_SIZE = "8m"
MEMCACHED_SOCKET_NAME = "memcached.sock"
MEMCACHED_PIDFILE_NAME = "memcached.pid"
LOGFILE = os.path.join(config.log_dir, "memcached.log")

def register():
    """ Register module. """
    from otpme.lib import locking
    locking.register_lock_type(LOCK_TYPE, module=__file__)
    config.register_config_var("memcached_bin", str, "memcached",
                        config_file_parameter="MEMCACHED_BIN")
    config.register_config_var("memcached_max_object_size", str, MEMCACHED_MAX_OBJECT_SIZE,
                        config_file_parameter="MEMCACHED_MAX_OBJECT_SIZE")
    config.register_config_var("memcached_maxmem", str, MEMCACHED_MAXMEM,
                        config_file_parameter="MEMCACHED_MAXMEM")
    config.register_config_var("memcached_threads", str, MEMCACHED_THREADS,
                        config_file_parameter="MEMCACHED_THREADS")
    config.register_config_var("memcached_pidfile", str, None,
                        config_file_parameter="MEMCACHED_PIDFILE")
    config.register_config_var("memcached_socket", str, None,
                        config_file_parameter="MEMCACHED_SOCKET")
    config.register_config_var("memcached_opts", str, None,
                        config_file_parameter="MEMCACHED_OPTS")

def get_memcache_handler():
    pidfile = get_pidfile()
    memcached_socket = get_socket()
    memcache_handler = MemcacheHandler(name="Memcached",
                                    lock_type=LOCK_TYPE,
                                    start_function=_start,
                                    socket=memcached_socket,
                                    pidfile=pidfile)
    return memcache_handler

def start():
    memcache_handler = get_memcache_handler()
    return memcache_handler.start()

def wait_for_start():
    memcache_handler = get_memcache_handler()
    return memcache_handler.wait_for_start()

def stop():
    memcache_handler = get_memcache_handler()
    return memcache_handler.stop()

def status():
    memcache_handler = get_memcache_handler()
    return memcache_handler.status()

def wait_for_shutdown():
    memcache_handler = get_memcache_handler()
    return memcache_handler.wait_for_shutdown()

def get_pool(*args, **kwargs):
    memcache_handler = get_memcache_handler()
    return memcache_handler.get_pool(*args, **kwargs)

def get_dict(*args, **kwargs):
    memcache_handler = get_memcache_handler()
    return memcache_handler.get_dict(*args, **kwargs)

def get_list(*args, **kwargs):
    memcache_handler = get_memcache_handler()
    return memcache_handler.get_list(*args, **kwargs)

def flushall():
    # Get logger.
    logger = config.logger
    msg = "Flushing memcached cache..."
    logger.debug(msg)
    memcache_handler = get_memcache_handler()
    memcache_handler.flushall()

def cli():
    memcache_handler = get_memcache_handler()
    memcache_handler.cli()

def get_pidfile():
    _pidfile = config.memcached_pidfile
    if _pidfile is None:
        _pidfile = os.path.join(config.pidfile_dir, MEMCACHED_PIDFILE_NAME)
    return _pidfile

def get_socket():
    _socket = config.memcached_socket
    if _socket is None:
        _socket = os.path.join(config.sockets_dir, MEMCACHED_SOCKET_NAME)
    return _socket

def command(command):
    """ Handle memcached command. """
    if command == "start":
        if status():
            msg = "Memcached already running."
            raise AlreadyRunning(msg)
        start()
        return wait_for_start()
    elif command == "wait":
        return wait_for_start()
    elif command == "stop":
        if stuff.controld_status():
            msg = "Please stop OTPme daemon first."
            raise OTPmeException(msg)
        return stop()
    elif command == "status":
        msg = "Memcached not running."
        if not status():
            raise NotRunning()
    elif command == "restart":
        if stuff.controld_status():
            msg = "Please stop OTPme daemon first."
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
            msg = "Memcached not running."
            raise NotRunning(msg)
        cli()
    else:
        msg = "Unknown memcached command: %s" % command
        raise OTPmeException(msg)

def _start():
    if status():
        msg = "Memcached already running."
        raise AlreadyRunning(msg)
    # Get logger.
    logger = config.logger
    memcached_socket = get_socket()
    if os.path.exists(memcached_socket):
        msg = "Removing stale socket: %s" % memcached_socket
        logger.info(msg)
        os.remove(memcached_socket)
    if config.memcached_opts:
        memcached_opts = config.memcached_opts.split()
    else:
        pidfile = get_pidfile()
        memcached_opts = [
                        '-d',
                        '-P', pidfile,
                        '-I', config.memcached_max_object_size,
                        '-m', config.memcached_maxmem,
                        '-t', config.memcached_threads,
                        '-U', 'off',
                        '-s', memcached_socket,
                        '-a', SOCKET_PERMS,
                        '-o', 'lru_maintainer,lru_crawler,hash_algorithm=murmur3',
                        '-v',
                        ]
    start_cmd = [config.memcached_bin]
    start_cmd += memcached_opts
    logfile_fd = open(LOGFILE, "w")
    return_code = system_command.run(command=start_cmd,
                                    user=config.user,
                                    group=config.group,
                                    stdout=logfile_fd,
                                    stderr=logfile_fd,
                                    call=True)
    if return_code == 0:
        return True
    return False
