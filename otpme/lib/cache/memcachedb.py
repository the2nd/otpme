# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import socket

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib.cache.memcache import MemcacheHandler

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
LOCK_TYPE = "memcachedb"

SOCKET_PERMS = "700"
MEMCACHEDB_MAXMEM = "128"
MEMCACHEDB_THREADS = "32"
MEMCACHEDB_SOCKET_NAME = "memcachedb.sock"
MEMCACHEDB_PIDFILE_NAME = "memcached.pid"
CACHE_DIR = os.path.join(config.cache_dir, "memcachedb")
LOGFILE = os.path.join(config.log_dir, "memcachedb.log")

def register():
    """ Register module. """
    from otpme.lib import locking
    locking.register_lock_type(LOCK_TYPE, module=__file__)
    config.register_config_var("memcachedb_bin", str, "memcachedb",
                        config_file_parameter="MEMCACHEDB_BIN")
    config.register_config_var("memcachedb_maxmem", str, MEMCACHEDB_MAXMEM,
                        config_file_parameter="MEMCACHEDB_MAXMEM")
    config.register_config_var("memcachedb_threads", str, MEMCACHEDB_THREADS,
                        config_file_parameter="MEMCACHEDB_THREADS")
    config.register_config_var("memcachedb_pidfile", str, None,
                        config_file_parameter="MEMCACHEDB_PIDFILE")
    config.register_config_var("memcachedb_socket", str, None,
                        config_file_parameter="MEMCACHEDB_SOCKET")
    config.register_config_var("memcachedb_cache_dir", str, CACHE_DIR,
                        config_file_parameter="MEMCACHEDB_CACHE_DIR")
    config.register_config_var("memcachedb_opts", str, None,
                        config_file_parameter="MEMCACHEDB_OPTS")

def get_memcache_handler():
    pidfile = get_pidfile()
    memcachedb_socket = get_socket()
    memcache_handler = MemcacheHandler(name="Memcachedb",
                                    lock_type=LOCK_TYPE,
                                    start_function=_start,
                                    socket=memcachedb_socket,
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
    msg = "Flushing memcachedb cache..."
    logger.debug(msg)
    memcache_handler = get_memcache_handler()
    memcache_handler.flushall()

def cli():
    memcache_handler = get_memcache_handler()
    memcache_handler.cli()

def get_pidfile():
    _pidfile = config.memcachedb_pidfile
    if _pidfile is None:
        _pidfile = os.path.join(config.pidfile_dir, MEMCACHEDB_PIDFILE_NAME)
    return _pidfile

def get_socket():
    _socket = config.memcachedb_socket
    if _socket is None:
        _socket = os.path.join(config.sockets_dir, MEMCACHEDB_SOCKET_NAME)
    return _socket

def command(command):
    """ Handle memcachedb command. """
    if command == "start":
        if status():
            raise AlreadyRunning()
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
        msg = "Memcachedb not running."
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
            msg = "Memcachedb not running."
            raise NotRunning(msg)
        cli()
    else:
        msg = "Unknown memcachedb command: %s" % command
        raise OTPmeException(msg)

def _start():
    if status():
        msg = "Memcachedb already running."
        raise AlreadyRunning(msg)
    logger = config.logger
    memcachedb_socket = get_socket()
    if os.path.exists(memcachedb_socket):
        msg = "Removing stale socket: %s" % memcachedb_socket
        logger.info(msg)
        os.remove(memcachedb_socket)
    if config.memcachedb_opts:
        memcachedb_opts = config.memcachedb_opts.split()
    else:
        memcachedb_opts = [
                        '-d',
                        '-m', config.memcachedb_maxmem,
                        '-t', config.memcachedb_threads,
                        '-A', '4096',
                        '-H', config.memcachedb_cache_dir,
                        #'-N',
                        '-U', 'off',
                        '-s', memcachedb_socket,
                        '-a', SOCKET_PERMS,
                        '-v',
                        ]
    start_cmd = [config.memcachedb_bin]
    start_cmd += memcachedb_opts
    logfile_fd = open(LOGFILE, "w")
    return_code = system_command.run(command=start_cmd,
                                    user=config.user,
                                    group=config.group,
                                    stdout=logfile_fd,
                                    stderr=logfile_fd,
                                    call=True)
    if return_code == 0:
        set_memcachedb_pid()
        return True
    return False

def set_memcachedb_pid(timeout=3):
    pid = None
    counter = 0
    wait_timeout = timeout * 10
    memcachedb_socket = get_socket()
    while not os.path.exists(memcachedb_socket):
        counter += 1
        if counter >= wait_timeout:
            msg = "Timeout waiting for socket: %s" % memcachedb_socket
            raise OTPmeException(msg)
        time.sleep(0.1)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(memcachedb_socket)
    sock.send("stats\n")
    reply = sock.recv(1024)
    for line in reply.split("\n"):
        if not line.startswith("STAT pid"):
            continue
        pid = line.split()[2]
        break
    if pid is None:
        msg = "Unable to get PID from: %s" % memcachedb_socket
        raise OTPmeException(msg)
    pidfile = get_pidfile()
    filetools.create_file(pidfile, pid)
    return pid
