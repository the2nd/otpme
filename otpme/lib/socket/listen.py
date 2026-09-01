# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pwd
import ssl
import mmap
import threading
import time
import struct
import socket
import psutil
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import re
from otpme.lib import log
from otpme.lib import net
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import multiprocessing

from otpme.lib.exceptions import *

# Worker scoreboard: two bytes per worker slot in a shared mmap. The
# first byte is written only by the worker itself, the second only by
# the parent. One writer per byte means the whole thing needs no lock
# and no shared dict (which would be a redis/memcached round trip per
# connection, see multiprocessing.get_dict()).
SCOREBOARD_SLOT_SIZE = 2
WORKER_IDLE = 0
WORKER_BUSY = 1
WORKER_RUN = 0
WORKER_EXIT = 1
# One slot past the workers carries the state of the pool as a whole.
# Only the supervisor writes it, every worker reads it, so it keeps the
# one-writer-per-byte rule the rest of the scoreboard lives by.
POOL_SLOT_OFFSET = 0
POOL_HEALTHY = 0
POOL_SATURATED = 1
# How long the pool has to stay unsaturated before we start giving back
# workers we forked on demand. Long enough that the morning login storm
# does not fork and reap in circles.
WORKER_SHRINK_DELAY = 60
# Seconds between two supervisor rounds.
WORKER_SUPERVISE_INTERVAL = 0.5
# How long a worker that is serving connections in threads, and may not
# take another one, waits before it looks again. It is out of the accept
# path while it waits, so this is also how long it takes to notice that
# the pool became saturated and it may help out after all.
WORKER_THREAD_POLL_INTERVAL = 0.1
# How long a stopping worker waits for the connections it handed to
# threads. Past this it leaves and they are cut off.
#
# Has to stay below the join(timeout=5) our parent gives each of us on
# shutdown (see _listen()): waiting longer than that does not buy the
# connections any time, it only gets us dropped and left behind as an
# orphan.
WORKER_DRAIN_TIMEOUT = 3
# How long a round of the accept loop takes. accept() returning is the
# only point at which that loop looks at self.shutdown, and a pool
# worker at its stop request, so this is how quickly either is noticed.
ACCEPT_TIMEOUT = 1
# How long a client may take over the TLS handshake. It runs in the
# worker that accepted the connection, so a client stalling it holds
# that worker for this long.
HANDSHAKE_TIMEOUT = 1

class ListenSocket(object):
    """ Class to start and stop TCP or unix socket. """
    def __init__(self, socket_uri, connection_handler, name,
        timeout=None, banner=None, socket_handler=None, user=None,
        group=None, mode=0o600, use_ssl=False, ssl_version=ssl.PROTOCOL_TLSv1_2,
        ssl_cert=None, ssl_key=None, ssl_ca_data=None, ssl_verify_client=False,
        proctitle=None, logger=None, max_conn=100, conn_handling="multiprocessing",
        worker_count=0, max_worker_count=0, worker_threads=0):
        # Check if we got all required paramters.
        if use_ssl:
            if not ssl_cert:
                raise Exception("Missing ssl_cert.")
            if not ssl_key:
                raise Exception("Missing ssl_key.")
            if ssl_verify_client:
                if not ssl_ca_data:
                    raise Exception("Missing ssl_ca_data.")

        # Our name.
        self.name = name
        # Get logger.
        if logger:
            self.logger = logger
            self.got_logger = True
        else:
            self.got_logger = False
            self.logger = config.logger
        # Timeout for the connections we accept, handed to Connection
        # below. None means they may wait as long as they have to, which
        # is what every daemon runs with: how long a connection may sit
        # idle is decided per daemon (daemon_idle_timeout), on the
        # single recv() that waits for the next request, not here.
        # This is not the accept loop's timeout, see ACCEPT_TIMEOUT.
        self.timeout = timeout
        # Our socket URI string. e.g. tcp://127.0.0.1:8080
        self.socket_uri = socket_uri
        # Our connections.
        self.connections = {}
        # Banner to be printed on client connection.
        self.banner = banner
        # Connection handler used to handle communication with clients.
        self.connection_handler = connection_handler
        # Socket we will listen on.
        self._socket = None
        # Socket handler.
        self.socket_handler = socket_handler
        # User and group our unix sockets will be owned by.
        self.user = user
        if not group:
            group = True
        self.group = group
        self.mode = mode
        # Indicates if we will use SSL.
        self.use_ssl = use_ssl
        # Server cert/key.
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        # Contains CA certs, CRLs etc.
        self.ssl_ca_data = ssl_ca_data
        # Indicates if we should verify client certificates.
        self.ssl_verify_client = ssl_verify_client
        # Max simultaneous client connections allowed.
        self.max_conn = max_conn

        self.key_file = None
        self.cert_file = None
        self.ca_data_file = None
        self.listen_process = None
        self._shutdown = None
        self.conn_handling = conn_handling
        self.worker_count = worker_count
        # Upper bound the pool may grow to while every worker is busy.
        # Anything at or below worker_count keeps the pool fixed.
        self.max_worker_count = max_worker_count or 0
        if self.max_worker_count < self.worker_count:
            self.max_worker_count = self.worker_count
        self.worker_procs = []
        self.scoreboard = None
        # Last time we saw every worker busy at once.
        self.last_saturated = 0
        self.last_max_workers_warn = 0
        # How many connections one worker may serve at the same time,
        # each in a thread of its own. 0 keeps a worker on the one
        # connection it accepted, which is what it always did.
        #
        # A second connection in the same worker means two of them
        # share one GIL, so this is the last resort and not the second:
        # a worker only reaches for it once the pool cannot grow any
        # further and every worker in it is busy. Up to that point
        # another process is the better answer, because it comes with a
        # core of its own. What makes it worth having at all is that a
        # login spends most of its time waiting for the user, and a
        # thread parked in a read holds no GIL.
        self.worker_threads = worker_threads or 0
        # Threads currently serving a connection, and the lock that
        # counts them. Both are per worker process, they never cross a
        # fork.
        self.worker_thread_count = 0
        self.worker_thread_lock = threading.Lock()

        # Save proctitle for later use (e.g. new client connection)
        if proctitle is None:
            self.proctitle = setproctitle.getproctitle()
        else:
            self.proctitle = proctitle

        # Handle unix sockets.
        if self.socket_uri.startswith("socket://"):
            # Get protocol.
            self.protocol = re.sub('^([^:]*):.*$', r'\1', self.socket_uri)
            # Get unix socket path.
            self.socket = re.sub('^socket://(.*)', r'\1', self.socket_uri)

            # Create unix socket.
            try:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                # NOTE: Prevent "socket.error: [Errno 98] Address already in use":
                #       http://stackoverflow.com/questions/4465959/python-errno-98-address-already-in-use
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except socket.error as e:
                log_msg = _("Failed to create socket. Error code: {code}, Error message: {message}", log=True)[1]
                log_msg = log_msg.format(code=e[0], message=e[1])
                self.logger.error(log_msg)
                return False
            # Remove old socket file.
            if os.path.exists(self.socket):
                try:
                    os.remove(self.socket)
                except OSError:
                    raise

        # Handle TCP sockets.
        elif self.socket_uri.startswith("tcp://"):
            self.protocol, self.address, self.port = net.parse_socket_uri(self.socket_uri)
            # Set socket tuple.
            self.socket = (self.address, self.port)

            # Create socket. Pick AF_INET6 for IPv6 literals (incl. '::').
            family = net.get_socket_family(self.address)
            try:
                self._socket = socket.socket(family, socket.SOCK_STREAM)
                # NOTE: Prevent "socket.error: [Errno 98] Address already in use":
                #       http://stackoverflow.com/questions/4465959/python-errno-98-address-already-in-use
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Dual-stack on '::' so we accept both v6 and v4-mapped clients.
                if family == socket.AF_INET6:
                    try:
                        self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except (OSError, AttributeError):
                        pass
            except socket.error as e:
                log_msg = _("Failed to create socket. Error code: {code}, Error message: {message}", log=True)[1]
                log_msg = log_msg.format(code=e[0], message=e[1])
                self.logger.error(log_msg)
                return False
            # Set send/recv buffer.
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, config.socket_send_buffer)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, config.socket_receive_buffer)
            # Disable Nagle's algorithm for lower latency.
            if self.protocol == "tcp":
                self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Set connection timeout. The listening socket always gets one,
        # even where connections are meant to have none: accept()
        # returning is the only point at which the accept loop gets to
        # look at self.shutdown, and a pool worker at its stop request.
        # So this also decides how quickly either is noticed.
        self._socket.settimeout(ACCEPT_TIMEOUT)

        # Bind socket (in case of unix socket create socket file).
        try:
            self._socket.bind(self.socket)
        except Exception as e:
            msg = _("Failed to bind to socket: {socket}: {error}")
            msg = msg.format(socket=self.socket, error=e)
            raise OTPmeException(msg) from e

        # Check if we have to change unix socket filesystem permissions.
        if self.protocol == "socket":
            if self.mode:
                # Set permissions.
                filetools.set_fs_permissions(path=self.socket,
                                            mode=self.mode,
                                            recursive=False)
            if self.user or self.group:
                # Set ownership.
                filetools.set_fs_ownership(path=self.socket,
                                            user=self.user,
                                            group=self.group,
                                            recursive=False)
    @property
    def shutdown(self):
        if not self._shutdown:
            return
        return self._shutdown.value

    @shutdown.setter
    def shutdown(self, new_status):
        if not self._shutdown:
            return
        self._shutdown.value = new_status

    def add_connection_proc(self, client, proc):
        """ Send client to client handler. """
        # Add connection proc.
        self.connections[client] = proc
        # Cleanup old connection PIDs.
        try:
            connections = self.connections.copy()
        except Exception:
            return
        for c in dict(connections):
            try:
                pid = self.connections[c].pid
            except Exception:
                continue
            if stuff.check_pid(pid):
                continue
            try:
                self.connections.pop(c)
            except Exception:
                pass

    def close_conn_procs(self):
        """ Make sure connection procs are closed. """
        while True:
            time.sleep(0.1)
            procs_alive = False
            for client in dict(self.connections):
                try:
                    proc = self.connections[client]
                except KeyError:
                    continue
                if proc.is_alive():
                    procs_alive = True
                    continue
                proc.join()
                # Prevent exception on daemon shutdown.
                if not self.shutdown:
                    if self.conn_handling == "multiprocessing":
                        proc.close()
                    else:
                        proc.join()
                try:
                    self.connections.pop(client)
                except KeyError:
                    pass
            if procs_alive:
                continue
            if self.shutdown:
                break

    def listen(self, **kwargs):
        """
        Wrapper function to start socket listening as process and return after
        initialization.
        """
        # Shared bool to handle shutdown.
        try:
            self._shutdown = multiprocessing.get_bool(self.name)
        except Exception as e:
            log_msg = _("Failed to get shared bool: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # Create queue to get init done info from self._listen()
        init_done = multiprocessing.MessageQueue("listensocket-initq")
        # Start listenting in new process.
        self.listen_process = multiprocessing.start_process(name=self.name,
                                                    target=self._listen,
                                                    target_args=(init_done,),
                                                    target_kwargs=kwargs)
        # Wait for _listen() to initialize (e.g. setup ssl certs etc.)
        init_status = None
        try:
            init_status = init_done.recv()
        except Exception as e:
            log_msg = _("Exception waiting for listen process init: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        finally:
            init_done.unlink()
        # A listen process that did not come up is not something to carry
        # on from. Our caller logs it (see OTPmeDaemon.listen()), which
        # is the only place the reason still reaches anyone.
        if init_status is not None and init_status != "init_successful":
            msg = _("Listen process failed to initialize: {status}")
            msg = msg.format(status=init_status)
            raise OTPmeException(msg)

    def _listen(self, init_done, **kwargs):
        """
        Listen on a socket, unix or TCP, and start per connection child process.
        """
        # Set our name if none was given.
        if self.name is None:
            self.name = stuff.get_pid_name(os.getpid())

        # Set process title.
        if self.use_ssl:
            new_proctitle = f"{self.proctitle} ListenSSL: {self.socket_uri}"
        else:
            new_proctitle = f"{self.proctitle} Listen: {self.socket_uri}"

        setproctitle.setproctitle(new_proctitle)

        # Handle multiprocessing stuff.
        multiprocessing.atfork(quiet=True)
        # Setup logger.
        if not self.got_logger:
            try:
                self.logger = log.setup_logger(pid=os.getpid())
            except Exception as e:
                # Our logfile is what just failed, so there is nothing to
                # log this with. Saying nothing is the worst option: our
                # parent waits on init_done and would wait forever, and
                # the daemon start hangs with it. So answer, and put the
                # reason where a foreground start still shows it.
                #
                # This is where a logfile the daemon cannot write ends
                # up: log.ensure_logfile() refuses it, and we run after
                # the privileges were dropped, so a path root can reach
                # and our user cannot fails right here.
                msg = _("Failed to setup logger: {error}")
                msg = msg.format(error=e)
                print(msg, file=sys.stderr)
                init_done.send(f"init_failed: {e}")
                return False

        # Start socket initialization.
        try:
            # Setup SSL wrapper for socket.
            if self.use_ssl:
                from otpme.lib.pki.cert import SSLCert
                # Encrypt cert private key with password.
                passphrase = stuff.gen_secret(len=32)
                passphrase = passphrase.encode("ascii")
                _cert = SSLCert(key=self.ssl_key)
                ssl_key = _cert.encrypt_key(passphrase=passphrase)
                # Temp file paths.
                self.cert_file = os.path.join(config.tmp_dir, f"{stuff.gen_secret(32)}-cert.pem")
                self.key_file = os.path.join(config.tmp_dir, f"{stuff.gen_secret(32)}-key.pem")
                self.ca_data_file = os.path.join(config.tmp_dir, f"{stuff.gen_secret(32)}-ca_data.pem")

                # Build dict with all temp files to create.
                tmp_files = {}
                tmp_files[self.cert_file] = self.ssl_cert
                tmp_files[self.key_file] = ssl_key
                tmp_files[self.ca_data_file] = self.ssl_ca_data

                # Create all needed temp files.
                for tmp_file in tmp_files:
                    file_content = tmp_files[tmp_file]
                    # try to create file
                    if os.path.exists(tmp_file):
                        log_msg = _("Cert file '{file}' exists, removing.", log=True)[1]
                        log_msg = log_msg.format(file=tmp_file)
                        self.logger.warning(log_msg)
                    # Create file.
                    fd = open(tmp_file, "w")
                    # Set permissions.
                    filetools.set_fs_permissions(path=tmp_file,
                                                mode=0o600,
                                                recursive=False)
                    # Set ownership.
                    filetools.set_fs_ownership(path=tmp_file,
                                                user=self.user,
                                                group=self.group,
                                                recursive=False)
                    # Write file content.
                    file_content = str(file_content)
                    fd.write(file_content)
                    fd.close()

                # Check if we need to verify client certficates.
                if self.ssl_verify_client:
                    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    # FIXME: Is this all we need to enable PFS with python 2.7??
                    # Enable PFS.
                    # http://jderose.blogspot.de/2014/01/how-to-enable-perfect-forward-secrecy.html
                    #ctx.set_ecdh_curve('prime256v1')
                    ctx.set_ecdh_curve('secp384r1')
                    ctx.load_cert_chain(certfile=self.cert_file,
                                        keyfile=self.key_file,
                                        password=passphrase)
                    ctx.load_verify_locations(cafile=self.ca_data_file,
                                            capath=None, cadata=None)
                    ctx.verify_mode = ssl.CERT_REQUIRED
                    ctx.verify_flags = ssl.VERIFY_CRL_CHECK_CHAIN
                    self._socket = ctx.wrap_socket(self._socket,
                                            server_side=True,
                                            do_handshake_on_connect=False,
                                            suppress_ragged_eofs=True,
                                            server_hostname=None)
                else:
                    #ctx = ssl.create_default_context()
                    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    # FIXME: Is this all we need to enable PFS with python 2.7??
                    # Enable PFS.
                    # http://jderose.blogspot.de/2014/01/how-to-enable-perfect-forward-secrecy.html
                    #ctx.set_ecdh_curve('prime256v1')
                    ctx.set_ecdh_curve('secp384r1')
                    ctx.check_hostname = False
                    ctx.load_cert_chain(certfile=self.cert_file,
                                        keyfile=self.key_file,
                                        password=passphrase)
                    ctx.load_verify_locations(cafile=self.ca_data_file,
                                            capath=None, cadata=None)
                    # We need cert optional because on host/node leave we need the host.
                    ctx.verify_mode = ssl.CERT_OPTIONAL
                    # Override default verify_flags (which include
                    # VERIFY_X509_STRICT since Python 3.10) — STRICT trips
                    # over real-world CA quirks and triggers a
                    # certificate_unknown alert before we can inspect the
                    # client cert. Match the REQUIRED branch.
                    ctx.verify_flags = ssl.VERIFY_CRL_CHECK_CHAIN
                    self._socket = ctx.wrap_socket(self._socket,
                                            server_side=True,
                                            do_handshake_on_connect=False,
                                            suppress_ragged_eofs=True,
                                            server_hostname=None)
            # Start listening on socket. The backlog is the queue of
            # connections the kernel finished on its own and nobody has
            # accepted yet. It is what carries a login storm while all
            # workers are busy: a client whose connection sits in there
            # notices nothing but the wait. Overflowing it costs more on
            # a unix socket than on TCP -- TCP drops the SYN and the
            # client tries again (see tcp_abort_on_overflow), a unix
            # socket refuses the connect right away, and that is the
            # path ldapd, freeradius and the web portal take to authd.
            self._socket.listen(config.socket_backlog)

            # Using SSLContext.wrap_socket() with newer python versions it's
            # possible to remove cert/key files after socket initialization.
            if self.use_ssl:
                self.remove_cert_files()

            if self.use_ssl:
                if self.ssl_verify_client:
                    log_msg = _("Started listening on '{uri}'. SSL client certificate verification enabled.", log=True)[1]
                    log_msg = log_msg.format(uri=self.socket_uri)
                    self.logger.info(log_msg)
                else:
                    log_msg = _("Started listening on '{uri}'. SSL enabled.", log=True)[1]
                    log_msg = log_msg.format(uri=self.socket_uri)
                    self.logger.info(log_msg)
            else:
                log_msg = _("Started listening on '{uri}'. SSL disabled.", log=True)[1]
                log_msg = log_msg.format(uri=self.socket_uri)
                self.logger.info(log_msg)

            # Notify self.listen() that we finished initialization.
            init_done.send("init_successful")
        except socket.error as e:
            log_msg = _("Bind failed. Error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.error(log_msg)
            init_done.send("init_failed")
            return False

        if self.worker_count > 0:
            # Pre-fork worker pool mode. The scoreboard has to exist
            # before the first fork: the workers inherit the mapping,
            # which is what makes it shared without any IPC.
            # One slot per worker, plus one for the pool itself.
            self.scoreboard = mmap.mmap(-1, (self.max_worker_count + 1)
                                        * SCOREBOARD_SLOT_SIZE)
            if self.max_worker_count > self.worker_count:
                log_msg = _("Starting {count} pre-fork workers (up to {max} under load) for '{uri}'", log=True)[1]
                log_msg = log_msg.format(count=self.worker_count,
                                        max=self.max_worker_count,
                                        uri=self.socket_uri)
            else:
                log_msg = _("Starting {count} pre-fork workers for '{uri}'", log=True)[1]
                log_msg = log_msg.format(count=self.worker_count,
                                        uri=self.socket_uri)
            self.logger.info(log_msg)
            # One slot per worker we may ever have. The ones above
            # worker_count stay empty until the load asks for them.
            self.worker_procs = [None] * self.max_worker_count
            for i in range(self.worker_count):
                self.worker_procs[i] = self.start_worker(i)
            # Wait for shutdown signal.
            while not self.shutdown:
                self.supervise_workers()
                time.sleep(WORKER_SUPERVISE_INTERVAL)
            # Shutdown: wait for workers.
            for p in self.worker_procs:
                if p is None:
                    continue
                p.join(timeout=5)
        else:
            # Legacy fork-per-connection mode.
            # Start thread to handle connection procs. Marked as daemon so
            # threading._shutdown() does not block on its infinite poll
            # loop when worker threads (daemon, may be blocked in long
            # polls) outlive the accept loop.
            multiprocessing.start_thread(name=self.name,
                                target=self.close_conn_procs,
                                daemon=True)
            self._accept_loop()

        log_msg = _("Stopped listening on '{uri}'", log=True)[1]
        log_msg = log_msg.format(uri=self.socket_uri)
        self.logger.info(log_msg)
        # Do multiprocessing cleanup.
        multiprocessing.cleanup()

    def set_worker_state(self, worker_idx, state):
        """ Tell the parent what we are doing. Called by the worker. """
        if self.scoreboard is None:
            return
        self.scoreboard[worker_idx * SCOREBOARD_SLOT_SIZE] = state

    def get_worker_state(self, worker_idx):
        """ What a worker is doing. Called by the parent. """
        if self.scoreboard is None:
            return WORKER_IDLE
        return self.scoreboard[worker_idx * SCOREBOARD_SLOT_SIZE]

    def set_worker_command(self, worker_idx, command):
        """ Ask a worker to stop. Called by the parent. """
        if self.scoreboard is None:
            return
        self.scoreboard[worker_idx * SCOREBOARD_SLOT_SIZE + 1] = command

    def get_worker_command(self, worker_idx):
        """ Check whether we were asked to stop. Called by the worker. """
        if self.scoreboard is None:
            return WORKER_RUN
        return self.scoreboard[worker_idx * SCOREBOARD_SLOT_SIZE + 1]

    def set_pool_state(self, state):
        """ Tell the workers how the pool is doing. Called by the parent. """
        if self.scoreboard is None:
            return
        pool_slot = self.max_worker_count * SCOREBOARD_SLOT_SIZE
        self.scoreboard[pool_slot + POOL_SLOT_OFFSET] = state

    def get_pool_state(self):
        """ How the pool is doing. Called by the worker. """
        if self.scoreboard is None:
            return POOL_HEALTHY
        pool_slot = self.max_worker_count * SCOREBOARD_SLOT_SIZE
        return self.scoreboard[pool_slot + POOL_SLOT_OFFSET]

    def start_worker(self, worker_idx):
        """ Fork one worker for the given scoreboard slot. """
        self.set_worker_state(worker_idx, WORKER_IDLE)
        self.set_worker_command(worker_idx, WORKER_RUN)
        worker_name = f"{self.name}-worker-{worker_idx}"
        return multiprocessing.start_process(name=worker_name,
                                        target=self._worker_loop,
                                        target_args=(worker_idx,),
                                        join=False)

    def supervise_workers(self):
        """ Respawn dead workers and size the pool to the load.

        The scoreboard tells us how many workers are in a connection
        right now. While all of them are, an accepted connection waits
        in the listen backlog with nobody to pick it up -- that is the
        morning login storm, where every worker sits in an auth flow
        waiting for a user to type. So we fork more, up to
        max_worker_count, and give them back once the rush is over.
        """
        # Respawn workers that died on us. A slot we retired ourselves
        # is set to None and must stay empty.
        for worker_idx, proc in enumerate(self.worker_procs):
            if proc is None:
                continue
            if proc.is_alive():
                continue
            proc.join()
            if self.shutdown:
                return
            if self.get_worker_command(worker_idx) == WORKER_EXIT:
                # Went away because we asked it to.
                self.worker_procs[worker_idx] = None
                continue
            log_msg = _("Worker {idx} died, respawning.", log=True)[1]
            log_msg = log_msg.format(idx=worker_idx)
            self.logger.warning(log_msg)
            self.worker_procs[worker_idx] = self.start_worker(worker_idx)

        idle_slots = []
        leaving_slots = []
        running = 0
        busy = 0
        for worker_idx, proc in enumerate(self.worker_procs):
            if proc is None:
                continue
            if self.get_worker_command(worker_idx) == WORKER_EXIT:
                # On its way out. It does not count as one of ours any
                # more, in either number: counting it as running would
                # hide the very saturation that has to bring it back,
                # and we must not ask it to stop twice.
                leaving_slots.append(worker_idx)
                continue
            running += 1
            if self.get_worker_state(worker_idx) == WORKER_BUSY:
                busy += 1
            elif worker_idx >= self.worker_count:
                # Only the ones we forked on demand may be given back.
                idle_slots.append(worker_idx)

        # Publish what a worker cannot see for itself: whether the pool
        # is out of room. Only here do we know both numbers, and being
        # the only writer of that byte is what keeps the scoreboard
        # free of locks. A worker reads it to decide whether serving a
        # second connection in a thread is warranted -- see
        # may_serve_in_thread().
        if running >= self.max_worker_count and busy >= running:
            self.set_pool_state(POOL_SATURATED)
        else:
            self.set_pool_state(POOL_HEALTHY)

        if self.max_worker_count <= self.worker_count:
            # Fixed pool. Nothing to grow or hand back, but the workers
            # still want to know whether it is saturated.
            return

        now = time.time()
        if not running or busy < running:
            # Somebody is free to accept, nothing to do but consider
            # handing workers back further down.
            pass
        else:
            self.last_saturated = now
            if leaving_slots:
                # Load came back while we were handing workers back.
                # Keep them: they are still alive and still accepting,
                # so taking the request back costs nothing, while
                # forking replacements would cost a fork and a cold
                # cache each. One that is gone already has its slot
                # free and gets forked again below. Give them this
                # round before growing any further.
                for worker_idx in leaving_slots:
                    self.set_worker_command(worker_idx, WORKER_RUN)
                log_msg = _("All {running} workers busy, keeping {count} we were about to stop: {uri}", log=True)[1]
                log_msg = log_msg.format(running=running,
                                        count=len(leaving_slots),
                                        uri=self.socket_uri)
                self.logger.info(log_msg)
                return
            free_slots = [i for i, p in enumerate(self.worker_procs) if p is None]
            if free_slots:
                # Grow by half of what we have, so a storm is met in a
                # few rounds instead of one worker every half second.
                grow_by = min(max(1, running // 2), len(free_slots))
                for worker_idx in free_slots[:grow_by]:
                    self.worker_procs[worker_idx] = self.start_worker(worker_idx)
                log_msg = _("All {running} workers busy, pool grown to {total} (max {max}): {uri}", log=True)[1]
                log_msg = log_msg.format(running=running,
                                        total=running + grow_by,
                                        max=self.max_worker_count,
                                        uri=self.socket_uri)
                self.logger.info(log_msg)
            elif (now - self.last_max_workers_warn) > 60:
                self.last_max_workers_warn = now
                log_msg = _("All {count} workers busy and pool at its maximum. New connections wait in the listen backlog: {uri}", log=True)[1]
                log_msg = log_msg.format(count=running, uri=self.socket_uri)
                self.logger.warning(log_msg)
            return

        # Hand back workers we forked on demand, one per round, once the
        # load has stayed down long enough.
        if not idle_slots:
            return
        if (now - self.last_saturated) < WORKER_SHRINK_DELAY:
            return
        worker_idx = idle_slots[-1]
        self.set_worker_command(worker_idx, WORKER_EXIT)
        log_msg = _("Pool not saturated for {delay}s, stopping worker {idx}: {uri}", log=True)[1]
        log_msg = log_msg.format(delay=WORKER_SHRINK_DELAY,
                                idx=worker_idx,
                                uri=self.socket_uri)
        self.logger.info(log_msg)

    def _accept_connection(self, worker_idx=None):
        """ Accept a single connection. Returns (new_connection, client) or (None, None). """
        # accept() returns after ACCEPT_TIMEOUT with a socket.timeout,
        # see the settimeout() on the listening socket. That is the
        # point where the loop above comes up for air to check for
        # shutdown and, in a worker, for its stop request.
        new_client_socket = None
        try:
            new_connection, new_client_socket = self._socket.accept()
            # We are out of the accept queue and busy from here on. The
            # TLS handshake below is part of that: a client that stalls
            # it holds this worker just as much as one in an auth flow.
            if worker_idx is not None:
                self.set_worker_state(worker_idx, WORKER_BUSY)
            # Disable Nagle's algorithm on accepted connection.
            if self.protocol == "tcp":
                new_connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Perform SSL handshake manually to catch errors with client info.
            # Without an explicit timeout the handshake blocks forever on a
            # client that connects but never speaks TLS, which prevents the
            # accept loop from observing self.shutdown.
            if self.use_ssl:
                handshake_timeout = HANDSHAKE_TIMEOUT
                try:
                    new_connection.settimeout(handshake_timeout)
                    new_connection.do_handshake()
                    new_connection.settimeout(None)
                except Exception as ssl_error:
                    # We have client info now, so log it with the error
                    if self.protocol == "tcp":
                        # accept() returns 2-tuple for v4 and 4-tuple for v6 --
                        # only the first two elements are (host, port).
                        client_address, client_port = new_client_socket[:2]
                        peer_cert = new_connection.getpeercert(binary_form=True)
                        peer_cn = None
                        if peer_cert:
                            peer_cert = stuff.parse_peer_cert(peer_cert)
                            peer_cn = peer_cert['cn']
                        log_msg = _("Listen: SSL handshake failed from {client}:{port}: CN: {cn}: {error}", log=True)[1]
                        log_msg = log_msg.format(client=client_address,
                                                port=client_port,
                                                cn=peer_cn,
                                                error=ssl_error)
                    else:
                        log_msg = _("Listen: SSL handshake failed: {error}", log=True)[1]
                        log_msg = log_msg.format(error=ssl_error)
                    self.logger.warning(log_msg)
                    try:
                        new_connection.close()
                    except Exception:
                        pass
                    return None, None
        except socket.timeout:
            return None, None
        except Exception as e:
            # Suppress shutdown-induced errors (accept() on closed socket
            # raises EINVAL/EBADF — that's expected, not a real error).
            if self.shutdown:
                return None, None
            if self.use_ssl:
                log_msg = _("Listen: SSL error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
            else:
                log_msg = _("Listen: Connection error: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return None, None

        # Build client identifier string.
        if self.protocol == "socket":
            SO_PEERCRED = 17
            creds = new_connection.getsockopt(socket.SOL_SOCKET,
                                                SO_PEERCRED,
                                                struct.calcsize('3i'))
            client_pid, client_uid, client_gid = struct.unpack('3i',creds)
            # Identity comes from the kernel-reported peer uid, not from a
            # /proc lookup keyed on pid -- the pid path is racy under
            # short-lived-child + pid-reuse, and downstream authz consumes
            # client_user verbatim (otpme_server.py:161, agent1.py:106).
            try:
                client_user = pwd.getpwuid(client_uid).pw_name
            except KeyError:
                new_connection.close()
                return None, None
            client_proc = stuff.get_pid_name(client_pid)
            if client_proc is None:
                new_connection.close()
                return None, None
            client_proc = client_proc.split()[0]
            client_id = stuff.gen_secret(len=32)
            client = f"socket://{client_proc}:{client_pid}:{client_user}:{client_id}"
        else:
            # v4 accept() yields a 2-tuple, v6 yields a 4-tuple.
            client_address, client_port = new_client_socket[:2]
            client = net.format_host_port(client_address, client_port)

        return new_connection, client

    def get_worker_thread_count(self):
        """ How many connections we are serving in threads right now. """
        with self.worker_thread_lock:
            return self.worker_thread_count

    def may_serve_in_thread(self):
        """ Check whether we may take a connection on top of our own.

        Only when there is nowhere else for it to go. A worker of our
        own is worth more than a thread of ours -- it brings a core with
        it, while a thread has to queue up behind us for the GIL -- so
        as long as the pool can still grow, or anyone in it is free, the
        answer is no and the connection is better off waiting in the
        backlog for a moment.

        The supervisor writes that verdict into the scoreboard, because
        it is the only one that sees every worker. We read one byte.
        """
        if self.worker_threads <= 0:
            return False
        if self.get_pool_state() != POOL_SATURATED:
            return False
        return self.get_worker_thread_count() < self.worker_threads

    def serve_in_thread(self, worker_idx, new_connection, client):
        """ Serve a connection in a thread and go back to accepting. """
        def run_connection():
            try:
                self.handle_connection(new_connection, client,
                                        self.connection_handler,
                                        _from_worker=True)
            except Exception as e:
                log_msg = _("Worker {idx}: Error handling connection: {error}", log=True)[1]
                log_msg = log_msg.format(idx=worker_idx, error=e)
                self.logger.warning(log_msg)
            finally:
                with self.worker_thread_lock:
                    self.worker_thread_count -= 1
                    threads_left = self.worker_thread_count
                # The accept loop may be sitting in accept() right now,
                # so nobody else would notice that we became free.
                if threads_left == 0:
                    self.set_worker_state(worker_idx, WORKER_IDLE)

        with self.worker_thread_lock:
            self.worker_thread_count += 1
        try:
            multiprocessing.start_thread(name=self.name,
                                        target=run_connection,
                                        daemon=True)
        except Exception as e:
            with self.worker_thread_lock:
                self.worker_thread_count -= 1
            log_msg = _("Worker {idx}: Failed to start connection thread: {error}", log=True)[1]
            log_msg = log_msg.format(idx=worker_idx, error=e)
            self.logger.warning(log_msg)
            try:
                new_connection.close()
            except Exception:
                pass

    def _worker_loop(self, worker_idx):
        """ Pre-fork worker loop: accept and handle connections repeatedly. """
        # Handle multiprocessing stuff.
        multiprocessing.atfork(quiet=True)
        # Setup logger.
        if not self.got_logger:
            self.logger = log.setup_logger(pid=os.getpid())
        # Set process title.
        new_proctitle = f"{self.proctitle} Worker: {worker_idx}"
        setproctitle.setproctitle(new_proctitle)

        if self.worker_threads > 0:
            # Two connections in one process means two of them share
            # what used to be private: config.auth_user/auth_token move
            # into thread local storage and the log handler takes a
            # lock. Both hang off this one switch, so it has to be set
            # before the first connection, not before the first thread.
            config.proc_mode = "threading"

        self.set_worker_state(worker_idx, WORKER_IDLE)

        while not self.shutdown:
            # Only reached between connections, so a client we accepted
            # ourselves is never left half served. Connections we handed
            # to threads are still running at this point -- those are
            # waited for below, before we leave.
            #
            # The pool never asks a worker with threads to stop:
            # supervise_workers() picks its slots from the idle ones,
            # and threads of ours keep us WORKER_BUSY.
            if self.get_worker_command(worker_idx) == WORKER_EXIT:
                log_msg = _("Worker {idx}: No longer needed, stopping.", log=True)[1]
                log_msg = log_msg.format(idx=worker_idx)
                self.logger.info(log_msg)
                break
            # Decided before we accept, not after: entering accept() is
            # what puts us in the running for the next connection, and
            # somebody who is already serving one has no business
            # competing for it while anyone else is free. Staying out
            # here is what leaves the connection to a worker that has
            # nothing to do -- the kernel hands it to whoever is in the
            # accept path, it knows nothing about who is busy.
            if self.get_worker_thread_count() > 0:
                if not self.may_serve_in_thread():
                    time.sleep(WORKER_THREAD_POLL_INTERVAL)
                    continue
            new_connection, client = self._accept_connection(worker_idx=worker_idx)
            if new_connection is None:
                # Nothing came in, or the handshake failed. Either way
                # we are free again -- unless a thread of ours is still
                # serving somebody.
                if self.get_worker_thread_count() == 0:
                    self.set_worker_state(worker_idx, WORKER_IDLE)
                continue
            if self.worker_threads > 0:
                # Where we serve connections in threads, we serve all of
                # them that way -- also the first one, and also while
                # the pool is healthy. Not a matter of taste: handing a
                # connection to a thread is a decision only a worker in
                # its accept loop can take, and taking one below leaves
                # that loop for as long as the connection lasts.
                #
                # Serving the first one below would close the door on
                # the rest. A wave of connections arrives in
                # milliseconds while the supervisor sets the pool state
                # every half second, so every worker would still see a
                # healthy pool, take its connection below, and be gone
                # from the accept loop by the time saturation is
                # published. Nobody would be left to read it, and the
                # threads would only start once the wave had passed --
                # or never, if whoever sent it holds on.
                #
                # It does not put us in the running for more than we are
                # allowed: whether we go back to accept at all is
                # decided at the top of the loop, before we get there.
                self.serve_in_thread(worker_idx, new_connection, client)
                continue
            # Log new connection.
            if config.debug_level("connections") > 0:
                log_msg = _("Worker {idx}: New connection from '{client}'", log=True)[1]
                log_msg = log_msg.format(idx=worker_idx, client=client)
                self.logger.debug(log_msg)
            # Set process title for duration of connection handling.
            new_proctitle = f"{self.proctitle} Worker: {worker_idx} Client: {client}"
            setproctitle.setproctitle(new_proctitle)
            try:
                self.handle_connection(new_connection, client,
                                      self.connection_handler,
                                      _from_worker=True)
            except Exception as e:
                log_msg = _("Worker {idx}: Error handling connection: {error}", log=True)[1]
                log_msg = log_msg.format(idx=worker_idx, error=e)
                self.logger.warning(log_msg)
            finally:
                if self.get_worker_thread_count() == 0:
                    self.set_worker_state(worker_idx, WORKER_IDLE)
            # Reset process title.
            new_proctitle = f"{self.proctitle} Worker: {worker_idx}"
            setproctitle.setproctitle(new_proctitle)

        # Give the connections we handed to threads their chance to
        # finish. os._exit() below takes them down mid request, and for
        # an authentication that means a client left without an answer
        # on something it cannot simply retry. They are daemon threads,
        # so nothing else waits for them.
        #
        # With a deadline: a client that stalls its connection must not
        # keep a worker of a stopping daemon alive for good. Whoever is
        # still running when it passes is cut off, which is what would
        # have happened right away without the wait.
        if self.get_worker_thread_count() > 0:
            log_msg = _("Worker {idx}: Waiting for {count} connection(s) to finish.", log=True)[1]
            log_msg = log_msg.format(idx=worker_idx,
                                    count=self.get_worker_thread_count())
            self.logger.info(log_msg)
            deadline = time.time() + WORKER_DRAIN_TIMEOUT
            while self.get_worker_thread_count() > 0:
                if time.time() >= deadline:
                    log_msg = _("Worker {idx}: Giving up on {count} connection(s) after {timeout}s.", log=True)[1]
                    log_msg = log_msg.format(idx=worker_idx,
                                            count=self.get_worker_thread_count(),
                                            timeout=WORKER_DRAIN_TIMEOUT)
                    self.logger.warning(log_msg)
                    break
                time.sleep(WORKER_THREAD_POLL_INTERVAL)

        # Leave the way every other forked child here leaves (see the
        # SIGTERM handler in multiprocessing.py): hard, without running
        # the interpreter shutdown. Returning from here would run the
        # atexit hook of concurrent.futures, which joins thread objects
        # we inherited at fork time -- threads that never existed in
        # this process, so the join never returns and the worker stays
        # alive for good. Nothing here needs flushing: the log handlers
        # write through, and the connection is closed by now.
        os._exit(0)

    def _accept_loop(self):
        """ Legacy fork-per-connection accept loop. """
        last_max_conn_warn = 0
        max_conn_warn_count = 0

        while True:
            if self.shutdown:
                break
            new_connection, client = self._accept_connection()
            if new_connection is None:
                time.sleep(0.01)
                continue

            # Handle max_conn.
            try:
                client_count = len(self.connections)
            except (KeyError, IOError):
                client_count = 0
            if (client_count + 1) > self.max_conn:
                new_connection.close()
                max_conn_warn_count += 1
                # Print max conn warning only every 5 seconds.
                if (time.time() - last_max_conn_warn) > 5:
                    last_max_conn_warn = time.time()
                    log_msg = _("Reached max connections ({count}). Refusing client '{client}'.", log=True)[1]
                    log_msg = log_msg.format(count=client_count, client=client)
                    self.logger.warning(log_msg)
                    if max_conn_warn_count > 1:
                        log_msg = _("Suppressed {count} max connections warnings to prevent logfile flooding.", log=True)[1]
                        log_msg = log_msg.format(count=max_conn_warn_count)
                        self.logger.warning(log_msg)
                        max_conn_warn_count = 0
                continue

            if self.shutdown:
                break

            # Log new connection.
            if config.debug_level("connections") > 0:
                log_msg = _("New connection from '{client}'", log=True)[1]
                log_msg = log_msg.format(client=client)
                self.logger.debug(log_msg)

            # Start child process to handle new connection.
            if self.conn_handling == "multiprocessing":
                try:
                    p = multiprocessing.start_process(name=self.name,
                                    target=self.handle_connection,
                                    target_args=(new_connection,
                                                client,
                                                self.connection_handler),
                                    hard_exit=True,
                                    join=False)
                except Exception as e:
                    log_msg = _("Failed to start connection handler: {e}", log=True)[1]
                    self.logger.warning(log_msg)
                else:
                    # Add process to dict.
                    self.add_connection_proc(client, p)
                # Close connection in parent process to avoid file descriptor leak.
                new_connection.close()
            else:
                try:
                    p = multiprocessing.start_thread(name=self.name,
                                    target=self.handle_connection,
                                    target_args=(new_connection,
                                                client,
                                                self.connection_handler),
                                    daemon=True)
                except Exception as e:
                    log_msg = _("Failed to start connection handler: {e}", log=True)[1]
                    self.logger.warning(log_msg)
                else:
                    # Add process to dict.
                    self.add_connection_proc(client, p)

    def handle_connection(self, client_conn, client, handler,
        _from_worker=False):
        """ Handle a connection. """
        if self.conn_handling == "multiprocessing":
            if not _from_worker:
                # Fork-per-connection mode: setup process.
                multiprocessing.atfork(quiet=True)
                if not self.got_logger:
                    self.logger = log.setup_logger(pid=os.getpid())
                new_proctitle = f"{self.proctitle} Client: {client}"
                setproctitle.setproctitle(new_proctitle)

        # Helper variables.
        peer_cert = None
        conn_handler = None

        # FIXME: DOES this work withouth SSL context?
        if self.use_ssl:
            peer_cert = client_conn.getpeercert(binary_form=True)
            if peer_cert:
                peer_cert = stuff.parse_peer_cert(peer_cert)

        # Create conncection instance.
        connection = Connection(connection=client_conn,
                                client=client,
                                peer_cert=peer_cert,
                                timeout=self.timeout,
                                logger=self.logger,
                                socket_handler=self.socket_handler)

        # Send banner if given.
        if self.banner:
            try:
                connection.send(f"{self.banner}\n")
            except Exception as e:
                log_msg = _("Unable to send banner: {uri}: {error}", log=True)[1]
                log_msg = log_msg.format(uri=self.socket_uri, error=e)
                self.logger.warn(log_msg)
                if not _from_worker:
                    multiprocessing.cleanup()
                config.raise_exception()
                return False

        # Check if we got a handler to handle this connection.
        if handler:
            # Create child handler for this connection.
            conn_handler = handler.__class__(name=handler.name,
                                            connection=connection,
                                            protocols=handler.protocols,
                                            client=client,
                                            peer_cert=peer_cert,
                                            logger=self.logger,
                                            **handler.handler_args)
            # Start connection handler.
            try:
                conn_handler.run()
            except ConnectionQuit as e:
                log_msg = _("Error running connection handler: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
            except Exception as e:
                config.raise_exception()
                log_msg = _("Unknown exception running connection handler: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
        else:
            # Without connection handler we act as simple echo server.
            while True:
                # Receive data from client.
                try:
                    response = connection.recv()
                except Exception as e:
                    log_msg = _("Error receiving data: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
                    break
                # Send response.
                try:
                    connection.send(response)
                except Exception as e:
                    log_msg = _("Error sending data: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
                    break

        if config.debug_level("connections") > 0:
            log_msg = _("Client '{client}' disconnected.", log=True)[1]
            log_msg = log_msg.format(client=client)
            self.logger.debug(log_msg)

        # Run connection cleanup (e.g. remove locks).
        if conn_handler:
            conn_handler.cleanup()

        # Make sure connection is closed.
        try:
            connection.close()
        except Exception:
            pass

        if self.conn_handling == "multiprocessing":
            if not _from_worker:
                # Fork-per-connection mode: full cleanup and notify.
                multiprocessing.cleanup(keep_queues=True)

        return True

    def remove_cert_files(self):
        """ Remove temporary SSL cert/key files. """
        if self.cert_file:
            if os.path.exists(self.cert_file):
                os.remove(self.cert_file)
        if self.key_file:
            if os.path.exists(self.key_file):
                os.remove(self.key_file)
        if self.ca_data_file:
            if os.path.exists(self.ca_data_file):
                os.remove(self.ca_data_file)

    def close_connections(self):
        """ Close connection with all clients. """
        # Walk through list of all client connections and close them. We do not
        # use self.connections because this is a shared dict (e.g. redis) which
        # may be unavailable if the cache is down.
        if self.listen_process is None:
            return
        try:
            proc = psutil.Process(self.listen_process.pid)
        except psutil.NoSuchProcess:
            return
        try:
            children = proc.get_children(recursive=False)
        except Exception:
            children = proc.children(recursive=False)

        for child in children:
            child_pid = child.pid
            try:
                child_name = child.name()
            except Exception:
                child_name = child.name

            if not stuff.check_pid(child_pid):
                continue
            log_msg = _("Sending SIGTERM to connection: {name} (PID {pid})", log=True)[1]
            log_msg = log_msg.format(name=child_name, pid=child_pid)
            self.logger.debug(log_msg)
            try:
                stuff.kill_pid(child_pid, signal=15,
                                timeout=5, kill_timeout=2)
            except Exception as e:
                log_msg = _("Failed to send SIGTERM to connection: {name}: {error}", log=True)[1]
                log_msg = log_msg.format(name=child_name, error=e)
                self.logger.warning(log_msg)

    def close(self):
        """ Close all connections and stop listening on socket. """
        # Inform main loop about shutdown.
        self.shutdown = True
        # Shutdown socket.
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except IOError:
            pass
        # Close client connections.
        self.close_connections()
        # Attempt graceful SSL shutdown.
        if hasattr(self._socket, 'unwrap'):
            try:
                self._socket.unwrap()
            except ValueError:
                pass
        # Stop listening on socket.
        self._socket.close()

        # Terminate listen process.
        if self.listen_process:
            self.listen_process.terminate()
            self.listen_process.join()

        if self.protocol == "socket":
            # Remove socket file.
            if os.path.exists(self.socket):
                try:
                    os.remove(self.socket)
                except OSError:
                    raise

        if self.use_ssl:
            # Remove temporary files:
            self.remove_cert_files()

        # Close shared bool.
        if self._shutdown:
            self._shutdown.close()

class Connection(object):
    """ Class to handle send/recv data. """
    def __init__(self, connection, client, socket_handler=None,
        peer_cert=None, timeout=None, logger=None):
        # Our connection.
        self.connection = connection
        # Connection timeout.
        self.timeout = timeout
        # Init socket handler.
        self.socket_handler = socket_handler("server", connection)
        # Connected client.
        self.client = client
        # Client certificate.
        self.peer_cert = peer_cert
        # Connection status.
        self.connected = True
        if logger:
            self.logger = logger
        else:
            self.logger = config.logger

    def __getattr__(self, name):
        """ Map to original attributes. """
        return getattr(self.connection, name)

    def set_timeout(self, timeout):
        """ Set connection timeout. """
        # settimeout() requires None for no timeout.
        if timeout == 0:
            timeout = None
        # Set timeout.
        self.connection.settimeout(timeout)
        self.timeout = timeout

    def sendall(self, data, timeout=None):
        """ Send data. """
        org_timeout = self.timeout
        if timeout is not None:
            self.set_timeout(timeout)
        try:
            if self.socket_handler:
                return self.socket_handler.sendall(data)
            else:
                return self.connection.sendall(data)
        except ConnectionQuit as e:
            self._close()
            msg = _("Client '{client}' closed connection while sending data: {error}")
            msg = msg.format(client=self.client, error=e)
            raise ConnectionQuit(msg) from e
        except ConnectionTimeout:
            self._close()
            raise
        except Exception as err:
            self._close()
            msg = _("Connection with client '{client}' closed while sending data.")
            msg = msg.format(client=self.client)
            raise Exception(msg) from err
        finally:
            # Only while the socket is still open: the paths above close
            # it on a timeout or a lost connection, and setting a
            # timeout on a closed one raises EBADF -- which would then
            # take the place of the exception we are on our way out
            # with, and a hangup would read as "Bad file descriptor".
            if timeout is not None and self.connected:
                self.set_timeout(org_timeout)

    def send(self, data, timeout=None):
        """ Send data. """
        org_timeout = self.timeout
        if timeout is not None:
            self.set_timeout(timeout)
        try:
            if self.socket_handler:
                if data == "quit":
                    return self.socket_handler.raw_send(data=data)
                else:
                    return self.socket_handler.send(data=data)
            else:
                return self.connection.send(data)
        except ConnectionQuit as e:
            self._close()
            msg = _("Client '{client}' closed connection while sending data: {error}")
            msg = msg.format(client=self.client, error=e)
            raise ConnectionQuit(msg) from e
        except ConnectionTimeout:
            self._close()
            raise
        except Exception as err:
            self._close()
            msg = _("Connection with client '{client}' closed while sending data.")
            msg = msg.format(client=self.client)
            raise Exception(msg) from err
        finally:
            # Only while the socket is still open: the paths above close
            # it on a timeout or a lost connection, and setting a
            # timeout on a closed one raises EBADF -- which would then
            # take the place of the exception we are on our way out
            # with, and a hangup would read as "Bad file descriptor".
            if timeout is not None and self.connected:
                self.set_timeout(org_timeout)

    def recv(self, recv_buffer=config.socket_receive_buffer, timeout=None):
        """ Receive data from connection. """
        org_timeout = self.timeout
        if timeout is not None:
            self.set_timeout(timeout)
        try:
            if self.socket_handler:
                data = self.socket_handler.recv(recv_buffer=recv_buffer)
            else:
                data = self.connection.recv(recv_buffer)
            return data
        except ConnectionTimeout:
            self._close()
            raise
        except ConnectionQuit as err:
            msg = _("Connection with client '{client}' closed while receiving data.")
            msg = msg.format(client=self.client)
            self._close()
            raise ConnectionQuit(msg) from err
        except Exception as err:
            msg = _("Connection with client '{client}' lost while receiving data.")
            msg = msg.format(client=self.client)
            self._close()
            raise Exception(msg) from err
        finally:
            # Only while the socket is still open: the paths above close
            # it on a timeout or a lost connection, and setting a
            # timeout on a closed one raises EBADF -- which would then
            # take the place of the exception we are on our way out
            # with, and a hangup would read as "Bad file descriptor".
            if timeout is not None and self.connected:
                self.set_timeout(org_timeout)

    def close(self):
        """ Close connection. """
        if not self.connected:
            return
        if config.debug_level("connections") > 0:
            log_msg = _("Closing connection to '{client}'", log=True)[1]
            log_msg = log_msg.format(client=self.client)
            self.logger.debug(log_msg)
        try:
            self.send("quit", timeout=0.01)
        except OSError:
            pass
        self.connected = False
        self._close()

    def _close(self):
        """ Close connection. """
        self.connected = False
        try:
            self.connection.close()
            self.connection.shutdown(2)
        except Exception:
            pass
