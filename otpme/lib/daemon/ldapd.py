# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import signal
#import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import log
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import multiprocessing
from otpme.lib.ldap.server import LDAPServer
from otpme.lib.ldap.server import clear_caches
from otpme.lib.ldap.server import install_reactor
from otpme.lib.ldap.server import set_shared_cache
from otpme.lib.ldap.server import create_listen_socket
from otpme.lib.ldap.server import set_shared_cache_time
from otpme.lib.ldap.server import SHARED_QUERY_CACHE_TIME
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

# Seconds we give a worker to go down before we get harder about it.
WORKER_STOP_TIMEOUT = 5

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("ldapd")

class LdapDaemon(OTPmeDaemon):
    """ LdapDaemon """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ldap_server = None
        self.ldapd_processes = 1
        self.worker_procs = []
        self.worker_sockets = []
        self.workers_shutdown = False

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # FIXME: Where to configure max_conn?
        # Set max client connections.
        #self.max_conn = 100

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Create cert/key files for twisted/ldaptor.
        try:
            # FIXME: Twisted does not support password protected key files!?
            # http://twistedmatrix.com/documents/13.1.0/api/twisted.internet.ssl.DefaultOpenSSLContextFactory.html
            ## Encrypt cert private key with password if supported by python SSL.
            #passphrase = stuff.gen_secret(len=32)
            #_cert = SSLCert(key=ssl_key)
            #ssl_key = _cert.encrypt_key(key=ssl_key, algo="blowfish", passphrase=passphrase)

            #ssl_cert = config.host_data['cert']
            #ssl_key = config.host_data['key']

            own_site = backend.get_object(uuid=config.site_uuid)
            ssl_cert = own_site.mgmt_cert
            ssl_key = own_site.mgmt_key

            # Materialise cert and key in a per-daemon subdir under
            # run_dir that is owner-only (0o700). Previously these went
            # to /tmp (config.tmp_dir), which is world-traversable; any
            # local uid could read the TLS private key during the window
            # between write and unlink. The 0o700 parent closes that
            # window even if the file itself is briefly created with
            # umask-defaults. The os.open(O_CREAT|O_EXCL, 0o600) below
            # additionally pins the file mode atomically. An in-memory
            # SSLContext.wrap_socket() would let us drop the on-disk
            # path entirely, but twisted/ldaptor still wants paths.
            ldapd_tmpdir = os.path.join(config.run_dir, "ldapd")
            if not os.path.exists(ldapd_tmpdir):
                filetools.create_dir(ldapd_tmpdir,
                                    user=self.user,
                                    group=self.group,
                                    mode=0o700)
            else:
                # Defensive: a pre-fix install may have created this
                # dir with looser perms.
                filetools.set_fs_permissions(path=ldapd_tmpdir,
                                            mode=0o700)
                if self.user or self.group:
                    filetools.set_fs_ownership(path=ldapd_tmpdir,
                                            user=self.user,
                                            group=self.group,
                                            recursive=False)

            self.cert_file = os.path.join(ldapd_tmpdir, f"{stuff.gen_secret(32)}-cert.pem")
            self.key_file = os.path.join(ldapd_tmpdir, f"{stuff.gen_secret(32)}-key.pem")

            # Build dict with all temp files to create.
            tmp_files = {}
            tmp_files[self.cert_file] = ssl_cert
            tmp_files[self.key_file] = ssl_key

            # Create all needed temp files.
            for tmp_file, file_content in tmp_files.items():
                # O_CREAT|O_EXCL refuses to follow a stale symlink or
                # reuse an attacker-placed inode; mode 0o600 is set
                # atomically by os.open, removing the umask-controlled
                # window between open() and a follow-up chmod.
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                fd = os.open(tmp_file, flags, 0o600)
                try:
                    if isinstance(file_content, str):
                        file_content = file_content.encode("utf-8")
                    os.write(fd, file_content)
                finally:
                    os.close(fd)
                if self.user or self.group:
                    filetools.set_fs_ownership(path=tmp_file,
                                            user=self.user,
                                            group=self.group,
                                            recursive=False)

            # Build the SSL context here, not in the workers: it reads
            # cert and key, so doing it once lets us take both off disk
            # right away instead of leaving them there until the last
            # worker got up.
            from twisted.internet import ssl
            ssl_context = ssl.DefaultOpenSSLContextFactory(
                                            privateKeyFileName=self.key_file,
                                            certificateFileName=self.cert_file)

            # Using SSLContext.wrap_socket() with newer python versions it's
            # possible to remove cert/key files after socket initialization.
            if os.path.exists(self.cert_file):
                os.remove(self.cert_file)
            if os.path.exists(self.key_file):
                os.remove(self.key_file)
        except Exception:
            raise

        self.ldapd_processes = self.get_ldapd_processes()

        # Before we fork, so every worker starts with the same setting.
        shared_cache = self.get_shared_cache()
        set_shared_cache(shared_cache)
        if not shared_cache:
            log_msg = _("Shared LDAP caches are turned off.", log=True)[1]
            self.logger.info(log_msg)
        set_shared_cache_time(self.get_shared_cache_time())

        if self.ldapd_processes > 1:
            # One process per core instead of one reactor for all of
            # them. They share the port through SO_REUSEPORT, so the
            # kernel spreads the connections over them.
            self.start_workers(ssl_context)
            self.drop_privileges()
            # No reactor of our own to run, so the daemon loop can have
            # the main thread.
            self.__run()
            return

        for x in self.listen_sockets:
            address, port = self.parse_listen_socket(x)
            self.ldap_server = LDAPServer(address=address, port=port)
            self.ldap_server.listen(use_ssl=True, ssl_context=ssl_context)

        # We can drop privileges AFTER sockets are created. This is needed when
        # listening to well known ports (<1024), which requires root privileges.
        self.drop_privileges()

        # We need to start the main loop in child thread because of some
        # high CPU load bug when running reactor.run() in child thread.
        multiprocessing.start_thread(name=self.name,
                                    target=self.__run,
                                    daemon=True)

        self.ldap_server.run()

    def parse_listen_socket(self, listen_socket):
        """ Get address and port. """
        # Format: "address:port"; v6 addresses are bracketed: "[::]:389"
        if listen_socket.startswith("["):
            end = listen_socket.find("]")
            address = listen_socket[1:end]
            port = listen_socket[end+2:]
        else:
            address, port = listen_socket.rsplit(":", 1)
        return address, port

    def get_shared_cache(self):
        """ Do our processes hand their search results to each other? """
        try:
            own_node = backend.get_object(uuid=config.uuid)
            enabled = own_node.get_config_parameter("ldap_shared_cache")
        except Exception as e:
            log_msg = _("Failed to get shared query cache setting: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return True
        if enabled is None:
            return True
        return bool(enabled)

    def get_shared_cache_time(self):
        """ How long do our processes trust a cached search? """
        try:
            own_node = backend.get_object(uuid=config.uuid)
            cache_time = own_node.get_config_parameter("ldap_shared_cache_time")
        except Exception as e:
            log_msg = _("Failed to get shared query cache time: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return SHARED_QUERY_CACHE_TIME
        if not cache_time:
            return SHARED_QUERY_CACHE_TIME
        return int(cache_time)

    def get_ldapd_processes(self):
        """ Get the number of processes we answer requests with. """
        try:
            own_node = backend.get_object(uuid=config.uuid)
            ldapd_processes = own_node.get_config_parameter("ldapd_processes")
        except Exception as e:
            log_msg = _("Failed to get ldapd process count: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return 1
        if not ldapd_processes:
            return 1
        return int(ldapd_processes)

    def start_workers(self, ssl_context):
        """ Start the processes that answer LDAP requests. """
        log_msg = _("Starting {count} ldapd workers.", log=True)[1]
        log_msg = log_msg.format(count=self.ldapd_processes)
        self.logger.info(log_msg)
        for x_id in range(self.ldapd_processes):
            # Bind while we still have the privileges for it. A worker we
            # have to start over later gets the very same socket, so it
            # does not need them either.
            self.worker_sockets.append(self.create_worker_sockets())
            self.worker_procs.append(self.start_worker(x_id, ssl_context))
        multiprocessing.start_thread(name=f"{self.name}-workers",
                                    target=self.watch_workers,
                                    target_args=(ssl_context,),
                                    daemon=True)

    def create_worker_sockets(self):
        """ Get the listening sockets of one worker. """
        worker_sockets = []
        for x in self.listen_sockets:
            address, port = self.parse_listen_socket(x)
            x_socket = create_listen_socket(address, port)
            worker_sockets.append((address, port, x_socket))
        return worker_sockets

    def start_worker(self, worker_id, ssl_context):
        """ Start one worker process. """
        worker_name = f"{self.name}-worker-{worker_id}"
        return multiprocessing.start_process(name=worker_name,
                                        target=self.run_worker,
                                        target_args=(worker_id, ssl_context))

    def watch_workers(self, ssl_context):
        """ Bring back the workers that died on us. """
        while not self.workers_shutdown:
            for x_id, x_proc in enumerate(self.worker_procs):
                if self.workers_shutdown:
                    break
                if x_proc.is_alive():
                    continue
                x_proc.join()
                log_msg = _("ldapd worker {idx} died, starting a new one.", log=True)[1]
                log_msg = log_msg.format(idx=x_id)
                self.logger.warning(log_msg)
                self.worker_procs[x_id] = self.start_worker(x_id, ssl_context)
            time.sleep(0.5)

    def run_worker(self, worker_id, ssl_context):
        """ Answer LDAP requests in our own process. """
        # Before anything gets hold of the inherited one.
        install_reactor()
        # We inherited the sockets of all our siblings. Ours is the only
        # one we may accept on, the rest are just descriptors to us.
        for x_id, x_sockets in enumerate(self.worker_sockets):
            if x_id == worker_id:
                continue
            for _address, _port, x_socket in x_sockets:
                x_socket.close()
        ldap_server = None
        for address, port, x_socket in self.worker_sockets[worker_id]:
            ldap_server = LDAPServer(address=address, port=port)
            ldap_server.listen(use_ssl=True,
                            ssl_context=ssl_context,
                            listen_socket=x_socket)
        # Our parent bound the socket for us, we need nothing else.
        self.drop_privileges()
        # Our caches are ours alone, so our parent tells us by signal
        # when it is time to drop them.
        signal.signal(signal.SIGHUP, self.worker_reload)
        ldap_server.run()
        # run() comes back when the reactor stopped, which is what a
        # SIGTERM does. Leave right here instead of letting the
        # interpreter shut down: we are a fork, and threads that only
        # ever ran in our parent are still on the lists that
        # threading._shutdown() joins at exit. It would wait for them
        # forever, and our parent waits for the whole process tree.
        os._exit(0)

    def worker_reload(self, _signal, frame):
        """ Drop our caches on our parents request. """
        clear_caches()

    def cleanup(self):
        """ Take our workers with us when we go down. """
        if self.worker_procs:
            self.stop_workers()

    def stop_workers(self):
        """ Stop the worker processes. """
        if self.workers_shutdown:
            return
        self.workers_shutdown = True
        for x_proc in self.worker_procs:
            try:
                x_proc.terminate()
            except Exception:
                pass
        for x_proc in self.worker_procs:
            try:
                x_proc.join(timeout=WORKER_STOP_TIMEOUT)
            except Exception:
                pass
            if not x_proc.is_alive():
                continue
            # Whoever stops us waits for our whole process tree, so a
            # worker we leave behind holds up the shutdown of the node.
            log_msg = _("ldapd worker {pid} ignored SIGTERM, killing it.", log=True)[1]
            log_msg = log_msg.format(pid=x_proc.pid)
            self.logger.warning(log_msg)
            try:
                x_proc.kill()
                x_proc.join(timeout=WORKER_STOP_TIMEOUT)
            except Exception:
                pass

    def reload_workers(self):
        """ Tell the workers to drop their caches. """
        for x_proc in self.worker_procs:
            try:
                os.kill(x_proc.pid, signal.SIGHUP)
            except Exception as e:
                log_msg = _("Failed to reload ldapd worker: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

    def __run(self, **kwargs):
        # Notify controld that we are ready.
        self.comm_handler.send("controld", command="ready")

        log_msg = _("{full_name} started", log=True)[1]
        log_msg = log_msg.format(full_name=self.full_name)
        self.logger.info(log_msg)

        # Run in loop unitl we get a signal.
        while True:
            try:
                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv()
                except ExitOnSignal:
                    break
                #except TimeoutReached:
                #    time.sleep(0.001)
                #    continue
                except Exception as e:
                    msg, log_msg = _("Error receiving daemon message: {error}", log=True)
                    msg = msg.format(error=e)
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg, exc_info=True)
                    raise OTPmeException(msg) from e

                # Check if command can be handled by parent class.
                try:
                    self._handle_daemon_command(sender, daemon_command, data)
                except UnknownCommand as e:
                    log_msg = str(e)
                    self.logger.warning(log_msg)
                except DaemonQuit:
                    break
                except DaemonReload:
                    # Caches live in the process that built them, so clear
                    # them right where they are. Going through shared state
                    # would mean that only the first process to look at it
                    # would clear anything.
                    if self.worker_procs:
                        self.reload_workers()
                    else:
                        clear_caches()
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in ldapd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)

        # Stop LDAP server (ldaptor).
        if self.worker_procs:
            # The reactors run in our workers. Our cleanup() stops them,
            # which also covers going down on a signal.
            return
        if config.daemonize:
            # Send SIGTERM.
            mypid = os.getpid()
            stuff.kill_pid(mypid)
        else:
            self.ldap_server.reactor.callFromThread(self.ldap_server.stop)
