# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import ssl
import time
import socket
import psutil
import setproctitle
from cryptography import x509
from cryptography.hazmat.backends import default_backend

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import re
from otpme.lib import log
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import multiprocessing

from otpme.lib.exceptions import *

class ListenSocket(object):
    """ Class to start and stop TCP or unix socket. """
    def __init__(self, socket_uri, connection_handler, name,
        blocking=True, timeout=1, banner=None, socket_handler=None, user=None,
        group=None, mode=0o600, use_ssl=False, ssl_version=ssl.PROTOCOL_TLSv1_2,
        ssl_cert=None, ssl_key=None, ssl_ca_data=None, ssl_verify_client=False,
        proctitle=None, logger=None, max_conn=100):
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
        # Set socket blocking.
        self.blocking = blocking
        # Our timeout.
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
        self.max_conn=max_conn

        self.key_file = None
        self.cert_file = None
        self.ca_data_file = None
        self.listen_process = None
        self._shutdown = None
        self.connection_closed_event = None

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
            # Get protocol.
            self.protocol = re.sub('^([^:]*):.*$', r'\1', self.socket_uri)
            # Get listen address.
            self.address = re.sub(f'^{self.protocol}://([^:]*):([0-9]*)$',
                                r'\1',
                                self.socket_uri)
            # Get listen port.
            self.port = int(re.sub(f'^{self.protocol}://([^:]*):([0-9]*)$',
                                r'\2',
                                self.socket_uri))
            # Set socket tuple.
            self.socket = (self.address, self.port)

            # Create socket.
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # NOTE: Prevent "socket.error: [Errno 98] Address already in use":
                #       http://stackoverflow.com/questions/4465959/python-errno-98-address-already-in-use
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except socket.error as e:
                log_msg = _("Failed to create socket. Error code: {code}, Error message: {message}", log=True)[1]
                log_msg = log_msg.format(code=e[0], message=e[1])
                self.logger.error(log_msg)
                return False
            # Set send/recv buffer.
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, config.socket_receive_buffer)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, config.socket_receive_buffer)

        if not self.blocking:
            self._socket.setblocking(0)

        if self.timeout > 0:
            _timeout = self.timeout
        else:
            _timeout = None

        # Set connect timeout.
        self._socket.settimeout(_timeout)

        # Bind socket (in case of unix socket create socket file).
        try:
            self._socket.bind(self.socket)
        except Exception as e:
            msg = _("Failed to bind to socket: {socket}: {error}")
            msg = msg.format(socket=self.socket, error=e)
            raise OTPmeException(msg)

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

    def parse_peer_cert(self, peer_cert):
        cert = x509.load_der_x509_certificate(peer_cert, default_backend())
        cert_cn = cert.subject.rfc4514_string()
        for x in cert_cn.split(","):
            if not x.startswith("CN="):
                continue
            cert_cn = x.split("=")[1]
            break
        cert_issuer = cert.issuer.rfc4514_string()
        for x in cert_issuer.split(","):
            if not x.startswith("CN="):
                continue
            cert_issuer = x.split("=")[1]
            break
        cert_serial_number = cert.serial_number
        peer_cert = {
                    'cn'            : cert_cn,
                    'issuer'        : cert_issuer,
                    'serial_number' : cert_serial_number,
                    }
        return peer_cert

    def add_connection_proc(self, client, proc):
        """ Send client to client handler. """
        # Add connection proc.
        self.connections[client] = proc
        # Cleanup old connection PIDs.
        try:
            connections = self.connections.copy()
        except:
            return
        for c in dict(connections):
            try:
                pid = self.connections[c].pid
            except:
                continue
            if stuff.check_pid(pid):
                continue
            try:
                self.connections.pop(c)
            except:
                pass

    def close_conn_procs(self):
        """ Make sure connection procs are closed. """
        while True:
            self.connection_closed_event.wait()
            if self.shutdown:
                break
            time.sleep(0.1)
            for client in dict(self.connections):
                try:
                    proc = self.connections[client]
                except KeyError:
                    continue
                if proc.is_alive():
                    continue
                proc.join()
                proc.close()
                try:
                    self.connections.pop(client)
                except KeyError:
                    pass

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
        # Connection closed event.
        self.connection_closed_event = multiprocessing.Event()
        # Create queue to get init done info from self._listen()
        init_done = multiprocessing.MessageQueue("listensocket-initq")
        # Start listenting in new process.
        self.listen_process = multiprocessing.start_process(name=self.name,
                                                    target=self._listen,
                                                    target_args=(init_done,),
                                                    target_kwargs=kwargs)
        # Wait for _listen() to initialize (e.g. setup ssl certs etc.)
        try:
            init_done.recv()
        except Exception as e:
            log_msg = _("Exception waiting for listen process init: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        finally:
            init_done.unlink()

    def _listen(self, init_done, **kwargs):
        """
        Listen on a socket, unix or TCP, and start per connection child process.
        """
        # Helper variables.
        last_max_conn_warn = 0
        max_conn_warn_count = 0

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
            self.logger = log.setup_logger(pid=os.getpid())

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
                # FIXME: implement ssl.CERT_NONE!!??
                #if self.ssl_verify_client:
                #    tmp_files[self.ca_data_file] = self.ssl_ca_data

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
                    ctx.verify_mode = ssl.CERT_OPTIONAL
                    self._socket = ctx.wrap_socket(self._socket,
                                            server_side=True,
                                            do_handshake_on_connect=False,
                                            suppress_ragged_eofs=True,
                                            server_hostname=None)
            # Start listening on socket.
            # Set backlog to 128 to prevent:
            #   "TCP: request_sock_TCP: Possible SYN flooding on port xxxx. Sending cookies.  Check SNMP counters."
            self._socket.listen(128)

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

        # Start thread to handle connection procs.
        multiprocessing.start_thread(name=self.name,
                            target=self.close_conn_procs)

        # Run in loop to accept connections:
        while True:
            if self.shutdown:
                break
            # Wait for client connection.
            exception = None
            new_client_socket = None
            try:
                new_connection, new_client_socket = self._socket.accept()
                # Perform SSL handshake manually to catch errors with client info
                if self.use_ssl:
                    try:
                        new_connection.do_handshake()
                    except Exception as ssl_error:
                        # We have client info now, so log it with the error
                        if self.protocol == "tcp":
                            client_address, client_port = new_client_socket
                            peer_cert = new_connection.getpeercert(binary_form=True)
                            peer_cn = None
                            if peer_cert:
                                peer_cert = self.parse_peer_cert(peer_cert)
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
                        except:
                            pass
                        time.sleep(0.01)
                        continue
            except socket.timeout:
                time.sleep(0.01)
                continue
            except Exception as e:
                exception = e
                new_connection = None

            # If we got no new connection there was an error.
            if not new_connection:
                if exception is not None:
                    if self.use_ssl:
                        log_msg = _("Listen: SSL error: {error}", log=True)[1]
                        log_msg = log_msg.format(error=exception)
                    else:
                        log_msg = _("Listen: Connection error: {error}", log=True)[1]
                        log_msg = log_msg.format(error=exception)
                    self.logger.warning(log_msg)
                time.sleep(0.01)
                continue

            # For TCP sockets we can get client address and port from socket
            # instance. For unix sockets we generate a socket ID that will be
            # used as dict key for self.connections.
            if self.protocol == "socket":
                # Get connecting PID and user infos.
                # http://stackoverflow.com/questions/7982714/unix-socket-credential-passing-in-python
                import struct
                SO_PEERCRED = 17
                creds = new_connection.getsockopt(socket.SOL_SOCKET,
                                                    SO_PEERCRED,
                                                    struct.calcsize('3i'))
                client_pid, client_uid, client_gid = struct.unpack('3i',creds)
                client_user = stuff.get_pid_user(client_pid)
                client_proc = stuff.get_pid_name(client_pid)
                # Ignore disconnected client.
                if client_proc is None:
                    continue
                # Get executable of PID.
                client_proc = client_proc.split()[0]
                client_id = stuff.gen_secret(len=32)
                client = f"socket://{client_proc}:{client_pid}:{client_user}:{client_id}"
            else:
                client_address, client_port = new_client_socket
                client = f"{client_address}:{client_port}"

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
            if config.debug_level() > 3:
                log_msg = _("New connection from '{client}'", log=True)[1]
                log_msg = log_msg.format(client=client)
                self.logger.debug(log_msg)

            # Start child process to handle new connection.
            p = multiprocessing.start_process(name=self.name,
                            target=self.handle_connection,
                            target_args=(new_connection,
                                        client,
                                        self.connection_handler,
                                        self.connection_closed_event),
                            join=False)
            # Close connection in parent process to avoid file descriptor leak.
            new_connection.close()
            # Add process to dict.
            self.add_connection_proc(client, p)

        if self.connection_closed_event:
            self.connection_closed_event.set()

        log_msg = _("Stopped listening on '{uri}'", log=True)[1]
        log_msg = log_msg.format(uri=self.socket_uri)
        self.logger.info(log_msg)
        # Do multiprocessing cleanup.
        multiprocessing.cleanup()

    def handle_connection(self, client_conn, client, handler, close_event):
        """ Handle a connection. """
        # Handle multiprocessing stuff.
        multiprocessing.atfork(quiet=True)
        # Setup logger.
        if not self.got_logger:
            self.logger = log.setup_logger(pid=os.getpid())

        # Set process title.
        new_proctitle = f"{self.proctitle} Client: {client}"
        setproctitle.setproctitle(new_proctitle)

        # Helper variables.
        peer_cert = None
        conn_handler = None

        # FIXME: DOES this work withouth SSL context?
        if self.use_ssl:
            peer_cert = client_conn.getpeercert(binary_form=True)
            if peer_cert:
                peer_cert = self.parse_peer_cert(peer_cert)

        #print(repr(self.client_conn.getpeername()))
        #print(self.client_conn.getpeercert()['subject'])
        #print(repr(self.client_conn.getpeercert()))
        #import pprint
        #print(pprint.pformat(self.client_conn.getpeercert()))

        # Create conncection instance.
        connection = Connection(connection=client_conn,
                                client=client,
                                blocking=self.blocking,
                                peer_cert=peer_cert,
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
                multiprocessing.cleanup()
                config.raise_exception()
                return False

        # Check if we got a handler to handle this connection.
        if handler:
            # Create child handler for this connection.
            conn_handler = handler.__class__(connection=connection,
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
                    reply = connection.recv()
                except Exception as e:
                    log_msg = _("Error receiving data: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
                    break
                # Send reply.
                try:
                    connection.send(reply)
                except Exception as e:
                    log_msg = _("Error sending data: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
                    break

        if config.debug_level() > 3:
            log_msg = _("Client '{client}' disconnected.", log=True)[1]
            log_msg = log_msg.format(client=client)
            self.logger.debug(log_msg)

        # Run connection cleanup (e.g. remove locks).
        if conn_handler:
            conn_handler.cleanup()

        # Make sure connection is closed.
        try:
            connection.close()
        except:
            pass

        # Cleanup locks etc.
        multiprocessing.cleanup(keep_queues=True)
        # Notify master process about closed connection.
        close_event.set()

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
        except:
            children = proc.children(recursive=False)

        for child in children:
            child_pid = child.pid
            try:
                child_name = child.name()
            except:
                child_name = child.name

            if not stuff.check_pid(child_pid):
                continue
            log_msg = _("Sending SIGTERM to connection: {name} (PID {pid})", log=True)[1]
            log_msg = log_msg.format(name=child_name, pid=child_pid)
            self.logger.debug(log_msg)
            try:
                stuff.kill_pid(child_pid, signal=15)
            except Exception as e:
                log_msg = _("Failed to send SIGTERM to connection: {name}: {error}", log=True)[1]
                log_msg = log_msg.format(name=child_name, error=e)
                self.logger.warning(log_msg)
            # Wait for connection process to finish.
            while stuff.check_pid(child_pid):
                time.sleep(0.01)

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

        # Close/unlink event.
        if self.connection_closed_event:
            self.connection_closed_event.close()
            self.connection_closed_event.unlink()

class Connection(object):
    """ Class to handle send/recv data. """
    def __init__(self, connection, client, blocking,
        socket_handler=None, peer_cert=None, logger=None):
        # Our connection.
        self.connection = connection
        # Blocking.
        self.blocking = blocking
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

    def sendall(self, data, timeout=None):
        """ Send data. """
        if timeout > 0:
            _timeout = timeout
        else:
            _timeout = None
        try:
            # Set connect timeout.
            self.connection.settimeout(_timeout)
            if self.socket_handler:
                return self.socket_handler.sendall(data)
            else:
                return self.connection.sendall(data)
        except ConnectionQuit as e:
            self._close()
            msg = _("Client '{client}' closed connection while sending data: {error}")
            msg = msg.format(client=self.client, error=e)
            raise ConnectionQuit(msg)
        except ConnectionTimeout:
            self._close()
            raise
        except Exception:
            self._close()
            msg = _("Connection with client '{client}' closed while sending data.")
            msg = msg.format(client=self.client)
            raise Exception(msg)

    def send(self, data, timeout=None):
        """ Send data. """
        _timeout = None
        if timeout is not None:
            if timeout > 0:
                _timeout = timeout
        try:
            # Set connect timeout.
            self.connection.settimeout(_timeout)
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
            raise ConnectionQuit(msg)
        except ConnectionTimeout:
            self._close()
            raise
        except Exception:
            self._close()
            msg = _("Connection with client '{client}' closed while sending data.")
            msg = msg.format(client=self.client)
            raise Exception(msg)

    def recv(self, recv_buffer=config.socket_receive_buffer, timeout=None):
        """ Receive data from connection. """
        _timeout = None
        if timeout is not None:
            if timeout > 0:
                _timeout = timeout
        try:
            # Set connect timeout.
            self.connection.settimeout(_timeout)
            if self.socket_handler:
                data = self.socket_handler.recv(recv_buffer=recv_buffer)
            else:
                data = self.connection.recv(recv_buffer)
            return data
        except ConnectionTimeout:
            self._close()
            raise
        except ConnectionQuit:
            msg = _("Connection with client '{client}' closed while receiving data.")
            msg = msg.format(client=self.client)
            self._close()
            raise ConnectionQuit(msg)
        except Exception:
            msg = _("Connection with client '{client}' lost while receiving data.")
            msg = msg.format(client=self.client)
            self._close()
            raise Exception(msg)

    def close(self):
        """ Close connection. """
        if not self.connected:
            return
        if config.debug_level() > 3:
            log_msg = _("Closing connection to '{client}'", log=True)[1]
            log_msg = log_msg.format(client=self.client)
            self.logger.debug(log_msg)
        self.send("quit", timeout=0.01)
        self.connected = False
        self._close()

    def _close(self):
        """ Close connection. """
        self.connected = False
        try:
            self.connection.close()
            self.connection.shutdown(2)
        except:
            pass
