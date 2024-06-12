# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import ssl
import signal
import socket
#import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools

from otpme.lib.exceptions import *

class ConnectSocket(object):
    """ Class to handle connections to TCP or unix sockets. """
    def __init__(self, socket_uri, use_ssl=True, ssl_version=ssl.PROTOCOL_TLSv1_2,
        cert=None, key=None, ca_data=None, verify_server=False,
        blocking=True, socket_handler=None):
        # Will hold certificate infos of peer.
        self.peer_cert = None
        # Our socket URI string. e.g. tcp://127.0.0.1:8080
        self.socket_uri = socket_uri
        self.blocking = blocking
        self.address = None
        # SSL stuff.
        self.use_ssl = use_ssl
        self.key_file = None
        self.key_pass = None
        self.cert_file = None
        self.ca_data_file = None
        self.connected = False
        self.logger = config.logger

        #is_main_thread = isinstance(threading.current_thread(), threading._MainThread)
        #if is_main_thread:
        #    # Save original signal handler.
        #    self.org_sigint_handler = signal.getsignal(signal.SIGINT)
        #    self.org_sigterm_handler = signal.getsignal(signal.SIGTERM)
        #    # Install the new SIGINT handler.
        #    signal.signal(signal.SIGTERM, self.signal_handler)
        #    signal.signal(signal.SIGINT, self.signal_handler)

        # Handle unix sockets.
        if self.socket_uri.startswith("socket://"):
            # Get protocol.
            self.protocol = re.sub('^([^:]*):.*$', r'\1', self.socket_uri)
            # Get unix socket path.
            self.socket = re.sub('^socket://(.*)', r'\1', self.socket_uri)

            if not os.path.exists(self.socket):
                msg = (_("Unix socket does not exist: %s") % self.socket)
                raise OTPmeException(msg)

            # Create socket.
            try:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            except socket.error as msg:
                msg = (_("Failed to create socket. Error code: %s, Error "
                        "message: %s") % (msg[0], msg[1]))
                raise OTPmeException(msg)

        # Handle TCP sockets.
        elif self.socket_uri.startswith("tcp://"):
            # Get protocol.
            self.protocol = re.sub('^([^:]*):.*$', r'\1', self.socket_uri)
            # Get listen address.
            self.address = re.sub('^%s://([^:]*):([0-9]*)$' % self.protocol,
                                    r'\1',
                                    self.socket_uri)
            # Get listen port.
            self.port = int(re.sub('^%s://([^:]*):([0-9]*)$' % self.protocol,
                                    r'\2',
                                    self.socket_uri))
            # Set socket tuple.
            self.socket = (self.address, self.port)

            # Create socket.
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error as msg:
                msg = (_("Failed to create socket. Error code: %s, Error "
                        "message: %s") % (msg[0], msg[1]))
                raise OTPmeException(msg)

            # Create SSL socket if requested.
            if self.use_ssl and cert and key:
                from otpme.lib.pki.cert import SSLCert
                # Encrypt cert private key with password.
                self.key_pass = stuff.gen_secret(len=32)
                self.key_pass = self.key_pass.encode("ascii")
                _cert = SSLCert(key=key)
                key = _cert.encrypt_key(passphrase=self.key_pass)

                # Temp file paths.
                self.cert_file = "%s/%s-cert.pem" % (config.tmp_dir,
                                                stuff.gen_secret(len=32))
                self.key_file = "%s/%s-key.pem" % (config.tmp_dir,
                                                stuff.gen_secret(len=32))
                self.ca_data_file = "%s/%s-ca_data.pem" % (config.tmp_dir,
                                                stuff.gen_secret(len=32))

                # Build dict with all temp files to create.
                tmp_files = {}
                tmp_files[self.cert_file] = cert
                tmp_files[self.key_file] = key
                if verify_server:
                    tmp_files[self.ca_data_file] = ca_data

                # Create all needed temp files.
                for tmp_file in tmp_files:
                    file_content = tmp_files[tmp_file]
                    # Try to create file.
                    if os.path.exists(tmp_file):
                        msg = ("Cert file '%s' exists, removing." % tmp_file)
                        self.logger.warning(msg)

                    # Create file.
                    fd = open(tmp_file, "w")

                    # Set permissions.
                    filetools.set_fs_permissions(path=tmp_file,
                                                mode=0o660,
                                                recursive=False)
                    # Write file content.
                    file_content = str(file_content)
                    fd.write(file_content)
                    fd.close()

            if self.use_ssl:
                # Create default SSL context.
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                # FIXME: Is this all we need to enable PFS with python 2.7??
                # Enable PFS.
                # http://jderose.blogspot.de/2014/01/how-to-enable-perfect-forward-secrecy.html
                ctx.set_ecdh_curve('prime256v1')

                # Verify server certificate and CRL.
                if verify_server:
                    # FIXME: do we want to enable hostname checks?
                    # Disable hostname checks.
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_REQUIRED
                    ctx.verify_flags = ssl.VERIFY_CRL_CHECK_CHAIN
                    ctx.load_verify_locations(cafile=self.ca_data_file,
                                            capath=None, cadata=None)
                else:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                # Load client certificate.
                if self.cert_file and self.key_file:
                    ctx.load_cert_chain(certfile=self.cert_file,
                                        keyfile=self.key_file,
                                        password=self.key_pass)

                # Add SSL socket.
                self._socket = ctx.wrap_socket(self._socket,
                                            server_side=False,
                                            do_handshake_on_connect=True,
                                            suppress_ragged_eofs=True,
                                            server_hostname=None)
                self.remove_cert_files()

        # Set blocking mode.
        self.set_blocking()
        # Init socket handler
        if socket_handler is None:
            self.socket_handler = None
        else:
            self.socket_handler = socket_handler("client", self._socket)

    def __getattr__(self, name):
        """ Map to original methods. """
        return getattr(self._socket, name)

    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        self.remove_cert_files()
        # Return control to original signal handler.
        signal.signal(signal.SIGINT, self.org_sigint_handler)
        signal.signal(signal.SIGINT, self.org_sigterm_handler)

    def connect(self, timeout=15, connect_timeout=3, quiet=False, **kwargs):
        """ Connect to remote socket and read first packet. """
        if self.connected:
            msg = "Already connected: %s" % self.socket_uri
            raise AlreadyConnected(msg)
        if timeout is None:
            timeout_msg = "None"
        else:
            timeout_msg = "%ss" % timeout
        if connect_timeout is None:
            connect_timeout_msg = "None"
        else:
            connect_timeout_msg = "%ss" % connect_timeout

        if not quiet:
            msg = ("Connecting to '%s' (tmo=%s/%s)"
                % (self.socket_uri, connect_timeout_msg, timeout_msg))
            self.logger.debug(msg)

        try:
            # Set connect timeout.
            self.set_timeout(connect_timeout)
            # Try to connect.
            self._socket.connect(self.socket)
            # Set connection timeout.
            self.set_timeout(timeout)
            self.connected = True
        except Exception as e:
            #config.raise_exception()
            msg = (_("Error connecting to '%s': %s") % (self.socket_uri, e))
            raise OTPmeException(msg)

        if self.use_ssl:
            # Set cert info of peer.
            self.peer_cert = self._socket.getpeercert()

        try:
            data = self.recv(timeout=timeout)
        except Exception as e:
            self._close()
            msg = (_("Error receiving data from '%s': %s")
                    % (self.socket_uri, e))
            config.raise_exception()
            raise OTPmeException(msg)

        return data

    def set_blocking(self, blocking=None):
        """ Set blocking mode. """
        if blocking is None:
            blocking = self.blocking
        if blocking:
            self._socket.setblocking(1)
        else:
            self._socket.setblocking(0)

    def set_timeout(self, timeout):
        """ Set socket timeout. """
        # If timeout is None we do not change the current timeout.
        if timeout is None:
            return
        # settimeout() requires None for no timeout.
        if timeout == 0:
            timeout = None
        # Set timeout.
        self._socket.settimeout(timeout)

    def send(self, data, blocking=None, timeout=None, **kwargs):
        """ Send data. """
        try:
            # Set socket stuff.
            self.set_blocking(blocking)
            self.set_timeout(timeout)
            if self.socket_handler:
                # Send quit command without any encoding.
                if data == "quit":
                    return self.socket_handler.raw_send(data=data)
                else:
                    return self.socket_handler.send(data=data)
            else:
                try:
                    return self._socket.send(data)
                except socket.timeout as e:
                    self._close()
                    raise ConnectionTimeout(_("Connection timed out."))
        except ConnectionQuit as e:
            self._close()
            raise ConnectionQuit(e)
        except Exception as e:
            self._close()
            msg = (_("Error sending data: %s") % e)
            raise OTPmeException(msg)

    def sendall(self, data, blocking=None, timeout=None, **kwargs):
        """ Send data. """
        try:
            # Set socket stuff.
            self.set_blocking(blocking)
            self.set_timeout(timeout)
            if self.socket_handler:
                return self.socket_handler.sendall(data=data)
            else:
                try:
                    return self._socket.sendall(data)
                except socket.timeout as e:
                    self._close()
                    raise ConnectionTimeout(_("Connection timed out."))
        except ConnectionQuit as e:
            self._close()
            raise ConnectionQuit(e)
        except Exception as e:
            self._close()
            msg = (_("Error sending data: %s") % e)
            raise ConnectionError(msg)

    def recv(self, recv_buffer=4096, blocking=None, timeout=None, **kwargs):
        """ Receive data. """
        try:
            # Set socket stuff.
            self.set_blocking(blocking)
            self.set_timeout(timeout)
            if self.socket_handler:
                data = self.socket_handler.recv(recv_buffer=recv_buffer)
            else:
                try:
                    data = self._socket.recv(recv_buffer)
                except socket.timeout as e:
                    self._close()
                    raise ConnectionTimeout(_("Connection timed out."))
        except ConnectionTimeout as e:
            self._close()
            raise
        except ConnectionQuit as e:
            self._close()
            raise ConnectionQuit(e)
        except Exception as e:
            self._close()
            msg = (_("Error receiving data: %s") % e)
            config.raise_exception()
            raise ConnectionError(msg)
        return data

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

    def close(self):
        """ Close socket. """
        if not self.connected:
            return
        self.connected = False
        if config.debug_level() > 3:
            self.logger.debug("Closing connection to '%s'" % self.socket_uri)
        self.send("quit", timeout=0.01)
        self._close()

    def _close(self):
        """ Close socket. """
        self.connected = False
        # Shutdown socket.
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except IOError:
            pass
        # Close socket.
        self._socket.close()
        self.remove_cert_files()
