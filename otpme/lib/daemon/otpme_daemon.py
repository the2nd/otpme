# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import signal
import importlib
import setproctitle
# python3.
try:
    from imp import reload
except:
    try:
        from importlib import reload
    except:
        pass

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import log
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import multiprocessing
from otpme.lib.preload import preload_modules
from otpme.lib.socket.listen import ListenSocket
from otpme.lib.multiprocessing import drop_privileges
from otpme.lib.classes.conn_handler import ConnHandler
from otpme.lib.socket.handler import SocketProtoHandler

from otpme.lib.exceptions import *

class OTPmeDaemon(object):
    """ Init generic OTPmeDaemon """
    def __init__(self, name, user, group, **kwargs):
        # Set our name.
        self.name = name
        self.full_name = f"{config.my_name.lower()}-{self.name}"
        # Set user we should run as.
        self.user = user
        self.group = group
        # Interprocess communication.
        self.comm_handler = None
        # Will hold our listen addresses.
        self.listen_sockets = []
        # Will hold our cert and private key.
        self.cert = None
        self.key = None
        # Will hold CA cert chain and CRLs.
        self.ca_data = None
        # Inter-daemon communication timeout.
        self.daemon_msg_timeout = config.inter_daemon_comm_timeout
        # Our PID.
        self.pid = None
        # Our status file.
        self.status_file = config.get_daemon_status_file(self.name)
        self.should_run = True
        # Get logger.
        self.logger = config.logger
        # Will hold all sockets of this daemon.
        self.sockets = {}
        # Will hold the default connection handler.
        self.conn_handler = None

    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        # Do nothing for signals to child processes (connection, jobs...).
        if os.getpid() != self.pid:
            return True
        self.close()
        os._exit(0)

    def _send_local_daemon_msg(self, command, data=None, timeout=1):
        """ Send command to daemon itself. """
        try:
            self.comm_handler.send(recipient=self.name,
                                    command=command,
                                    data=data, timeout=timeout)
        except Exception as e:
            msg = _("Failed to send local daemon message: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)
        return

    def _handle_daemon_command(self, sender, command, data=None, timeout=1):
        """ Handle commands from protocol handler. """
        if command == "ping":
            self.comm_handler.send("controld", command="pong", timeout=timeout)
            return

        if command == "reload":
            msg = _("Received reload command.")
            self.__reload()
            raise DaemonReload(msg)

        if command == "quit":
            msg = _("Received quit command.")
            raise DaemonQuit(msg)

        msg = _("Received unknown daemon command: {command}")
        msg = msg.format(command=command)
        raise UnknownCommand(msg)

    def __reload(self):
        """ Daemon reload. """
        # Clear caches.
        try:
            cache.flush(quiet=False)
        except Exception as e:
            log_msg = _("Failed to flush caches on 'reload' command: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg, exc_info=True)
        try:
            cache.clear(quiet=False)
        except Exception as e:
            log_msg = _("Failed to clear caches on 'reload' command: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg, exc_info=True)

    def _preload_modules(self):
        """ Preload modules """
        if config.debug_level("module_loading") > 0:
            log_msg = _("Preloading modules...", log=True)[1]
            self.logger.debug(log_msg)
        count = 0
        for m in preload_modules:
            try:
                importlib.import_module(m)
                count += 1
            except Exception as e:
                log_msg = _("Failed to preload module: {module}: {error}", log=True)[1]
                log_msg = log_msg.format(module=m, error=e)
                self.logger.critical(log_msg, exc_info=True)
        if config.debug_level("module_loading") > 0:
            log_msg = _("Preloaded {count} modules...", log=True)[1]
            log_msg = log_msg.format(count=count)
            self.logger.debug(log_msg)

        if config.debug_level("module_loading") > 0:
            log_msg = _("Loading token modules...", log=True)[1]
            self.logger.debug(log_msg)
        # Preload token modules.
        from otpme.lib.token import utils
        try:
            utils.load_token_modules()
        except Exception as e:
            log_msg = _("Failed to preload token modules: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        if config.debug_level("module_loading") > 0:
            log_msg = _("Loading resolver modules...", log=True)[1]
            self.logger.debug(log_msg)
        # Preload resolver modules.
        from otpme.lib.resolver import utils
        try:
            utils.load_resolver_modules()
        except Exception as e:
            log_msg = _("Failed to preload resolver modules: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        if config.debug_level("module_loading") > 0:
            log_msg = _("Loading policy modules...", log=True)[1]
            self.logger.debug(log_msg)
        # Preload policy modules.
        from otpme.lib.policy import utils
        try:
            utils.load_policy_modules()
        except Exception as e:
            log_msg = _("Failed to preload policy modules: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        if config.debug_level("module_loading") > 0:
            log_msg = _("Loading protocol modules...", log=True)[1]
            self.logger.debug(log_msg)
        # Preload protocol modules.
        from otpme.lib.protocols import utils
        try:
            utils.load_protocol_modules()
        except Exception as e:
            log_msg = _("Failed to preload protocol modules: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Workaround to prevent problem with ldap3 module because twisted (used
        # by ldaptor) replaces the standard socket module.
        import socket
        reload(socket)

        from otpme.lib.extensions import utils
        utils.load_schemas()

    def configure(self):
        """ Make sure we are configured correctly. """
        # Enable file logging when going to background.
        if config.daemonize:
            config.file_logging = True
        if not config.debug_enabled:
            config.file_logging = True

        # Reload config to re-configure logger etc.
        try:
            config.reload(configure_logger=True)
        except Exception as e:
            log_msg = _("Failed to reload config: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        if self.name not in config.default_listen_ports:
            log_msg = _("No listen port configured for {name}", log=True)[1]
            log_msg = log_msg.format(name=self.full_name)
            self.logger.info(log_msg)
            return

        restart = False

        # Get listen port from config.
        try:
            listen_port = config.default_listen_ports[self.name]
        except:
            msg = _("Unable to get listen port from config: {name}")
            msg = msg.format(name=self.name)
            raise OTPmeException(msg)
        # Get listen addresses from config.
        if config.site_address == "127.0.0.1":
            c_listen_sockets = f'127.0.0.1:{listen_port}'
            c_listen_sockets = [c_listen_sockets]
        else:
            try:
                c_listen_sockets = list(config.listen_sockets[self.name])
            except:
                c_listen_sockets = f'0.0.0.0:{listen_port}'
                c_listen_sockets = [c_listen_sockets]

        if self.cert:
            if self.cert != config.host_data['cert']:
                log_msg = _("Certificate changed.", log=True)[1]
                self.logger.info(log_msg)
                restart = True
        else:
            self.cert = config.host_data['cert']

        if self.key:
            if self.key != config.host_data['key']:
                log_msg = _("Private key changed.", log=True)[1]
                self.logger.info(log_msg)
                restart = True
        else:
            self.key = config.host_data['key']

        if self.ca_data:
            if self.ca_data != config.host_data['ca_data']:
                log_msg = _("CA certificate chain or CRLs changed.", log=True)[1]
                self.logger.info(log_msg)
                restart = True
        else:
            self.ca_data = config.host_data['ca_data']

        if config.host_data['type'] == "node":
            result = backend.search(object_type="site",
                                    attribute="name",
                                    value=config.site,
                                    realm=config.realm,
                                    return_type="instance")
            site = result[0]
            site_listen_socket = f"{site.address}:{listen_port}"
            found_listen_on_any = False
            for x in c_listen_sockets:
                if "0.0.0.0:" not in x:
                    continue
                found_listen_on_any = True
                break
            if not found_listen_on_any:
                if site_listen_socket not in c_listen_sockets:
                    c_listen_sockets.append(site_listen_socket)

        if self.listen_sockets:
            for socket_uri in c_listen_sockets:
                if socket_uri in self.listen_sockets:
                    continue
                log_msg = _("Listen address changed.", log=True)[1]
                self.logger.info(log_msg)
                restart = True
                break

        self.listen_sockets = c_listen_sockets

        if restart:
            log_msg = _("Configuration changed. Going down for reload.", log=True)[1]
            self.logger.info(log_msg)
            # Inform controld that we need a restart to reload our config.
            self.comm_handler.send(recipient="controld",
                                command="reload_shutdown",
                                timeout=1)
        return restart

    def set_connection_handler(self, handler_args={}):
        """ Set default connection handler. """
        # Get handler to receive messages from  connection processes.
        child_name = f"{self.name}-connection"
        comm_handler = self.comm_handler.get_child(child_name)
        handler_args['comm_handler'] = comm_handler
        # Create handler for the new socket.
        self.conn_handler = ConnHandler(protocols=self.protocols,
                                            **handler_args)

    def setup_sockets(self, use_ssl=True, ssl_verify_client=True):
        """ Setup sockets. """
        for x in self.listen_sockets:
            address = x.split(":")[0]
            port = x.split(":")[1]
            # Set listen socket URI.
            socket_uri = f"tcp://{address}:{port}"
            # Add sync socket.
            self.add_socket(socket_uri,
                            handler=self.conn_handler,
                            banner=self.socket_banner,
                            user=self.user,
                            group=self.group,
                            use_ssl=use_ssl,
                            ssl_cert=self.cert,
                            ssl_key=self.key,
                            ssl_ca_data=self.ca_data,
                            ssl_verify_client=ssl_verify_client,
                            max_conn=self.max_conn)

    def listen(self):
        """ Start listening on sockets. """
        for s in self.sockets:
            try:
                s.listen()
            except Exception as e:
                log_msg = _("Unable to listen on socket: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)

    def default_startup(self, use_ssl=True, ssl_verify_client=True,
        handler_args={}, dont_drop_privileges=False):
        """ Do default daemon startup stuff. """
        # Set connection handler.
        try:
            self.set_connection_handler(handler_args=handler_args)
        except Exception as e:
            log_msg = _("Failed to set connection handler: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # Setup sockets.
        try:
            self.setup_sockets(use_ssl=use_ssl, ssl_verify_client=ssl_verify_client)
        except Exception as e:
            log_msg = _("Failed to setup sockets: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # We can drop privileges AFTER sockets are created. This is needed when
        # listening to well known ports (<1024), which requires root privileges.
        if not dont_drop_privileges:
            try:
                self.drop_privileges()
            except Exception as e:
                log_msg = _("Failed to drop privileges: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
        # Start listening on sockets.
        try:
            self.listen()
        except Exception as e:
            log_msg = _("Failed to listen on sockets: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # Some logging.
        log_msg = _("{full_name} started", log=True)[1]
        log_msg = log_msg.format(full_name=self.full_name)
        self.logger.info(log_msg)
        # Notify controld that we are ready.
        try:
            self.comm_handler.send(recipient="controld", command="ready", timeout=1)
        except Exception as e:
            log_msg = _("Failed to notify controld about daemon startup: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

    def drop_privileges(self):
        """ Drop privileges. """
        drop_privileges(self.user, self.group)

    def run(self, comm_handler, **kwargs):
        """ Run daemon. """
        # Handle multiprocessing stuff.
        multiprocessing.atfork(quiet=True)
        # Set daemon name.
        config.daemon_name = self.name
        # Set queue for parent daemon communication.
        self.comm_handler = comm_handler
        # Override singal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        # Set daemon status.
        config.daemon_status = "running"
        # Our PID.
        self.pid = os.getpid()
        # Update logger with new PID and daemon name.
        log_banner = f"{self.full_name}:"
        # Setup logger.
        self.logger = log.setup_logger(banner=log_banner, pid=self.pid)
        # Set process title.
        try:
            setproctitle.setproctitle(self.full_name)
        except Exception as e:
            log_msg = _("Failed to set proctitle: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # Preload some other modules.
        try:
            self._preload_modules()
        except Exception as e:
            log_msg = _("Failed to preload modules: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # Run child class method.
        try:
            self._run(**kwargs)
        finally:
            self.close()
        os._exit(0)

    def add_socket(self, socket_uri, handler, **kwargs):
        """ Add new socket. """
        # Create new listen socket instance.
        new_socket  = ListenSocket(name=self.name,
                                socket_uri=socket_uri,
                                connection_handler=handler,
                                socket_handler=SocketProtoHandler,
                                **kwargs)
        # Append new socket to list of daemon sockets.
        try:
            socket_data = self.sockets[new_socket]
        except:
            socket_data = {}
        self.sockets[new_socket] = socket_data
        # Return new socket.
        return new_socket

    def close_sockets(self):
        """ Close listen sockets. """
        for sock in self.sockets:
            sock.close()

    def cleanup(self):
        """ Should be overridden in child class. """
        pass

    def close(self):
        """ End daemon. """
        self.should_run = False
        # Close all connections.
        self.close_sockets()
        # Cleanup locks etc.
        multiprocessing.cleanup()
        # Run child class cleanup.
        self.cleanup()
        #log_msg = _("Notifying controld that we got down.", log=True)[1]
        #self.logger.info(log_msg)
        ## Confirm shutdown.
        #self.comm_handler.send(recipient="controld", command="down", timeout=1)
        self.comm_handler.close()
        if os.path.exists(self.status_file):
            os.remove(self.status_file)
