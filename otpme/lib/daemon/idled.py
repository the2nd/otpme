# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import copy
import time
import queue
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import log
from otpme.lib import config
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("idled")

class _IdleDispatcher:
    """ Per-process subscriber registry: keeps a queue per active idled
    connection, fans out published events to all queues of a given user.
    All idled threads in one process share the module-level singleton."""

    def __init__(self):
        self.lock = threading.Lock()
        self.subscribers = {}
        self.login_data = {}

    def subscribe(self, username, host, login_data):
        q = queue.Queue()
        with self.lock:
            self.subscribers.setdefault(username, []).append(q)
            #self.login_data[username] = login_data
            self.login_data.setdefault(username, {}).setdefault(host, login_data)
        return q

    def unsubscribe(self, username, q, host):
        with self.lock:
            try:
                self.subscribers[username].remove(q)
                if not self.subscribers[username]:
                    del self.subscribers[username]
            except (KeyError, ValueError):
                pass
            try:
                self.login_data[username].pop(host)
                if not self.login_data[username]:
                    self.login_data[username].pop(username)
            except (KeyError, ValueError):
                pass

    def publish(self, username, event):
        # Deep-copy per subscriber: publish puts a separate object into
        # each queue so consumers can mutate their copy (the agent-side
        # share-handler pops fields like host_uuid as it processes)
        # without poisoning what the next consumer sees. With shared
        # references, a second wait for the same user would observe
        # the already-iterated-and-stripped dict.
        with self.lock:
            queues = list(self.subscribers.get(username, ()))
        for q in queues:
            try:
                q.put_nowait(copy.deepcopy(event))
            except Exception:
                pass

    def get_login_data(self):
        with self.lock:
            return copy.deepcopy(self.login_data)

class IdleDaemon(OTPmeDaemon):
    """ IdleDaemon """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Handle new connections in process.
        self.conn_handling = "threading"
        self.dispatcher = _IdleDispatcher()

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # Set max client connections.
        self.max_conn = self.get_max_conn("idled_max_conn")
        # FIXME: where to configure socket banner?
        # set socket banner.
        self.socket_banner = f"{status_codes.OK} {self.full_name} {config.my_version}"

        # Disable interactive policies (e.g. reauth).
        if "interactive" not in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Do default startup (e.g. drop privileges, listen on sockets etc.).
        handler_args = {'dispatcher':self.dispatcher}
        self.default_startup(handler_args=handler_args)

        # Run in loop unitl we get a signal.
        while True:
            try:
                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv()
                except TimeoutReached:
                    time.sleep(0.001)
                    continue
                except ExitOnSignal:
                    break
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
                    # FIXME: get reload command via network to reload on changes of own host?
                    # Check for config changes.
                    restart = self.configure()
                    if restart:
                        break
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in idled: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
