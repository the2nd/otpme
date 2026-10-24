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
        # Hosts keep a keyspace of their own. A user is reached by its
        # name and a host by its uuid, and the two must not meet in the
        # middle: a user named like a host would otherwise be handed
        # what the host was meant to hear.
        self.host_subscribers = {}
        self.host_data = {}

    def subscribe_host(self, host_uuid, host_data):
        """ A host that wants to be told when there is something for it.

        Keyed by uuid and not by name: a host is named within its site,
        the uuid is the thing that is one host and no other.
        """
        q = queue.Queue()
        with self.lock:
            self.host_subscribers.setdefault(host_uuid, []).append(q)
            self.host_data[host_uuid] = host_data
        return q

    def unsubscribe_host(self, host_uuid, q):
        with self.lock:
            try:
                self.host_subscribers[host_uuid].remove(q)
            except (KeyError, ValueError):
                pass
            if not self.host_subscribers.get(host_uuid):
                self.host_subscribers.pop(host_uuid, None)
                self.host_data.pop(host_uuid, None)

    def publish_host(self, host_uuid, event):
        """ Tell a host. Returns how many of its connections heard it.

        Zero is an answer and not an error: a host that is not here
        picks the news up on its next round, which is what it did
        before anybody was told anything.
        """
        with self.lock:
            queues = list(self.host_subscribers.get(host_uuid, ()))
        told = 0
        for q in queues:
            try:
                q.put_nowait(copy.deepcopy(event))
                told += 1
            except Exception:
                pass
        return told

    def get_host_data(self):
        with self.lock:
            return copy.deepcopy(self.host_data)

    def subscribe(self, username, host, login_data):
        """ A user's agent that waits for events.

        The login data is kept per connection: a user can wait from
        two sessions on one host, and the end of one must not take the
        host out of who while the other still waits.
        """
        q = queue.Queue()
        with self.lock:
            self.subscribers.setdefault(username, []).append(q)
            user_hosts = self.login_data.setdefault(username, {})
            user_hosts.setdefault(host, {})[id(q)] = login_data
        return q

    def unsubscribe(self, username, q, host):
        with self.lock:
            try:
                self.subscribers[username].remove(q)
                if not self.subscribers[username]:
                    del self.subscribers[username]
            except (KeyError, ValueError):
                pass
            user_hosts = self.login_data.get(username, {})
            host_connections = user_hosts.get(host, {})
            host_connections.pop(id(q), None)
            if not host_connections:
                user_hosts.pop(host, None)
            # The user, once no connection of it is left: message counts
            # the users it finds here.
            if not user_hosts:
                self.login_data.pop(username, None)

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
        """ {user: {host: login data}}, one entry per user and host.

        Of a user waiting from several connections on one host the one
        that came last, the way who shows it.
        """
        result = {}
        with self.lock:
            for username, user_hosts in self.login_data.items():
                for host, host_connections in user_hosts.items():
                    if not host_connections:
                        continue
                    last = list(host_connections.values())[-1]
                    result.setdefault(username, {})[host] = copy.deepcopy(last)
        return result

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
