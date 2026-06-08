# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import queue

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import backend

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-idle-1.0"

# Block time for a single q.get() call in the "wait" loop. On timeout we
# silently loop again (per design: no keepalive sent to the agent). The
# value bounds how quickly we notice connection shutdown / daemon stop.
WAIT_TIMEOUT = 3

def register():
    config.register_otpme_protocol("idled", PROTOCOL_VERSION, server=True)


class OTPmeIdleP1(OTPmeServer1):
    """ Class that implements OTPme-idle-1.0. """
    def __init__(self, dispatcher=None, **kwargs):
        # Our name.
        self.name = "idled"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Idled does not require any authentication on client connect.
        self.require_auth = None
        self.require_preauth = False
        # Instructs parent class to require a client certificate.
        self.require_client_cert = True
        # Idled only works on master node.
        self.require_master_node = True
        # We need a clean cluster status.
        self.require_cluster_status = True
        # No encryption for idled.
        self.encrypt_session = False
        self.logger = None
        self.dispatcher = dispatcher
        # Per-connection subscription state. The queue lives for the
        # lifetime of the TCP connection -- subscribed on first wait,
        # released in _close -- so events published between two
        # consecutive wait calls land in the queue instead of being
        # dropped on the floor while no q is registered.
        self.subscribed_username = None
        self.q = None
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        self.pid = os.getpid()

    def _close(self):
        """ Connection ending -- unsubscribe so the dispatcher stops
        accumulating events for a queue nobody will read. """
        if self.q is not None and self.subscribed_username:
            try:
                self.dispatcher.unsubscribe(self.subscribed_username,
                                            self.q, self.peer.name)
            except Exception:
                pass
        self.q = None
        self.subscribed_username = None

    def _process(self, command, command_args, **kwargs):
        """ Handle connections from otpme-agent and notify producers. """
        self.logger = config.logger

        valid_commands = ["wait", "notify", "who"]
        if command not in valid_commands:
            message = _("Unknown command: {command}")
            message = message.format(command=command)
            return self.build_response(False, message)

        if not config.use_api:
            try:
                self.check_cluster_status()
            except Exception as e:
                return self.build_response(status_codes.CLUSTER_NOT_READY,
                                           str(e))

        try:
            username = command_args['username']
        except Exception:
            username = None

        if command == "notify":
            return self._handle_notify(username, command_args)

        if command == "wait":
            try:
                login_token = command_args['login_token']
            except Exception:
                login_token = None
            try:
                login_time = command_args['login_time']
            except Exception:
                login_time = None
            return self._handle_wait(username, login_token, login_time)

        if command == "who":
            return self._handle_who(username)

    def _handle_notify(self, username, command_args):
        """ In-process fan-out: publish event to all subscriber queues of
        the given user. Producers call this via connections.get("idled")
        from share.add_token / add_role / remove_* etc. """
        if not self.peer.type == "node":
            return self.build_response(False, "Permission denied")
        if not username:
            return self.build_response(False, "Missing username")
        try:
            event_type = command_args['event_type']
        except KeyError:
            return self.build_response(False, "Missing event_type")
        event = {
            'event_type'    : event_type,
            'data'          : command_args.get('data', {}),
        }
        self.dispatcher.publish(username, event)
        return self.build_response(True, "ok")

    def _handle_wait(self, username, login_token, login_time):
        """ Long-poll: subscribe the calling agent to its user's queue
        and block until an event arrives. On timeout we loop silently
        (no keepalive frame). Returns one matching event per call; the
        agent is expected to re-issue 'wait' immediately after
        processing.

        The queue is allocated ONCE per connection and kept alive
        across consecutive wait calls (released in _close). Earlier
        the queue was subscribed/unsubscribed per call, so any
        publish hitting between two waits found no subscriber and got
        dropped. """
        if not username:
            return self.build_response(False, "Missing username")
        if self.q is None:
            host = self.peer.name
            login_data = {
                        'host'          : host,
                        'connect_time'  : time.time(),
                        'login_time'    : login_time,
                        'login_token'   : login_token,
                        }
            self.q = self.dispatcher.subscribe(username, host, login_data=login_data)
            self.subscribed_username = username
        elif self.subscribed_username != username:
            # Different username on same connection (shouldn't happen
            # in practice, but stay safe).
            self.dispatcher.unsubscribe(self.subscribed_username,
                                        self.q,  self.peer.name)
            self.q = self.dispatcher.subscribe(username)
            self.subscribed_username = username
        while True:
            try:
                event = self.q.get(timeout=WAIT_TIMEOUT)
            except queue.Empty:
                return self.build_response(False, "keepalive")
            except ExitOnSignal:
                return self.build_response(False, "shutdown")
            except Exception as e:
                log_msg = _("Error while waiting for idle event: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                return self.build_response(False, str(e))
            try:
                result = self.process_event(username, event)
            except Exception as e:
                log_msg = _("Failed to process event: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if result:
                return result

    def process_event(self, username, event):
        try:
            event_type = event['event_type']
        except KeyError:
            msg = _("Got event without event_type")
            raise OTPmeException(msg)

        if event_type == "share_unmount":
            try:
                shares = event['data']
            except KeyError:
                shares = None
            if not shares:
                msg = _("Got share unmount event without shares.")
                raise OTPmeException(msg)
            share_ids = ",".join(shares.keys())
            log_msg = _("Sending share unmount notification ({shares}) to {username} on host {host}", log=True)[1]
            log_msg = log_msg.format(shares=share_ids, username=username, host=self.peer.name)
            self.logger.info(log_msg)
            return self.build_response(True, event)

        elif event_type == "share_mount":
            try:
                shares = event['data']
            except KeyError:
                shares = None
            if not shares:
                msg = _("Got share mount event without shares.")
                raise OTPmeException(msg)
            for share_id in dict(shares):
                share = shares[share_id]
                try:
                    limit_hosts = share.pop('limit_hosts')
                except KeyError:
                    limit_hosts = False
                try:
                    share_hosts = share.pop('hosts')
                except KeyError:
                    share_hosts = []
                if not limit_hosts:
                    continue
                if self.peer.name in share_hosts:
                    continue
                shares.pop(share_id)
            if not shares:
                return False
            share_ids = ",".join(shares.keys())
            log_msg = _("Sending share mount notification ({shares}) to {username} on host {host}", log=True)[1]
            log_msg = log_msg.format(shares=share_ids, username=username, host=self.peer.name)
            self.logger.info(log_msg)
            return self.build_response(True, event)

        elif event_type == "share_add_host":
            try:
                shares = event['data']
            except KeyError:
                shares = None
            if not shares:
                msg = _("Got share mount event without shares.")
                raise OTPmeException(msg)
            for share_id in dict(shares):
                share = shares[share_id]
                try:
                    hosts = share.pop('hosts')
                except KeyError:
                    msg = _("Received share_add_host event without host information: {share}")
                    msg = msg.format(share=share_id)
                    raise OTPmeException(msg)
                if self.peer.name in hosts:
                    continue
                shares.pop(share_id)
            if not shares:
                return False
            share_ids = ",".join(shares.keys())
            log_msg = _("Sending share mount notification ({shares}) to {username} on host {host}", log=True)[1]
            log_msg = log_msg.format(shares=share_ids, username=username, host=self.peer.name)
            self.logger.info(log_msg)
            mount_event = {'event_type':'share_mount', 'data':shares}
            return self.build_response(True, mount_event)

        elif event_type == "share_remove_host":
            try:
                shares = event['data']
            except KeyError:
                shares = None
            if not shares:
                msg = _("Got share unmount event without shares.")
                raise OTPmeException(msg)
            for share_id in dict(shares):
                share = shares[share_id]
                try:
                    hosts = share.pop('hosts')
                except KeyError:
                    msg = _("Received share_remove_host event without host information: {share}")
                    msg = msg.format(share=share_id)
                    raise OTPmeException(msg)
                if self.peer.name not in hosts:
                    continue
                shares.pop(share_id)
            if not shares:
                return False
            share_ids = ",".join(shares.keys())
            log_msg = _("Sending share unmount notification ({shares}) to {username} on host {host}", log=True)[1]
            log_msg = log_msg.format(shares=share_ids, username=username, host=self.peer.name)
            self.logger.info(log_msg)
            mount_event = {'event_type':'share_unmount', 'data':shares}
            return self.build_response(True, mount_event)
        else:
            msg = _("Received invalid event: {event_type}")
            msg = msg.format(event_type=event_type)
            raise OTPmeException(msg)

    def _handle_who(self, username=None):
        """ Get online users. """
        own_site = backend.get_object(uuid=config.site_uuid)
        allow_who_from_hosts = own_site.get_config_parameter("allow_who_from_hosts")
        if not allow_who_from_hosts:
            if not self.peer.type == "node":
                return self.build_response(False, "Permission denied")
        login_data = self.dispatcher.get_login_data()
        if username:
            try:
                login_data = login_data[username]
            except Exception:
                login_data = _("Not logged in.")
        return self.build_response(True, login_data)
