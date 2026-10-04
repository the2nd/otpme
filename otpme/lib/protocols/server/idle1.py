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
        # The host this connection waits for, where it is a host that
        # waits. One connection is one or the other, never both.
        self.subscribed_host = None
        self.q = None
        # Session of connected user.
        self.session = None
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
        if self.q is not None and self.subscribed_host:
            try:
                self.dispatcher.unsubscribe_host(self.subscribed_host,
                                                self.q)
            except Exception:
                pass
        self.q = None
        self.subscribed_username = None
        self.subscribed_host = None

    def _process(self, command, command_args, **kwargs):
        """ Handle connections from otpme-agent and notify producers. """
        self.logger = config.logger

        valid_commands = ["wait", "notify", "who",
                        "host_wait", "host_notify", "host_who"]
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
            try:
                session_uuid = command_args['session_uuid']
            except Exception:
                session_uuid = None
            try:
                version = command_args['version']
            except Exception:
                version = None
            return self._handle_wait(username, login_token, login_time, session_uuid, version)

        if command == "who":
            return self._handle_who(username)

        if command == "host_wait":
            return self._handle_host_wait()

        if command == "host_notify":
            return self._handle_host_notify(command_args)

        if command == "host_who":
            return self._handle_host_who(command_args.get('host'))

    def _handle_notify(self, username, command_args):
        """ In-process fan-out: publish event to all subscriber queues of
        the given user. Producers call this via connections.get("idled")
        from share.add_token / add_role / remove_* etc. """
        if not self.peer.type == "node":
            return self.build_response(False, "Permission denied")
        # Bind to our own site/realm: idled coordinates share events for
        # this site's users and its producers are same-site nodes. A
        # foreign-site node (whose cert still chains to the realm CA) must
        # not be able to inject events into local users' agents.
        if self.peer.realm_uuid != config.realm_uuid \
        or self.peer.site_uuid != config.site_uuid:
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

    def _handle_host_wait(self):
        """ Long-poll for a host: tell it when there is something for it.

        What a host is told is never more than "look now". Everything
        that decides whether it may do anything is checked where it was
        always checked -- the job is fetched from syncd and verified
        against the signers the host holds. So a message that reached
        the wrong host, or reached one twice, costs a look and nothing
        else.

        Which host is asking comes from its certificate and not from
        anything it says: this connection has no user authentication,
        and a name a client writes into a request is signed by nobody.
        """
        if self.peer is None:
            return self.build_response(False, "Who are you?")
        if self.peer.type not in ("host", "node"):
            return self.build_response(False, "Permission denied")
        # Bound to our own site, like every other thing idled does: a
        # host of a site we trust does not wait here for its jobs.
        if self.peer.realm_uuid != config.realm_uuid \
        or self.peer.site_uuid != config.site_uuid:
            return self.build_response(False, "Permission denied")
        host_uuid = self.peer.uuid
        if self.q is None:
            host_data = {
                        'host'          : self.peer.name,
                        'type'          : self.peer.type,
                        'connect_time'  : time.time(),
                        'client_ip'     : self.client,
                        }
            self.q = self.dispatcher.subscribe_host(host_uuid,
                                                host_data=host_data)
            self.subscribed_host = host_uuid
        while True:
            try:
                event = self.q.get(timeout=WAIT_TIMEOUT)
            except queue.Empty:
                # The host asks again right away. Said rather than left
                # silent so a host can tell a live connection from one
                # that died on the way.
                return self.build_response(False, "keepalive")
            except ExitOnSignal:
                return self.build_response(False, "shutdown")
            except Exception as e:
                log_msg = _("Error while waiting for host event: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                return self.build_response(False, str(e))
            return self.build_response(True, event)

    def _handle_host_notify(self, command_args):
        """ Tell one host that there is something for it.

        Sent by a node, which is where the job was made. The answer
        says how many of the host's connections heard it, and zero is
        an answer: a host that is not here picks the news up on its
        next round.
        """
        if not self.peer.type == "node":
            return self.build_response(False, "Permission denied")
        if self.peer.realm_uuid != config.realm_uuid \
        or self.peer.site_uuid != config.site_uuid:
            return self.build_response(False, "Permission denied")
        host_uuid = command_args.get('host_uuid')
        if not host_uuid:
            return self.build_response(False, "Missing host_uuid")
        event_type = command_args.get('event_type')
        if not event_type:
            return self.build_response(False, "Missing event_type")
        event = {
                'event_type'    : event_type,
                'data'          : command_args.get('data', {}),
                }
        told = self.dispatcher.publish_host(host_uuid, event)
        return self.build_response(True, told)

    def _handle_host_who(self, host=None):
        """ The hosts that are here, waiting to be told something.

        Read the way "who" is read, and fenced the same way: only from
        a node of our own site, unless the site says otherwise.
        """
        own_site = backend.get_object(uuid=config.site_uuid)
        allow_who_from_hosts = own_site.get_config_parameter("allow_who_from_hosts")
        if not allow_who_from_hosts:
            if not self.peer.type == "node":
                return self.build_response(False, "Permission denied")
        if self.peer.realm_uuid != config.realm_uuid \
        or self.peer.site_uuid != config.site_uuid:
            return self.build_response(False, "Permission denied")
        host_data = self.dispatcher.get_host_data()
        if host:
            host_data = {x:host_data[x] for x in host_data
                        if host_data[x].get('host') == host}
        return self.build_response(True, host_data)

    def _handle_wait(self, username, login_token, login_time, session_uuid, version):
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
        if session_uuid:
            return_attributes = ['session_id']
            result = backend.search(object_type="session",
                                        attribute="uuid",
                                        value=session_uuid,
                                        return_attributes=return_attributes,
                                        return_type="uuid")
            if result:
                self.session = result[0]
        else:
            self.session = None
        if self.q is None:
            host = self.peer.name
            login_data = {
                        'host'          : host,
                        'connect_time'  : time.time(),
                        'login_time'    : login_time,
                        'login_token'   : login_token,
                        'client_ip'     : self.client,
                        'session'       : self.session,
                        'version'       : version,
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
            # Dont notify clients without session.
            if not self.session:
                continue
            try:
                result = self.process_event(username, login_token, event)
            except Exception as e:
                log_msg = _("Failed to process event: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue
            if result:
                return result

    def process_event(self, username, login_token, event):
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
            for share_id in dict(shares):
                share = shares[share_id]
                try:
                    tokens = share['tokens']
                except KeyError:
                    msg = _("Got share unmount event without tokens.")
                    raise OTPmeException(msg)
                if login_token in tokens:
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
                    tokens = share['tokens']
                except KeyError:
                    msg = _("Got share mount event without tokens.")
                    raise OTPmeException(msg)
                if login_token in tokens:
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
                msg = _("Got share_add_host event without shares.")
                raise OTPmeException(msg)
            for share_id in dict(shares):
                share = shares[share_id]
                try:
                    tokens = share['tokens']
                except KeyError:
                    msg = _("Got share_add_host event without tokens.")
                    raise OTPmeException(msg)
                if login_token in tokens:
                    try:
                        limit_hosts = share.pop('limit_hosts')
                    except KeyError:
                        limit_hosts = False
                    if not limit_hosts:
                        continue
                    try:
                        host = share.pop('host')
                        found_host = True
                    except KeyError:
                        found_host = False
                        host = None
                    try:
                        hosts = share.pop('hosts')
                        found_hosts = True
                    except KeyError:
                        hosts = []
                        found_hosts = False
                    if not found_host and not found_hosts:
                        msg = _("Received share_add_host event without host information: {share}")
                        msg = msg.format(share=share_id)
                        raise OTPmeException(msg)
                    if found_host:
                        if self.peer.name == host:
                            continue
                    if found_hosts:
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
                msg = _("Got share_remove_host event without shares.")
                raise OTPmeException(msg)
            for share_id in dict(shares):
                share = shares[share_id]
                try:
                    tokens = share['tokens']
                except KeyError:
                    msg = _("Got share_remove_host event without tokens.")
                    raise OTPmeException(msg)
                if login_token in tokens:
                    try:
                        limit_hosts = share.pop('limit_hosts')
                    except KeyError:
                        limit_hosts = False
                    if not limit_hosts:
                        continue
                    try:
                        host = share.pop('host')
                        found_host = True
                    except KeyError:
                        host = None
                        found_host = False
                    try:
                        hosts = share.pop('hosts')
                        found_hosts = True
                    except KeyError:
                        found_hosts = False
                        hosts = []
                    if not found_host and not found_hosts:
                        msg = _("Received share_remove_host event without host information: {share}")
                        msg = msg.format(share=share_id)
                        raise OTPmeException(msg)
                    if found_host:
                        if self.peer.name == host:
                            continue
                    if found_hosts:
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
        # Scope to our own site/realm: the presence map (login_token,
        # client_ip, ...) belongs to this site's users. A foreign-site peer
        # must not enumerate it.
        if self.peer.realm_uuid != config.realm_uuid \
        or self.peer.site_uuid != config.site_uuid:
            return self.build_response(False, "Permission denied")
        login_data = self.dispatcher.get_login_data()
        if username:
            try:
                login_data = login_data[username]
            except Exception:
                login_data = _("Not logged in.")
        return self.build_response(True, login_data)
