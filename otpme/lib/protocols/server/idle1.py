# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import queue

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-idle-1.0"

# Block time for a single q.get() call in the "wait" loop. On timeout we
# silently loop again (per design: no keepalive sent to the agent). The
# value bounds how quickly we notice connection shutdown / daemon stop.
WAIT_TIMEOUT = 30

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
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        self.pid = os.getpid()

    def _process(self, command, command_args, **kwargs):
        """ Handle connections from otpme-agent and notify producers. """
        self.logger = config.logger

        valid_commands = ["wait", "notify"]
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
            return self._handle_wait(username)

    def _handle_notify(self, username, command_args):
        """ In-process fan-out: publish event to all subscriber queues of
        the given user. Producers call this via connections.get("idled")
        from share.add_token / add_role / remove_* etc. """
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

    def _handle_wait(self, username):
        """ Long-poll: subscribe the calling agent to its user's queue and
        block until an event arrives. On timeout we loop silently (no
        keepalive frame is sent). Returns one event per call; the agent is
        expected to re-issue 'wait' immediately after processing it. """
        if not username:
            return self.build_response(False, "Missing username")
        q = self.dispatcher.subscribe(username)
        try:
            while True:
                try:
                    event = q.get(timeout=WAIT_TIMEOUT)
                    return self.build_response(True, event)
                except queue.Empty:
                    continue
                except ExitOnSignal:
                    return self.build_response(False, "shutdown")
                except Exception as e:
                    log_msg = _("Error while waiting for idle event: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
                    return self.build_response(False, str(e))
        finally:
            self.dispatcher.unsubscribe(username, q)
