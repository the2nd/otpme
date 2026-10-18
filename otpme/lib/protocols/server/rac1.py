# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Bringing the two sides of a remote access session together.

A remote_access job names a host and an SSH public key. The host
connects here and so does whoever asked for the shell; both say which
job they are here for, and from then on this daemon moves bytes between
them and reads none of them.

What travels is SSH, between the client and the host, so this daemon
carries the session without being able to listen to it or to speak into
it. Both sides connect out, which is why a host behind a firewall can
be reached at all.

The connection stops being an OTPme connection at the "meet" command:
the answer to it is the last thing spoken in this protocol, and
everything after it is the session. The handler says so by raising
ConnectionHijacked, which is what keeps the connection handler from
writing a closing frame into the middle of somebody else's protocol.

Who may take part is not decided here. The host only shows up for a job
whose signature it has verified against its own signers, and whoever
cannot answer the SSH authentication of the host gets nothing out of
the meeting but a closed connection. This daemon knows a key and two
sockets.
"""
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import rendezvous

from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-rac-1.0"

def register():
    config.register_otpme_protocol("racd", PROTOCOL_VERSION, server=True)


class OTPmeRacP1(OTPmeServer1):
    """ Class that implements OTPme-rac-1.0. """
    def __init__(self, rendezvous_point=None, **kwargs):
        # Our name.
        self.name = "racd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Both sides show who they are with their certificate. What that
        # buys is not permission -- the host verified the job itself and
        # the SSH authentication decides the rest -- but it keeps the
        # meeting among members of the realm.
        self.require_auth = None
        self.require_preauth = False
        self.require_client_cert = True
        # Only the master node holds the floating IP, and that is the
        # address both sides are told to meet at.
        self.require_master_node = True
        self.require_cluster_status = True
        # A disabled host or node meets here like any other. Being let
        # in on it is the very thing otpme-shell is for -- somebody has
        # to look at a host that was switched off -- and nothing here
        # gives permission: the job was verified on the host, and SSH
        # decides who gets the shell.
        self.check_peer_disabled = False
        # What travels through here is SSH, which brings its own. A
        # session key on top would be encryption of ciphertext.
        self.encrypt_session = False
        self.logger = None
        self.rendezvous_point = rendezvous_point
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        self.pid = os.getpid()

    def _process(self, command, command_args, **kwargs):
        """ Handle the one command this protocol has. """
        self.logger = config.logger

        if command != "meet":
            message = _("Unknown command: {command}")
            message = message.format(command=command)
            return self.build_response(False, message)

        if not config.use_api:
            try:
                self.check_cluster_status()
            except Exception as e:
                return self.build_response(status_codes.CLUSTER_NOT_READY,
                                        str(e))

        key = command_args.get('key')
        role = command_args.get('role')

        def go_ahead():
            """ The last thing said in this protocol. """
            response = self.build_response(True, "go ahead")
            self.connection.send(response,
                                timeout=config.connection_timeout)
            log_msg = _("Remote access session: {role} arrived for {key}.", log=True)[1]
            log_msg = log_msg.format(role=role, key=key)
            self.logger.info(log_msg)

        # Who is holding the master failover off. This protocol asks
        # for no user authentication -- the host shows up for a job it
        # verified itself, and the client answers to the SSH server of
        # the host, so neither proves anything to us here. What we do
        # know is the certificate the connection was made with, and
        # that is what goes in. Who wanted the shell is written on the
        # job: "otpme-deploy show <key>" names the user who signed it.
        blocked_by = "unknown"
        if config.auth_token:
            blocked_by = config.auth_token.rel_path
        elif self.peer:
            blocked_by = self.peer.oid.read_oid

        try:
            sent, received = rendezvous.meet(point=self.rendezvous_point,
                                            key=key,
                                            role=role,
                                            sock=self.connection.connection,
                                            go_ahead=go_ahead,
                                            blocked_by=blocked_by)
        except ConnectionHijacked as e:
            # The go ahead is out and the far end is speaking SSH by
            # now, so there is nothing to answer with any more.
            log_msg = _("Remote access session failed: {key}: {error}", log=True)[1]
            log_msg = log_msg.format(key=key, error=e)
            self.logger.warning(log_msg)
            raise
        except OTPmeException as e:
            # Nothing was let through yet, so this can still be said.
            return self.build_response(False, str(e))

        log_msg = _("Remote access session over: {key} ({sent} sent, {received} received).", log=True)[1]
        log_msg = log_msg.format(key=key, sent=sent, received=received)
        self.logger.info(log_msg)
        msg = _("Session over: {key}")
        msg = msg.format(key=key)
        raise ConnectionHijacked(msg)
