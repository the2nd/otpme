# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The daemon two sides of a remote access session meet at.

A host that was given a remote_access job connects here, and so does
whoever asked for the shell. Both name the job, and from then on this
daemon moves bytes between them and reads none of them -- what travels
is SSH, between the client and the host (see protocols/server/rac1.py).

Runs on the master node only, like idled, and is started by clusterd
when this node takes the role. Both sides are told to meet at the
floating IP, so a failover does not have to be told to anybody: the
address follows the role.

Connections are handled in threads and not in processes: the two sides
of a meeting have to find each other, and they only do that in one
memory.
"""
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import log
from otpme.lib import config
from otpme.lib import rendezvous
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("racd")


class RacDaemon(OTPmeDaemon):
    """ Remote access daemon. """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Handle new connections in process: the two sides of a meeting
        # find each other in the rendezvous point, which lives here.
        self.conn_handling = "threading"
        self.rendezvous_point = rendezvous.RendezvousPoint()

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # Set max client connections. Two per session, and a session
        # lasts as long as somebody works in it.
        self.max_conn = self.get_max_conn("racd_max_conn")
        # FIXME: where to configure socket banner?
        # set socket banner.
        self.socket_banner = f"{status_codes.OK} {self.full_name} {config.my_version}"

        # Disable interactive policies (e.g. reauth).
        if "interactive" not in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Do default startup (e.g. drop privileges, listen on sockets etc.).
        handler_args = {'rendezvous_point':self.rendezvous_point}
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
                    # Check for config changes.
                    restart = self.configure()
                    if restart:
                        break
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in racd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
