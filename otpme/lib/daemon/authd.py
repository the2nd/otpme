# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("authd")

class AuthDaemon(OTPmeDaemon):
    """ AuthDaemon """
    def __init__(self, *args, **kwargs):
        self.last_session_outdate = 0
        super(AuthDaemon, self).__init__(*args, **kwargs)

    def outdate_sessions(self):
        now = time.time()
        outdate_age = now - self.last_session_outdate
        if outdate_age < 300:
            return
        self.last_session_outdate = time.time()
        all_sessions = backend.get_sessions(return_type="instance")
        for session in all_sessions:
            session.exists(outdate=True)

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # FIXME: where to configure max_conn?
        # Set max client connections.
        self.max_conn = 100
        # FIXME: where to configure socket banner?
        # set socket banner.
        self.socket_banner = ("%s %s %s"
                            % (status_codes.OK,
                            self.full_name,
                            config.my_version))

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Add default connection handler.
        try:
            self.set_connection_handler()
        except Exception as e:
            msg = "Failed to set connection handler: %s" % e
            self.logger.critical(msg)

        # Add authd unix socket.
        self.socket_path = config.authd_socket_path
        try:
            self.add_socket(self.socket_path,
                            handler=self.conn_handler,
                            banner=self.socket_banner,
                            user=self.user,
                            group=self.group,
                            mode=0o666)
        except Exception as e:
            msg = "Failed to add unix socket: %s" % e
            self.logger.critical(msg)

        # Do default startup (e.g. drop privileges, listen on sockets etc.).
        self.default_startup()

        # Run in loop unitl we get a signal.
        while True:
            try:
                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv()
                #except TimeoutReached:
                #    time.sleep(0.001)
                #    continue
                except ExitOnSignal:
                    break
                except Exception as e:
                    msg = (_("Error receiving daemon message: %s") % e)
                    self.logger.critical(msg, exc_info=True)
                    raise OTPmeException(msg)

                # Check if command can be handled by parent class.
                try:
                    self._handle_daemon_command(sender, daemon_command, data)
                except UnknownCommand as e:
                    self.logger.warning(str(e))
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
                self.logger.critical("Unhandled error in authd: %s" % e)

            # Make sure outdated expired get removed.
            self.outdate_sessions()
