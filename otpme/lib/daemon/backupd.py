# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import signal
from datetime import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import log
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon
from otpme.lib.classes.command_handler import CommandHandler

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("backupd")

class BackupDaemon(OTPmeDaemon):
    """ BackupDaemon """
    def __init__(self, *args, **kwargs):
        super(BackupDaemon, self).__init__(*args, **kwargs)
        self.backup_childs = {}

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        if _signal != 15:
            return
        # Act only on our own PID.
        if os.getpid() != self.pid:
            return
        log_msg = _("Received SIGTERM.", log=True)[1]
        self.logger.info(log_msg)
        # Shutdown backup childs.
        self.shutdown_backup_childs()
        return super(BackupDaemon, self).signal_handler(_signal, frame)

    def in_backup_window(self, start_time, end_time):
        try:
            start_time = datetime.strptime(start_time, "%H:%M").time()
        except ValueError:
            msg = "Invalid start time."
            raise ValueError(msg)

        try:
            end_time = datetime.strptime(end_time, "%H:%M").time()
        except ValueError:
            msg = "Invalid end time."
            raise ValueError(msg)

        now = datetime.now().time()

        if start_time <= end_time:
            in_window = start_time <= now <= end_time
        else:
            # Window spans midnight, e.g. 23:00 - 03:00
            in_window = now >= start_time or now <= end_time
        return in_window

    def process_backups(self):
        """ Check if we have to run a backup. """
        backup_enabled = backend.search(object_types=["node", "share"],
                                        attribute="backup_enabled",
                                        value=True,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="oid")
        backup_disabled = backend.search(object_types=["node", "share"],
                                        attribute="backup_enabled",
                                        value=False,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="oid")
        for x_oid in backup_enabled:
            if x_oid in backup_disabled:
                continue
            o = backend.get_object(x_oid)
            if o.type == "node":
                # Backup of node must be started on node.
                if o.uuid != config.uuid:
                    continue
            else:
                # Share backups only run on master node.
                if not config.master_node:
                    continue
            backup_time = o.get_config_parameter("backup_time")
            if not backup_time:
                log_msg = _("Not starting object without backup time: {o}", log=True)[1]
                log_msg = log_msg.format(o=x_oid)
                self.logger.warning(log_msg)
                continue
            try:
                start_time = backup_time.split("-")[0]
                end_time = backup_time.split("-")[1]
            except Exception:
                log_msg = _("Invalid backup time: {backup_time}", log=True)[1]
                log_msg = msg.format(backup_time=backup_time)
                self.logger.warning(log_msg)
                continue
            try:
                if not self.in_backup_window(start_time, end_time):
                    continue
            except ValueError as e:
                log_msg = str(e)
                self.logger.warning(log_msg)
                continue
            if o.last_backup:
                backup_age = time.time() - o.last_backup
                backup_interval = o.get_config_parameter("backup_interval")
                if not backup_interval:
                    backup_interval = "24h"
                try:
                    backup_interval = units.time2int(backup_interval, time_unit="s")
                except Exception:
                    log_msg = _("Invalid backup interval: {backup_interval}", log=True)[1]
                    log_msg = msg.format(backup_interval=backup_interval)
                    self.logger.warning(log_msg)
                    continue
                if backup_age < backup_interval:
                    continue
            try:
                backup_child = self.backup_childs[o.uuid]
            except KeyError:
                pass
            else:
                if backup_child.is_alive():
                    continue
                backup_child.join()
                backup_child.close()
                self.backup_childs.pop(o.uuid)
            # Create child process that will do the backup.
            backup_child = multiprocessing.start_process(name=self.name,
                                                target=self.start_backup,
                                                target_args=(o,),
                                                join=True)
            self.backup_childs[o.uuid] = backup_child

    def start_backup(self, o):
        multiprocessing.atfork(exit_on_signal=True)
        banner = f"{config.log_name}: {o.type}:{o.name}"
        self.logger = log.setup_logger(banner=banner, pid=True,
                                        existing_logger=config.logger)
        backup_start_time = time.time()
        backup_object = f"{o.type}:{o.name}"
        command_handler = CommandHandler()
        try:
            command_handler.start_backup(backup_object)
        except Exception as e:
            log_msg = _("Failed to run backup: {backup_object}: {e}", log=True)[1]
            log_msg = log_msg.format(backup_object=backup_object, e=e)
            self.logger.warning(log_msg)
            multiprocessing.cleanup(keep_queues=True)
            sys.exit(1)
        o.last_backup = backup_start_time
        o._write(update_last_modified=False,
                update_last_modified_by=False)
        multiprocessing.cleanup(keep_queues=True)
        sys.exit()

    def shutdown_backup_childs(self):
        """ Shutdown backup childs. """
        for x_uuid in self.backup_childs:
            backup_child = self.backup_childs[x_uuid]
            if backup_child.is_alive():
                # Send TERM signal to sync process.
                try:
                    backup_child.terminate()
                except OSError:
                    pass
            try:
                backup_child.join()
            except OSError:
                pass
            try:
                backup_child.close()
            except OSError:
                pass
            except ValueError:
                pass

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # FIXME: where to configure max_conn?
        # Set max client connections.
        self.max_conn = 256
        # FIXME: where to configure socket banner?
        # set socket banner.
        self.socket_banner = f"{status_codes.OK} {self.full_name} {config.my_version}"

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Add default connection handler.
        try:
            self.set_connection_handler()
        except Exception as e:
            log_msg = _("Failed to set connection handler: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Do default startup (e.g. listen on sockets etc.).
        listen = False
        if config.backup_server:
            listen = True
        self.default_startup(dont_drop_privileges=True, listen=listen)

        # Run in loop unitl we get a signal.
        while True:
            try:
                recv_timeout = 30
                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv(recv_timeout)
                except TimeoutReached:
                    daemon_command = None
                except ExitOnSignal:
                    break
                except Exception as e:
                    msg, log_msg = _("Error receiving daemon message: {error}", log=True)
                    msg = msg.format(error=e)
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg, exc_info=True)
                    raise OTPmeException(msg)

                # Check if command can be handled by parent class.
                if daemon_command:
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
                # Check if its backup time.
                self.process_backups()
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in backupd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
                config.raise_exception()
