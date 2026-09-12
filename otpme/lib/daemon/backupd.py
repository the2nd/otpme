# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import signal
import setproctitle
from datetime import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import log
from otpme.lib import config
from otpme.lib import script
from otpme.lib import backend
from otpme.lib.mail import send_mail
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = ['otpme.lib.classes.unit']

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("backupd")
    register_config_params()
    # Backup reports of backup_report_mode=summary. The backups run in
    # child processes, so we need a shared dict to collect their reports.
    multiprocessing.register_shared_dict("backup_reports")

def register_config_params():
    object_types = [
                        'site',
                        'unit',
                        'share',
                        'node',
                    ]
    def script_setter(script_path, **kwargs):
        if config.auth_token:
            if not config.auth_token.is_admin():
                msg = _("You must be admin to set <backup_script>.")
                raise OTPmeException(msg)
        result = backend.search(object_type="script",
                                attribute="rel_path",
                                value=script_path,
                                return_type="uuid")
        if not result:
            msg = _("Unknown script: {script_path}")
            msg = msg.format(script_path=script_path)
            raise UnknownObject(msg)
        script_uuid = result[0]
        return script_uuid
    def script_getter(script_uuid, **kwargs):
        result = backend.search(object_type="script",
                                attribute="uuid",
                                value=script_uuid,
                                return_type="rel_path")
        if not result:
            msg = _("Unknown script: {script_uuid}")
            msg = msg.format(script_uuid=script_uuid)
            raise UnknownObject(msg)
        script_path = result[0]
        return script_path
    # Default scripts unit.
    scripts_unit = config.get_default_unit("script")
    # Default mount script to add to new shares.
    backup_script = f"{scripts_unit}/backup_script.sh"
    config.register_config_parameter(name="backup_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=backup_script,
                                    object_types=object_types)

class BackupDaemon(OTPmeDaemon):
    """ BackupDaemon """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
        return super().signal_handler(_signal, frame)

    def set_proctitle(self, backup_object):
        """ Set proctitle to contain backup object. """
        if config.use_api:
            return
        proctitle = setproctitle.getproctitle()
        new_proctitle ="{proctitle} Backup: {backup_object}"
        new_proctitle = new_proctitle.format(proctitle=proctitle,
                                            backup_object=backup_object)
        setproctitle.setproctitle(new_proctitle)

    def in_backup_window(self, now, start_time, end_time):
        try:
            start_time = datetime.strptime(start_time, "%H:%M").time()
        except ValueError as err:
            msg = "Invalid start time."
            raise ValueError(msg) from err

        try:
            end_time = datetime.strptime(end_time, "%H:%M").time()
        except ValueError as err:
            msg = "Invalid end time."
            raise ValueError(msg) from err

        #now = datetime.now().time()

        if start_time <= end_time:
            in_window = start_time <= now <= end_time
        else:
            # Window spans midnight, e.g. 23:00 - 03:00
            in_window = now >= start_time or now <= end_time
        return in_window

    def send_backup_report(self, backup_object, status, subject, result):
        """ Send backup report. """
        backup_report_enabled = backup_object.get_config_parameter("backup_report_enabled")
        if not backup_report_enabled:
            return
        backup_report_mode = backup_object.get_config_parameter("backup_report_mode")
        if backup_report_mode:
            if backup_report_mode == "success":
                if status is not True:
                    return
            if backup_report_mode == "error":
                if status is not False:
                    return
            if backup_report_mode == "summary":
                # One report for all backups. It is sent by the daemon
                # process when the last backup has finished.
                return self.queue_backup_report(backup_object, status, result)
        mail_settings = self.get_mail_settings(backup_object)
        if not mail_settings:
            return False
        message = "\n".join(result['log'])
        return self.send_report_mail(mail_settings, subject, message)

    def queue_backup_report(self, backup_object, status, result):
        """ Add backup report to be sent with the summary report. """
        mail_to = backup_object.get_config_parameter("backup_report_mail_to")
        if not mail_to:
            log_msg = _("Cannot send backup report: backup_report_mail_to not configured.", log=True)[1]
            self.logger.warning(log_msg)
            return False
        report_name = f"{backup_object.type}/{backup_object.name}"
        report = {
                'uuid'          : backup_object.uuid,
                'name'          : report_name,
                'mail_to'       : mail_to,
                'status'        : status,
                'time'          : time.time(),
                'duration'      : result.get('duration'),
                'total_bytes'   : result.get('total_bytes'),
                'stored_bytes'  : result.get('stored_bytes'),
                }
        if not status:
            # Without counters the report line has to tell why.
            report['message'] = result['log'][-1]
        multiprocessing.backup_reports[report_name] = report
        return True

    def process_backup_reports(self):
        """ Send summary report when all backups have finished. """
        reports = dict(multiprocessing.backup_reports)
        if not reports:
            return
        for x_uuid in dict(self.backup_childs):
            backup_child = self.backup_childs[x_uuid]
            if backup_child.is_alive():
                return
        queued_reports = []
        for x in reports:
            try:
                x_report = multiprocessing.backup_reports.pop(x)
            except KeyError:
                continue
            queued_reports.append(x_report)
        self.send_summary_report(queued_reports)

    def send_summary_report(self, reports):
        """ Send one report for all finished backups. """
        from otpme.lib.classes.backup import _format_size
        # Backup objects may have different report receivers.
        reports_by_mail_to = {}
        for x_report in reports:
            x_mail_to = x_report['mail_to']
            if x_mail_to not in reports_by_mail_to:
                reports_by_mail_to[x_mail_to] = []
            reports_by_mail_to[x_mail_to].append(x_report)
        host_name = config.host_data['name']
        for x_mail_to in reports_by_mail_to:
            x_reports = reports_by_mail_to[x_mail_to]
            x_reports = sorted(x_reports, key=lambda report: report['time'])
            # The mail settings (e.g. relay) of the receiver are the ones
            # of the first backup object that reports to it.
            first_report = x_reports[0]
            backup_object = backend.get_object(uuid=first_report['uuid'])
            if not backup_object:
                log_msg = _("Cannot send backup report: Unknown object: {name}", log=True)[1]
                log_msg = log_msg.format(name=first_report['name'])
                self.logger.warning(log_msg)
                continue
            mail_settings = self.get_mail_settings(backup_object)
            if not mail_settings:
                continue
            # The receiver is the one the backups reported to, not the one
            # the object is configured with right now.
            mail_settings['mail_to'] = x_mail_to
            failed_backups = 0
            successful_backups = 0
            message = []
            for x_report in x_reports:
                if x_report['status']:
                    successful_backups += 1
                    x_status = "ok"
                else:
                    failed_backups += 1
                    x_status = "failed"
                x_duration = x_report['duration']
                if not x_duration:
                    x_duration = "-"
                x_info = x_report.get('message')
                if not x_info:
                    x_total = _format_size(x_report['total_bytes'] or 0)
                    x_stored = _format_size(x_report['stored_bytes'] or 0)
                    x_info = f"{x_total} -> {x_stored}"
                x_line = f"{x_report['name']:<20} {x_status:<8} {x_duration:<10} {x_info}"
                message.append(x_line)
            message = "\n".join(message)
            subject = _("Backup report {host_name} ({successful} ok, {failed} failed)")
            subject = subject.format(host_name=host_name,
                                    successful=successful_backups,
                                    failed=failed_backups)
            self.send_report_mail(mail_settings, subject, message)

    def get_mail_settings(self, backup_object):
        """ Get mail settings to send a backup report. """
        server = backup_object.get_config_parameter("smtp_relay_server")
        if not server:
            log_msg = _("Cannot send backup report: smtp_relay_server not configured.", log=True)[1]
            self.logger.warning(log_msg)
            return False
        mail_from = backup_object.get_config_parameter("backup_report_mail_from")
        if not mail_from:
            log_msg = _("Cannot send backup report: backup_report_mail_from not configured.", log=True)[1]
            self.logger.warning(log_msg)
            return False
        mail_to = backup_object.get_config_parameter("backup_report_mail_to")
        if not mail_to:
            log_msg = _("Cannot send backup report: backup_report_mail_to not configured.", log=True)[1]
            self.logger.warning(log_msg)
            return False
        port = backup_object.get_config_parameter("smtp_relay_port")
        if port is None:
            port = 25
        starttls = backup_object.get_config_parameter("smtp_relay_starttls")
        if starttls is None:
            starttls = False
        smtp_auth = backup_object.get_config_parameter("smtp_relay_auth")
        if smtp_auth is None:
            smtp_auth = False
        username = None
        password = None
        if smtp_auth:
            username = backup_object.get_config_parameter("smtp_relay_username")
            if username is None:
                log_msg = _("Cannot send backup report: smtp_relay_auth configured without smtp_relay_username.", log=True)[1]
                self.logger.warning(log_msg)
                return False
            password = backup_object.get_config_parameter("smtp_relay_password")
            if password is None:
                log_msg = _("Cannot send backup report: smtp_relay_auth configured without smtp_relay_password.", log=True)[1]
                self.logger.warning(log_msg)
                return False
        mail_settings = {
                        'server'    : server,
                        'port'      : port,
                        'starttls'  : starttls,
                        'username'  : username,
                        'password'  : password,
                        'mail_from' : mail_from,
                        'mail_to'   : mail_to,
                        }
        return mail_settings

    def send_report_mail(self, mail_settings, subject, message):
        """ Send backup report mail. """
        try:
            send_mail(mail_from=mail_settings['mail_from'],
                    mail_to=mail_settings['mail_to'],
                    subject=subject,
                    message=message,
                    server=mail_settings['server'],
                    port=mail_settings['port'],
                    starttls=mail_settings['starttls'],
                    username=mail_settings['username'],
                    password=mail_settings['password'])
        except Exception as e:
            log_msg = _("Failed to send backup report: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return False
        return True

    def process_backups(self):
        """ Check if we have to run a backup. """
        backup_objects = backend.search(object_types=["node", "share"],
                                        attribute="name",
                                        value="*",
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="oid")
        for x_oid in backup_objects:
            o = backend.get_object(x_oid)
            if not o:
                continue
            if not o.get_config_parameter("backup_enabled"):
                continue
            if o.type == "node":
                # Backup of node must be started on node.
                if o.uuid != config.uuid:
                    continue
            elif o.type == "share":
                # No backups for restore shares.
                if o.restore_share:
                    continue
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
                log_msg = log_msg.format(backup_time=backup_time)
                self.logger.warning(log_msg)
                continue
            now = datetime.now().time()
            try:
                if not self.in_backup_window(now, start_time, end_time):
                    continue
            except ValueError as e:
                log_msg = str(e)
                self.logger.warning(log_msg)
                continue
            if o.last_backup:
                backup_age = time.time() - o.last_backup
                backup_interval = o.get_config_parameter("backup_interval")
                if not backup_interval:
                    backup_interval = "23h"
                try:
                    backup_interval = units.time2int(backup_interval, time_unit="s")
                except Exception:
                    log_msg = _("Invalid backup interval: {backup_interval}", log=True)[1]
                    log_msg = log_msg.format(backup_interval=backup_interval)
                    self.logger.warning(log_msg)
                    continue
                if backup_age < backup_interval:
                    # The interval holds off a second run within the same
                    # window, and only that. Where the last one started
                    # outside the window we have now it belonged to a
                    # different one -- someone moved backup_time for a
                    # while and a backup ran while it was moved. That one
                    # does not count against this window, so let the
                    # regular run happen even though the interval is not
                    # up yet.
                    last_backup = datetime.fromtimestamp(o.last_backup).time()
                    if self.in_backup_window(last_backup, start_time, end_time):
                        continue
            try:
                backup_child = self.backup_childs[o.uuid]
            except KeyError:
                pass
            else:
                if backup_child.is_alive():
                    continue
                try:
                    backup_child.join()
                except Exception:
                    pass
                try:
                    backup_child.close()
                except Exception:
                    pass
                self.backup_childs.pop(o.uuid)
            # Create child process that will do the backup.
            backup_child = multiprocessing.start_process(name=self.name,
                                                target=self.start_backup,
                                                target_args=(o,),
                                                hard_exit=True,
                                                join=True)
            self.backup_childs[o.uuid] = backup_child

    def run_backup_script(self, script_path, backup_object, hook):
        # Run backup script.
        variables = {
                    'backup_object' : backup_object,
                    'backup_hook'   : hook,
                }
        try:
            script_returncode, \
            script_stdout, \
            script_stderr, \
            script_pid = script.run(script_type="backup_script",
                                    script_path=script_path,
                                    variables=variables,
                                    verify_signatures=True,
                                    user="root",
                                    group="root",
                                    call=False)
            if script_returncode != 0:
                script_output = script_stdout + script_stderr
                log_msg = _("Failed to run backup script: {script_path}: {script_output}", log=True)[1]
                log_msg = log_msg.format(script_path=script_path, script_output=script_output)
                self.logger.warning(log_msg)
        except Exception as e:
            log_msg = _("Failed to run backup script: {script_path}: {e}", log=True)[1]
            log_msg = log_msg.format(script_path=script_path, e=e)
            self.logger.warning(log_msg)

    def start_backup(self, o):
        from otpme.lib.classes.command_handler import CommandHandler
        multiprocessing.atfork(exit_on_signal=True)
        backup_object = f"{o.type}/{o.name}"
        self.set_proctitle(backup_object)
        banner = f"{config.log_name}: {o.type}:{o.name}"
        self.logger = log.setup_logger(banner=banner, pid=True,
                                        existing_logger=config.logger)
        backup_object = f"{o.type}:{o.name}"
        backup_script = o.get_config_parameter("backup_script")
        if backup_script:
            self.run_backup_script(backup_script, backup_object, "pre")

        subject = _("Backup {status} {backup_object}")

        backup_start_time = time.time()
        command_handler = CommandHandler()
        try:
            result = command_handler.start_backup(backup_object, return_result=True)
        except Exception as e:
            log_msg = _("Failed to run backup: {backup_object}: {e}", log=True)[1]
            log_msg = log_msg.format(backup_object=backup_object, e=e)
            result = {'log':[log_msg]}
            subject = subject.format(status="failed", backup_object=backup_object)
            self.send_backup_report(backup_object=o,
                                    status=False,
                                    subject=subject,
                                    result=result)
            self.logger.warning(log_msg)
            multiprocessing.cleanup(keep_queues=True)
            sys.exit(1)
        finally:
            o.last_backup = backup_start_time
            o._write(update_last_modified=False,
                    update_last_modified_by=False)
        if backup_script:
            self.run_backup_script(backup_script, backup_object, "post")
        subject = subject.format(status="successful", backup_object=backup_object)
        self.send_backup_report(backup_object=o,
                                status=True,
                                subject=subject,
                                result=result)
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
        # Set max client connections.
        self.max_conn = self.get_max_conn("backupd_max_conn")
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
                recv_timeout = 10
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
                    raise OTPmeException(msg) from e

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
                # Check if we have to send a backup summary report.
                self.process_backup_reports()
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in backupd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
                config.raise_exception()
