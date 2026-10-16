# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import html
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
from otpme.lib import maintenance
from otpme.lib import connections
from otpme.lib.mail import send_mail
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = ['otpme.lib.classes.unit']

# A backup that finds the repository in somebody else's hands (another
# backup, a restore, a repack) has not failed: the very same attempt
# works once that is done. So it waits and tries again -- how long and
# how often comes from the backup_retry_interval and backup_retry_count
# parameters of the object. These are what an object that has neither
# gets: a realm created before they existed has no value for them, and
# the default of a parameter is written to a site when the site is made.
DEFAULT_BACKUP_RETRY_INTERVAL = 300
DEFAULT_BACKUP_RETRY_COUNT = 12

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
        # Whether backups wait for our site to leave maintenance, see
        # process_backups().
        self._maintenance_paused = False

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

    def get_backup_retry_settings(self, o):
        """ How long and how often to wait for a busy repository.

        Whatever cannot be read falls back to the default, with a word in
        the log: a value nobody can make sense of must not decide that a
        backup is given up on.
        """
        retry_interval = o.get_config_parameter("backup_retry_interval")
        if not retry_interval:
            retry_interval = DEFAULT_BACKUP_RETRY_INTERVAL
        try:
            # A string ("5m") on the way out of the parameter getter.
            retry_interval = units.time2int(retry_interval, time_unit="s")
        except Exception:
            log_msg = _("Invalid backup retry interval: {retry_interval}", log=True)[1]
            log_msg = log_msg.format(retry_interval=retry_interval)
            self.logger.warning(log_msg)
            retry_interval = DEFAULT_BACKUP_RETRY_INTERVAL
        retry_count = o.get_config_parameter("backup_retry_count")
        if retry_count is None:
            retry_count = DEFAULT_BACKUP_RETRY_COUNT
        try:
            retry_count = int(retry_count)
        except Exception:
            log_msg = _("Invalid backup retry count: {retry_count}", log=True)[1]
            log_msg = log_msg.format(retry_count=retry_count)
            self.logger.warning(log_msg)
            retry_count = DEFAULT_BACKUP_RETRY_COUNT
        return retry_interval, retry_count

    def in_backup_window_now(self, o):
        """ Whether a backup of this object may start right now.

        The window says when a backup may start, and process_backups()
        asks that before it starts one. This is the same question asked
        again from the backup itself, before it waits for a repository
        somebody else holds: a retry hours later would belong to a
        window that is long over.

        Anything it cannot read is a no. The value got this far, so
        process_backups() has read it already and said what is wrong
        with it.
        """
        backup_time = o.get_config_parameter("backup_time")
        if not backup_time:
            return False
        try:
            start_time = backup_time.split("-")[0]
            end_time = backup_time.split("-")[1]
        except Exception:
            return False
        try:
            return self.in_backup_window(datetime.now().time(),
                                        start_time, end_time)
        except ValueError:
            return False

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
                'file_count'    : result.get('file_count'),
                'skipped_files' : result.get('skipped_files'),
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
            html_message = self.build_summary_report_html(host_name,
                                                        x_reports,
                                                        successful_backups,
                                                        failed_backups)
            self.send_report_mail(mail_settings, subject, message,
                                html_message=html_message)

    def build_summary_report_html(self, host_name, reports, successful, failed):
        """ The summary report as HTML, failed backups in red.

        Inline styles only: many mail clients drop a <style> block. The
        plain text version goes along with it for those that show no
        HTML at all. """
        from otpme.lib.classes.backup import _format_size
        red = "#c62828"
        green = "#2e7d32"
        cell = "padding:6px 10px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;"
        head_cell = f"{cell}background:#f5f5f5;font-weight:bold;"
        rows = []
        for x_report in reports:
            if x_report['status']:
                x_status = _("ok")
                row_style = ""
                status_style = f"color:{green};font-weight:bold;"
            else:
                x_status = _("failed")
                row_style = "background:#fdecea;"
                status_style = f"color:{red};font-weight:bold;"
            x_finished = datetime.fromtimestamp(x_report['time'])
            x_finished = x_finished.strftime("%Y-%m-%d %H:%M")
            x_duration = x_report['duration'] or "-"
            x_files = "-"
            if x_report.get('file_count') is not None:
                x_files = str(x_report['file_count'])
                if x_report.get('skipped_files'):
                    x_skipped = _("{skipped} skipped")
                    x_skipped = x_skipped.format(skipped=x_report['skipped_files'])
                    x_files = f"{x_files} ({x_skipped})"
            x_info = x_report.get('message')
            if x_info:
                x_info = f'<span style="color:{red};">{html.escape(x_info)}</span>'
            else:
                x_total = _format_size(x_report['total_bytes'] or 0)
                x_stored = _format_size(x_report['stored_bytes'] or 0)
                x_info = html.escape(f"{x_total} → {x_stored}")
            rows.append(f'<tr style="{row_style}">'
                        f'<td style="{cell}">{html.escape(x_report["name"])}</td>'
                        f'<td style="{cell}{status_style}">{html.escape(x_status)}</td>'
                        f'<td style="{cell}white-space:nowrap;">{html.escape(x_finished)}</td>'
                        f'<td style="{cell}white-space:nowrap;">{html.escape(x_duration)}</td>'
                        f'<td style="{cell}">{html.escape(x_files)}</td>'
                        f'<td style="{cell}">{x_info}</td>'
                        '</tr>')
        title = _("Backup report {host_name}")
        title = title.format(host_name=host_name)
        successful_text = _("{count} ok")
        successful_text = html.escape(successful_text.format(count=successful))
        failed_text = _("{count} failed")
        failed_text = html.escape(failed_text.format(count=failed))
        counts = (f'<span style="color:{green};font-weight:bold;">'
                    f'{successful_text}</span> &middot; ')
        if failed:
            counts += (f'<span style="color:{red};font-weight:bold;">'
                        f'{failed_text}</span>')
        else:
            counts += failed_text
        columns = [_("Backup"), _("Status"), _("Finished"), _("Duration"),
                    _("Files"), _("Size / Error")]
        header = "".join(f'<th style="{head_cell}">{html.escape(x)}</th>'
                        for x in columns)
        return ('<!DOCTYPE html>'
                '<html><head><meta charset="utf-8"></head>'
                '<body style="margin:0;padding:16px;font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222;">'
                f'<h2 style="margin:0 0 4px 0;font-size:18px;">{html.escape(title)}</h2>'
                f'<p style="margin:0 0 16px 0;">{counts}</p>'
                '<table style="border-collapse:collapse;border:1px solid #e0e0e0;">'
                f'<thead><tr>{header}</tr></thead>'
                f'<tbody>{"".join(rows)}</tbody>'
                '</table>'
                '</body></html>')

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

    def send_report_mail(self, mail_settings, subject, message,
        html_message=None):
        """ Send backup report mail. """
        try:
            send_mail(mail_from=mail_settings['mail_from'],
                    mail_to=mail_settings['mail_to'],
                    subject=subject,
                    message=message,
                    html_message=html_message,
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
        # A backup ends by storing its time on the object, which is not
        # written while our site is in maintenance. It would be due again
        # right away and run over and over. Running backups end as they
        # are; the next ones start after it.
        if maintenance.is_active():
            if not self._maintenance_paused:
                log_msg = _("Site is in maintenance, not starting backups.", log=True)[1]
                self.logger.info(log_msg)
                self._maintenance_paused = True
            return
        if self._maintenance_paused:
            log_msg = _("Site is out of maintenance, starting backups again.", log=True)[1]
            self.logger.info(log_msg)
            self._maintenance_paused = False
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

        command_handler = CommandHandler()
        retry_interval, retry_count = self.get_backup_retry_settings(o)
        failed = None
        attempt = 0
        while True:
            attempt += 1
            backup_start_time = time.time()
            try:
                result = command_handler.start_backup(backup_object,
                                                    return_result=True)
            except ObjectLocked as e:
                # Somebody else holds the repository: another backup, a
                # restore, a repack. Nothing of this backup has run, so
                # it is one to do later and not a failed one -- and
                # last_backup stays where it is, because it says when a
                # backup of this object ran and none did. Without that,
                # the backup interval would count this as the backup of
                # this window and the next one would be tomorrow.
                #
                # Only the repository lock says this (see the lock_repo
                # branch in protocols/server/backup1.py), so it cannot
                # be a retention that found the repository taken after a
                # backup that worked. Repeating that is not the same
                # thing as repeating the backup.
                if attempt <= retry_count \
                and self.in_backup_window_now(o):
                    log_msg = _("Backup repository is busy, trying again in {interval} seconds: {backup_object}: {error}", log=True)[1]
                    log_msg = log_msg.format(interval=retry_interval,
                                            backup_object=backup_object,
                                            error=e)
                    self.logger.info(log_msg)
                    # The repository is still open on the connection
                    # this attempt used, and the next attempt opens it
                    # again -- which the server refuses on a connection
                    # that holds it open already. So this one goes and
                    # the next attempt brings its own.
                    connections.close_connections()
                    time.sleep(BACKUP_RETRY_INTERVAL)
                    continue
                failed = _("Giving up on a busy backup repository after {attempt} attempts: {backup_object}: {error}", log=True)[1]
                failed = failed.format(attempt=attempt,
                                        backup_object=backup_object,
                                        error=e)
            except Exception as e:
                failed = _("Failed to run backup: {backup_object}: {e}", log=True)[1]
                failed = failed.format(backup_object=backup_object, e=e)
            break
        o.last_backup = backup_start_time
        try:
            o._write(update_last_modified=False,
                    update_last_modified_by=False)
        except MaintenanceMode as e:
            # The backup was made all the same, and is reported. The
            # next one runs earlier than it would have, that is all.
            log_msg = _("Cannot store time of last backup: {backup_object}: {e}", log=True)[1]
            log_msg = log_msg.format(backup_object=backup_object, e=e)
            self.logger.warning(log_msg)
        if failed:
            subject = subject.format(status="failed", backup_object=backup_object)
            self.send_backup_report(backup_object=o,
                                    status=False,
                                    subject=subject,
                                    result={'log':[failed]})
            self.logger.warning(failed)
            multiprocessing.cleanup(keep_queues=True)
            sys.exit(1)
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
