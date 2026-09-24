# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The daemon that runs configuration management jobs on a host.

It asks its site for the jobs meant for this host, checks each one
against the signers the host holds for that job type, has it run, and
sends back what came of it. It is the only OTPme daemon that keeps root
privileges -- installing a package or writing a file below /etc needs
them -- which is also why it is a daemon of its own and not another
task inside hostd, which runs as the otpme user.

A job does not run in this process. It is handed to a runner of its own
(otpme-confd-job), started as a transient systemd service, and this
daemon only looks for what the runner leaves behind. Two reasons:
a long job would otherwise block the daemon loop until controld calls
it dead, and a job that restarts OTPme would take its own runner down
with it and never finish -- the transient service is a child of PID 1,
so it outlives the restart and its result is picked up afterwards.

Nothing is run twice: a job that has been run leaves a marker behind
(<spool_dir>/confd/done/<job uuid>), and the marker is written before
the result is sent. A result that got lost on the way is sent again,
the job is not run again.

The whole output of a run stays here (<log_dir>/confd/<job uuid>.log,
root only); what travels to the nodes is the tail of it.
"""
import os
import time
import shutil
import subprocess
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import log
from otpme.lib import json
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import connections
from otpme.lib.audit import emit_audit
from otpme.lib.confd import job as confd_job
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

# How often we ask for jobs.
JOB_CHECK_INTERVAL = 60
# How often we look for the result of a job that is running. A job may
# be over in a second, and its result should not wait a minute for the
# next round.
RESULT_CHECK_INTERVAL = 1
# How often the master node removes old jobs and results (conf_job_max_age).
# Jobs are kept for months, so once an hour is plenty.
CLEANUP_INTERVAL = 3600
# The inventory of the host (system and packages) is looked at every
# round, but the nodes are only asked when it changed here -- or after
# this long, in case what they hold changed on their side.
INVENTORY_CHECK_INTERVAL = 3600
# The command that runs one job, and the transient service it runs as.
RUNNER_COMMAND = "otpme-confd-job"
RUNNER_UNIT_PREFIX = "otpme-confd-job"
# How many lines of the journal of a service go into the result when its
# runner is gone without one.
UNIT_LOG_LINES = 50
# How long a log file of a finished job is kept here.
LOG_MAX_AGE = 90 * 86400
# How long a marker of a job that has been run is kept. Longer than a
# job may live on the nodes (conf_job_max_age), so a job cannot come back
# after its marker is gone.
DONE_MAX_AGE = 90 * 86400
# What stands in the marker of a refusal that goes away by itself, so a
# restart can tell the two kinds apart. An empty marker is the old kind:
# we said no, and we only look again when our signers change.
RETRY_MARKER = "retry"

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("confd")

def get_done_dir():
    """ Where the markers of jobs we ran go. """
    return confd_job.get_spool_dir("done")

def get_refused_dir():
    """ Where the markers of jobs we refused and said so go. """
    return confd_job.get_spool_dir("refused")

def get_started_dir():
    """ Where the markers of jobs we handed to a runner go. """
    return confd_job.get_spool_dir("started")

def get_results_dir():
    """ Where the runners leave what came of their jobs. """
    return confd_job.get_spool_dir("results")

def get_log_dir():
    """ Where the whole output of a run goes. """
    return confd_job.get_log_dir()

class ConfDaemon(OTPmeDaemon):
    """ ConfDaemon. """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # We ask for jobs, nobody asks us: no listen socket.
        self.job_check_interval = JOB_CHECK_INTERVAL
        self.result_check_interval = RESULT_CHECK_INTERVAL
        self.cleanup_interval = CLEANUP_INTERVAL
        self.last_cleanup = 0.0
        # What the nodes last confirmed about our inventory, and when.
        self.inventory_check_interval = INVENTORY_CHECK_INTERVAL
        self.reported_inventory = None
        self.last_inventory_check = 0.0
        # What we ran, and what we refused and said so about, read from
        # the markers on startup.
        self.done_jobs = []
        self.refused_jobs = []
        # The refusals that go away by themselves: a job that names an
        # object we have not synced yet. Reported like any other, so
        # whoever made the job can see why nothing happened, but still
        # asked for every round -- see get_jobs().
        self.retry_jobs = []
        # The job a runner is busy with. Only one at a time: two package
        # managers on one host wait for each other at best.
        self.running_job = None
        # When the signers of this host last changed. A job we refused
        # for want of a signer is worth another look after that, see
        # signers_changed().
        self.signers_mtime = None

    def set_proctitle(self):
        """ Set proctitle. """
        new_proctitle = f"{self.full_name}"
        setproctitle.setproctitle(new_proctitle)

    def read_done_jobs(self):
        """ The jobs we have run, from the markers on disk.

        Markers are what keeps a job from being run twice, so they are
        read from disk rather than kept in memory alone -- a restart
        must not forget them. """
        done_dir = get_done_dir()
        if not os.path.exists(done_dir):
            return []
        done_jobs = []
        now = time.time()
        for x_job in filetools.list_dir(done_dir):
            x_file = os.path.join(done_dir, x_job)
            try:
                x_age = now - os.path.getmtime(x_file)
            except OSError:
                continue
            if x_age > DONE_MAX_AGE:
                try:
                    os.remove(x_file)
                except OSError as e:
                    log_msg = _("Failed to remove job marker: {file}: {e}", log=True)[1]
                    log_msg = log_msg.format(file=x_file, e=e)
                    self.logger.warning(log_msg)
                continue
            done_jobs.append(x_job)
        return done_jobs

    def add_done_job(self, job_uuid):
        """ Note that we ran a job, before its result goes out. """
        done_dir = get_done_dir()
        if not os.path.exists(done_dir):
            filetools.create_dir(done_dir, mode=0o700, user="root", group="root")
        marker_file = os.path.join(done_dir, job_uuid)
        filetools.touch(marker_file, mode=0o600, user="root", group="root")
        if job_uuid not in self.done_jobs:
            self.done_jobs.append(job_uuid)

    def read_refused_jobs(self):
        """ The jobs whose refusal we have reported.

        Returns all of them, and those we go on asking for. A marker
        holding RETRY_MARKER is one of the latter, and it survives a
        restart like every other marker: what we already said must not
        be said again.
        """
        refused_dir = get_refused_dir()
        if not os.path.exists(refused_dir):
            return [], []
        refused_jobs = []
        retry_jobs = []
        now = time.time()
        for x_job in filetools.list_dir(refused_dir):
            x_file = os.path.join(refused_dir, x_job)
            try:
                x_age = now - os.path.getmtime(x_file)
            except OSError:
                continue
            if x_age > DONE_MAX_AGE:
                try:
                    os.remove(x_file)
                except OSError as e:
                    log_msg = _("Failed to remove job marker: {file}: {e}", log=True)[1]
                    log_msg = log_msg.format(file=x_file, e=e)
                    self.logger.warning(log_msg)
                continue
            refused_jobs.append(x_job)
            try:
                marker_content = filetools.read_file(x_file)
            except Exception:
                marker_content = ""
            if marker_content.strip() == RETRY_MARKER:
                retry_jobs.append(x_job)
        return refused_jobs, retry_jobs

    def add_refused_job(self, job_uuid, retry=False):
        """ Note that we told the nodes about a refusal.

        <retry> for a refusal whose reason goes away by itself. Such a
        job stays out of the known jobs we send, so the nodes go on
        offering it, while the marker keeps us from reporting the same
        refusal once a minute.
        """
        refused_dir = get_refused_dir()
        if not os.path.exists(refused_dir):
            filetools.create_dir(refused_dir, mode=0o700,
                                user="root", group="root")
        marker_file = os.path.join(refused_dir, job_uuid)
        # Written, not touched, in both cases: touching a marker that is
        # there already leaves what is in it, and an old RETRY_MARKER
        # would then outlive the refusal it belonged to.
        marker_content = RETRY_MARKER if retry else ""
        filetools.create_file(marker_file,
                            content=marker_content,
                            mode=0o600,
                            user="root",
                            group="root")
        if job_uuid not in self.refused_jobs:
            self.refused_jobs.append(job_uuid)
        if retry:
            if job_uuid not in self.retry_jobs:
                self.retry_jobs.append(job_uuid)
        elif job_uuid in self.retry_jobs:
            self.retry_jobs.remove(job_uuid)

    def del_refused_job(self, job_uuid):
        """ Forget a refusal, because the job runs after all. """
        if job_uuid in self.refused_jobs:
            self.refused_jobs.remove(job_uuid)
        if job_uuid in self.retry_jobs:
            self.retry_jobs.remove(job_uuid)
        marker_file = os.path.join(get_refused_dir(), job_uuid)
        if not os.path.exists(marker_file):
            return
        try:
            os.remove(marker_file)
        except OSError as e:
            log_msg = _("Failed to remove job marker: {file}: {e}", log=True)[1]
            log_msg = log_msg.format(file=marker_file, e=e)
            self.logger.warning(log_msg)

    def get_started_file(self, job_uuid):
        """ The marker that says a runner has the job. """
        return os.path.join(get_started_dir(), job_uuid)

    def add_started_job(self, job_uuid, unit=None, pid=None):
        """ Note that a job was handed to a runner, before it is.

        Written first, not after the run: a job that restarts OTPme
        takes this daemon with it while its runner keeps going, and a
        marker written afterwards would never be written at all -- the
        job would be handed out again on the next round, and again, and
        the host would restart itself forever. """
        started_file = self.get_started_file(job_uuid)
        started_info = {
                    'started'   : time.time(),
                    'unit'      : unit,
                    'pid'       : pid,
                    }
        filetools.create_file(path=started_file,
                            content=json.encode(started_info),
                            user="root",
                            group="root",
                            mode=0o600)

    def read_started_job(self, job_uuid):
        """ What we noted when the job was handed out. """
        started_file = self.get_started_file(job_uuid)
        if not os.path.exists(started_file):
            return None
        try:
            with open(started_file, "r") as fd:
                return json.decode(fd.read())
        except Exception as e:
            log_msg = _("Failed to read job marker: {file}: {e}", log=True)[1]
            log_msg = log_msg.format(file=started_file, e=e)
            self.logger.warning(log_msg)
            return {}

    def del_started_job(self, job_uuid):
        """ Forget that a runner had the job: it is finished. """
        if self.running_job == job_uuid:
            self.running_job = None
        for x_file in [self.get_started_file(job_uuid),
                        confd_job.get_job_file(job_uuid)]:
            if not os.path.exists(x_file):
                continue
            try:
                os.remove(x_file)
            except OSError as e:
                log_msg = _("Failed to remove job file: {file}: {e}", log=True)[1]
                log_msg = log_msg.format(file=x_file, e=e)
                self.logger.warning(log_msg)

    def get_started_jobs(self):
        """ The jobs we handed to a runner, from the markers on disk. """
        return filetools.list_dir(get_started_dir())

    def have_systemd(self):
        """ Whether jobs can run as a transient service.

        Both halves are needed: a system that was booted by systemd, and
        the command to ask it for a service. """
        if not os.path.isdir("/run/systemd/system"):
            return False
        if not shutil.which("systemd-run"):
            return False
        return True

    def get_runner_unit(self, job_uuid):
        """ The name of the transient service of one job. """
        return f"{RUNNER_UNIT_PREFIX}-{job_uuid}.service"

    def runner_active(self, job_uuid):
        """ Whether the runner of this job is still at work.

        Asked about a job whose marker is there but whose result is not:
        either it is still running, or it died on the way -- and those
        two want different answers from us. """
        started_info = self.read_started_job(job_uuid)
        if started_info is None:
            return False
        unit = started_info.get('unit')
        if unit:
            try:
                proc = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                    check=False)
            except OSError as e:
                log_msg = _("Failed to ask systemd about {unit}: {e}", log=True)[1]
                log_msg = log_msg.format(unit=unit, e=e)
                self.logger.warning(log_msg)
                return False
            return proc.returncode == 0
        pid = started_info.get('pid')
        if not pid:
            return False
        # No systemd: the runner is a child of ours that we set loose,
        # and the job uuid in its command line says it is still the same
        # process and not one that got the number after it.
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fd:
                cmdline = fd.read().decode()
        except OSError:
            return False
        return job_uuid in cmdline

    def start_runner(self, job):
        """ Hand the job to a runner of its own.

        As a transient systemd service where there is systemd: that
        makes the runner a child of PID 1 instead of one of ours, so
        stopping or restarting OTPme does not stop the job. Where there
        is no systemd it is a process we set loose, which is as far as
        we can get. """
        job_uuid = job['uuid']
        runner = shutil.which(RUNNER_COMMAND)
        if not runner:
            msg = _("Command not found: {command}")
            msg = msg.format(command=RUNNER_COMMAND)
            raise OTPmeException(msg)
        job_file = confd_job.write_job_file(job)
        if self.have_systemd():
            unit = self.get_runner_unit(job_uuid)
            description = f"OTPme configuration job {job_uuid}"
            command = [
                    "systemd-run",
                    "--quiet",
                    # Takes the unit away when it is finished, so a
                    # failed job does not keep its unit around and the
                    # same job could run again after all.
                    "--collect",
                    f"--unit={unit}",
                    f"--description={description}",
                    runner,
                    job_file,
                    ]
            # The marker before the start: see add_started_job().
            self.add_started_job(job_uuid, unit=unit)
            try:
                subprocess.run(command, check=True)
            except Exception as e:
                self.del_started_job(job_uuid)
                msg = _("Failed to start job as transient service: {e}")
                msg = msg.format(e=e)
                raise OTPmeException(msg) from e
            log_msg = _("Started job {job_uuid} as transient service: {unit}", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, unit=unit)
            self.logger.info(log_msg)
        else:
            command = [runner, job_file]
            try:
                proc = subprocess.Popen(command,
                                    stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            except Exception as e:
                msg = _("Failed to start job runner: {e}")
                msg = msg.format(e=e)
                raise OTPmeException(msg) from e
            self.add_started_job(job_uuid, pid=proc.pid)
            log_msg = _("Started job {job_uuid} as process {pid}.", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, pid=proc.pid)
            self.logger.info(log_msg)
        self.running_job = job_uuid

    def collect_results(self):
        """ Send what the runners left behind.

        Done before anything else of a round: a result that is on its
        way out must not have its job handed out again, and a runner
        that is finished frees the way for the next job. """
        for x_file in sorted(filetools.list_dir(get_results_dir())):
            if not x_file.endswith(".json"):
                continue
            result_file = os.path.join(get_results_dir(), x_file)
            try:
                result = confd_job.read_result_file(result_file)
            except Exception as e:
                log_msg = _("Failed to read job result: {file}: {e}", log=True)[1]
                log_msg = log_msg.format(file=result_file, e=e)
                self.logger.warning(log_msg)
                continue
            job_uuid = result['job_uuid']
            x_status = result.get('status')
            # A runner can refuse a job too. It checks everything again
            # before it does anything, and between our check and its own
            # the answer can change -- the other way round as well, so a
            # job we let through arrives at a runner that says no.
            #
            # Nothing ran then, and the job is not done. Noted as a
            # refusal we reported, so we do not say it twice, and as one
            # to come back to: the runner refuses for the same reason we
            # do, and that reason goes away by itself.
            if x_status == "refused":
                if job_uuid not in self.refused_jobs:
                    self.audit_job("job_refused",
                                level='warning',
                                job=job_uuid,
                                job_type=result.get('job_type'),
                                action=result.get('action'),
                                reason=result.get('output'))
                self.add_refused_job(job_uuid, retry=True)
            else:
                # Once, when the result first turns up. A result we fail
                # to send is kept and tried again next round, and the
                # job finished only the one time -- the nodes say when
                # it reached them (OTPmeSyncP1.add_conf_result()), this
                # says when it happened.
                if job_uuid not in self.done_jobs:
                    self.audit_job("job_done",
                                level='info' if x_status == "ok" else 'warning',
                                job=job_uuid,
                                job_type=result.get('job_type'),
                                action=result.get('action'),
                                status=x_status,
                                exit_code=result.get('exit_code'))
                # Before the result goes out: a result we fail to send is
                # sent again later, but the job must not run a second time.
                self.add_done_job(job_uuid)
            try:
                self.send_result(result)
            except Exception as e:
                log_msg = _("Failed to send result of job {job_uuid}: {e}", log=True)[1]
                log_msg = log_msg.format(job_uuid=job_uuid, e=e)
                self.logger.warning(log_msg)
                # Kept, so the next round tries again. The job is done
                # either way, so nothing runs twice because of it.
                self.del_started_job(job_uuid)
                continue
            try:
                os.remove(result_file)
            except OSError as e:
                log_msg = _("Failed to remove job result: {file}: {e}", log=True)[1]
                log_msg = log_msg.format(file=result_file, e=e)
                self.logger.warning(log_msg)
            self.del_started_job(job_uuid)

    def check_running_jobs(self):
        """ Look after the jobs we handed out.

        A runner that is gone without leaving a result was interrupted
        -- the host was rebooted while it worked, or something killed
        it. That is reported once, like a refusal, and the job counts as
        run: what it did before it was cut short is unknown, and doing
        it again unasked could be worse than not doing it. """
        self.running_job = None
        for job_uuid in self.get_started_jobs():
            if os.path.exists(confd_job.get_result_file(job_uuid)):
                # Picked up by collect_results() on the next round.
                continue
            if self.runner_active(job_uuid):
                self.running_job = job_uuid
                continue
            log_msg = _("Job {job_uuid} was interrupted.", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid)
            self.logger.warning(log_msg)
            self.report_interrupted(job_uuid)

    def report_interrupted(self, job_uuid):
        """ Tell the nodes about a job whose runner did not come back.

        What we know about it is in its log file, which is where the
        runner wrote as it went: that is the only account of how far it
        got. """
        started_info = self.read_started_job(job_uuid) or {}
        started = started_info.get('started') or time.time()
        log_file = confd_job.get_log_file(job_uuid)
        output = self.read_job_log(log_file)
        message = _("Job was interrupted.")
        output = f"{output}\n{message}\n"
        # A runner that died before it could write anything leaves an
        # empty log, and then this is all that is known about it: what
        # it said as it went down went to the journal of its service.
        unit_output = self.read_unit_log(started_info.get('unit'))
        if unit_output:
            output = f"{output}{unit_output}"
        job_file = confd_job.get_job_file(job_uuid)
        try:
            job = confd_job.read_job_file(job_file)
        except Exception as e:
            log_msg = _("Failed to read job file: {file}: {e}", log=True)[1]
            log_msg = log_msg.format(file=job_file, e=e)
            self.logger.warning(log_msg)
            # Nothing to report with, and nothing to run either: the
            # job is forgotten, and the nodes go on waiting for it.
            self.add_done_job(job_uuid)
            self.del_started_job(job_uuid)
            return
        result = confd_job.build_result(job=job,
                                    exit_code=1,
                                    output=output,
                                    log_file=log_file,
                                    started=started,
                                    finished=time.time())
        self.add_done_job(job_uuid)
        try:
            self.send_result(result)
        except Exception as e:
            log_msg = _("Failed to report interrupted job {job_uuid}: {e}", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, e=e)
            self.logger.warning(log_msg)
            # Written for the next round to pick up, so the job is
            # reported even if we cannot reach the nodes right now.
            try:
                confd_job.write_result_file(result)
            except Exception as write_error:
                log_msg = _("Failed to write job result: {job_uuid}: {e}", log=True)[1]
                log_msg = log_msg.format(job_uuid=job_uuid, e=write_error)
                self.logger.warning(log_msg)
            return
        self.del_started_job(job_uuid)

    def read_unit_log(self, unit):
        """ The last thing the service of a runner said.

        Asked for a runner that is gone without a result: whatever took
        it down -- a missing module, a signal -- is in the journal of
        its unit and nowhere else. """
        if not unit:
            return ""
        command = [
                "journalctl",
                "--no-pager",
                "-n", str(UNIT_LOG_LINES),
                "-u", unit,
                ]
        try:
            proc = subprocess.run(command,
                                check=False,
                                capture_output=True,
                                text=True)
        except OSError as e:
            log_msg = _("Failed to read journal of {unit}: {e}", log=True)[1]
            log_msg = log_msg.format(unit=unit, e=e)
            self.logger.warning(log_msg)
            return ""
        if not proc.stdout:
            return ""
        return f"### journal of {unit}\n{proc.stdout}"

    def read_job_log(self, log_file):
        """ What a run wrote about itself. """
        if not os.path.exists(log_file):
            return ""
        try:
            with open(log_file, "r") as fd:
                return fd.read()
        except OSError as e:
            log_msg = _("Failed to read job log: {file}: {e}", log=True)[1]
            log_msg = log_msg.format(file=log_file, e=e)
            self.logger.warning(log_msg)
            return ""

    def get_signers_mtime(self):
        """ When the signers of this host last changed.

        The newest change below the signers directory: a signer of a job
        type is a file there, and one added or removed changes the
        directory it sits in. """
        signers_dir = config.signers_dir
        if not os.path.exists(signers_dir):
            return None
        mtime = 0.0
        for dir_path, dir_names, file_names in os.walk(signers_dir):
            for x_path in [dir_path] + [os.path.join(dir_path, x)
                                        for x in file_names]:
                try:
                    x_mtime = os.path.getmtime(x_path)
                except OSError:
                    continue
                mtime = max(mtime, x_mtime)
        return mtime

    def signers_changed(self):
        """ Whether the signers of this host changed since we looked.

        A job we refused because no signer of ours vouched for it is not
        asked for again -- the nodes are told about it, like the jobs we
        ran. But the answer changes the moment an administrator adds the
        signer, so then the refusals are forgotten and the jobs come
        back with the next round. """
        mtime = self.get_signers_mtime()
        if mtime == self.signers_mtime:
            return False
        first_look = self.signers_mtime is None
        self.signers_mtime = mtime
        if first_look:
            return False
        return True

    def clear_refused_jobs(self):
        """ Forget every refusal, so the jobs are asked for again.

        Apart from the ones that are asked for anyway: forgetting them
        would only make us report the same refusal a second time.
        """
        for job_uuid in list(self.refused_jobs):
            if job_uuid in self.retry_jobs:
                continue
            self.del_refused_job(job_uuid)

    def remove_outdated_logs(self):
        """ Remove the log files of jobs nobody asks about anymore. """
        log_dir = get_log_dir()
        if not os.path.exists(log_dir):
            return
        now = time.time()
        for x_log in filetools.list_dir(log_dir):
            x_file = os.path.join(log_dir, x_log)
            try:
                x_age = now - os.path.getmtime(x_file)
            except OSError:
                continue
            if x_age <= LOG_MAX_AGE:
                continue
            try:
                os.remove(x_file)
            except OSError as e:
                log_msg = _("Failed to remove job log: {file}: {e}", log=True)[1]
                log_msg = log_msg.format(file=x_file, e=e)
                self.logger.warning(log_msg)

    def may_remove_jobs(self):
        """ Whether we are the ones to clean up the jobs of the site.

        Only the master node: jobs and results are synced between the
        nodes, and a removal made here reaches the others. Asked again
        and again during the cleanup, so a failover stops it at once. """
        if config.host_type != "node":
            return False
        if not config.master_node:
            return False
        if not config.cluster_status:
            return False
        if config.master_failover:
            return False
        return True

    def remove_outdated_jobs(self):
        """ Remove jobs older than conf_job_max_age, with their results.

        While we do it, the master must not change: another node would
        start with a picture of the jobs that is half gone. So a failover
        blocker is held for the time of the cleanup. """
        now = time.time()
        if (now - self.last_cleanup) < self.cleanup_interval:
            return
        if not self.may_remove_jobs():
            return
        self.last_cleanup = now
        from otpme.lib import deploy
        from otpme.lib import multiprocessing
        blocker_name = "confd: removing outdated configuration jobs"
        blocker_id = multiprocessing.add_master_failover_blocker(blocker_name,
                                                            auth_token="confd")
        from otpme.lib.classes.data_objects.host_inventory import remove_orphan_inventories
        try:
            removed = deploy.remove_outdated_jobs(still_allowed=self.may_remove_jobs,
                                                logger=self.logger)
            remove_orphan_inventories(still_allowed=self.may_remove_jobs,
                                    logger=self.logger)
        finally:
            multiprocessing.del_master_failover_blocker(blocker_id)
        log_msg = _("Removed {count} outdated job(s).", log=True)[1]
        log_msg = log_msg.format(count=removed)
        if removed:
            self.logger.info(log_msg)
        else:
            self.logger.debug(log_msg)

    def update_inventory(self):
        """ Tell the nodes what system, packages and hardware this host
        has.

        Only what changed travels: we send the checksum of our packages,
        and only if the nodes hold something else do they send their
        list, and we send back the difference. A host that reports for
        the first time sends all of its packages that way, in parts of
        MAX_PACKAGES_PER_UPDATE.

        The hardware takes no such round. It is a dozen values, so the
        nodes only say whether theirs is the same, and if it is not we
        send all of it with the next update.

        Not while a job runs: a package manager at work is no moment to
        take stock, the next round after it will. """
        from otpme.lib import confd as os_handlers
        from otpme.lib.confd import inventory
        from otpme.lib.confd import hardware as hardware_mod
        if self.running_job:
            return
        os_name, os_version = os_handlers.get_os_info()
        packages = {}
        try:
            handler = os_handlers.get_handler(logger=self.logger)
            packages = handler.get_installed_packages()
        except Exception as e:
            log_msg = _("Failed to get installed packages: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.debug(log_msg)
        hardware = {}
        try:
            hardware = hardware_mod.get_hardware()
        except Exception as e:
            log_msg = _("Failed to get hardware: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.debug(log_msg)
        checksum = inventory.get_packages_checksum(packages)
        hardware_checksum = hardware_mod.get_hardware_checksum(hardware)
        local_inventory = (os_name, os_version, checksum, hardware_checksum)
        now = time.time()
        if local_inventory == self.reported_inventory:
            if (now - self.last_inventory_check) < self.inventory_check_interval:
                return
        sync_conn = self.get_sync_connection()
        try:
            command_args = {
                        'packages_checksum' : checksum,
                        'hardware_checksum' : hardware_checksum,
                        }
            status, \
            status_code, \
            response, \
            binary_data = sync_conn.send("get_host_inventory", command_args)
            if not status:
                msg = _("Failed to get inventory: {response}")
                msg = msg.format(response=response)
                raise OTPmeException(msg)
            set_packages = {}
            del_packages = []
            if response.get('packages') is not None:
                set_packages, del_packages = inventory.diff_packages(response['packages'],
                                                                    packages)
            send_os = False
            if response.get('os') != os_name:
                send_os = True
            if response.get('os_version') != os_version:
                send_os = True
            send_hardware = response.get('hardware_checksum') != hardware_checksum
            updates = self.split_inventory_update(set_packages, del_packages)
            if (send_os or send_hardware) and not updates:
                updates = [({}, [])]
            for x_set, x_del in updates:
                command_args = {
                            'set_packages'  : x_set,
                            'del_packages'  : x_del,
                            }
                if send_os:
                    command_args['os'] = os_name
                    command_args['os_version'] = os_version
                    send_os = False
                # Whole, with the first of the updates: it is a dozen
                # values, and sending it again with every part of a
                # package list would say the same thing over and over.
                if send_hardware:
                    command_args['hardware'] = hardware
                    send_hardware = False
                status, \
                status_code, \
                response, \
                binary_data = sync_conn.send("update_host_inventory",
                                            command_args)
                if not status:
                    msg = _("Failed to update inventory: {response}")
                    msg = msg.format(response=response)
                    raise OTPmeException(msg)
        finally:
            sync_conn.close()
        if set_packages or del_packages:
            log_msg = _("Reported inventory: {os_version}, {set_count} new or changed, {del_count} removed package(s).", log=True)[1]
            log_msg = log_msg.format(os_version=os_version,
                                    set_count=len(set_packages),
                                    del_count=len(del_packages))
            self.logger.info(log_msg)
        self.reported_inventory = local_inventory
        self.last_inventory_check = now

    def split_inventory_update(self, set_packages, del_packages):
        """ The changes in parts the nodes take in one request. """
        from otpme.lib.confd.inventory import MAX_PACKAGES_PER_UPDATE
        changes = [('del', name) for name in del_packages]
        changes += [('set', name) for name in sorted(set_packages)]
        updates = []
        for start in range(0, len(changes), MAX_PACKAGES_PER_UPDATE):
            x_set = {}
            x_del = []
            for kind, name in changes[start:start + MAX_PACKAGES_PER_UPDATE]:
                if kind == "del":
                    x_del.append(name)
                else:
                    x_set[name] = set_packages[name]
            updates.append((x_set, x_del))
        return updates

    def get_sync_connection(self):
        """ Connection to the syncd of our site. """
        log_msg = _("Connecting to syncd: {realm}/{site}", log=True)[1]
        log_msg = log_msg.format(realm=config.realm, site=config.site)
        self.logger.debug(log_msg)
        return connections.get("syncd",
                            realm=config.realm,
                            site=config.site,
                            timeout=60,
                            interactive=False)

    def get_jobs(self):
        """ The jobs our site has for us, oldest first.

        What we have run is sent along, and what we refused and told the
        nodes about, so neither travels again and again. A refusal is
        forgotten when the signers of this host change, and then the job
        comes back with the next round.

        Not the refusals that go away by themselves (self.retry_jobs).
        Nothing tells us when the object a job waits for has arrived, so
        such a job is asked for every round and looked at again. We only
        reported it once, and that stands. """
        sync_conn = self.get_sync_connection()
        try:
            known_jobs = [x for x in self.refused_jobs
                        if x not in self.retry_jobs]
            known_jobs = list(self.done_jobs) + known_jobs
            command_args = {'known_jobs':known_jobs}
            status, \
            status_code, \
            response, \
            binary_data = sync_conn.send("get_conf_jobs", command_args)
        finally:
            sync_conn.close()
        if not status:
            msg = _("Failed to get jobs: {response}")
            msg = msg.format(response=response)
            raise OTPmeException(msg)
        try:
            jobs = response['jobs']
        except (TypeError, KeyError) as err:
            msg = _("Got invalid answer for jobs.")
            raise OTPmeException(msg) from err
        return sorted(jobs, key=lambda x: x.get('created') or 0)

    def send_result(self, result):
        """ Send the result of a run to our site. """
        log_msg = _("Sending result of job {job_uuid}: {status} (exit {exit_code})", log=True)[1]
        log_msg = log_msg.format(job_uuid=result['job_uuid'],
                                status=result['status'],
                                exit_code=result['exit_code'])
        self.logger.info(log_msg)
        sync_conn = self.get_sync_connection()
        try:
            status, \
            status_code, \
            response, \
            binary_data = sync_conn.send("add_conf_result", {'result':result})
        finally:
            sync_conn.close()
        if not status:
            msg = _("Failed to send job result: {response}")
            msg = msg.format(response=response)
            raise OTPmeException(msg)
        return True

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Set process title.
        self.set_proctitle()
        # We keep the privileges of our parent (root) on purpose, see
        # the module docstring. Every other daemon calls
        # drop_privileges() here.

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        self.done_jobs = self.read_done_jobs()
        # Refusals survive a restart. Forgetting them here made every
        # start walk through every job we ever refused again, and a job
        # whose signature says something else than the job does will
        # never be run, however often it is looked at. The one reason a
        # refusal does go away is the one that can change the answer:
        # the signers of this host, see signers_changed(). Apart from
        # the refusals that go away by themselves, which are asked for
        # every round anyway, see get_jobs().
        self.refused_jobs, self.retry_jobs = self.read_refused_jobs()
        # A signer added while we were not running would go unnoticed:
        # signers_changed() only knows what it saw in this run. So a
        # refusal older than the newest change below the signers
        # directory gets another look.
        signers_mtime = self.get_signers_mtime()
        if signers_mtime:
            for job_uuid in list(self.refused_jobs):
                if job_uuid in self.retry_jobs:
                    # Asked for anyway, and dropping the marker would
                    # only make us report the same refusal twice.
                    continue
                marker_file = os.path.join(get_refused_dir(), job_uuid)
                try:
                    marker_mtime = os.path.getmtime(marker_file)
                except OSError:
                    continue
                if marker_mtime >= signers_mtime:
                    continue
                self.del_refused_job(job_uuid)
        final_refusals = [x for x in self.refused_jobs
                        if x not in self.retry_jobs]
        if final_refusals:
            log_msg = _("Not asking for {count} refused job(s) again.", log=True)[1]
            log_msg = log_msg.format(count=len(final_refusals))
            self.logger.info(log_msg)
        if self.retry_jobs:
            log_msg = _("Waiting for {count} refused job(s) to become runnable.", log=True)[1]
            log_msg = log_msg.format(count=len(self.retry_jobs))
            self.logger.info(log_msg)

        # Jobs run in a runner of their own, so a restart of ours does
        # not touch them: what is still running keeps running, what
        # finished meanwhile left its result behind, and the first round
        # picks up both.
        started_jobs = self.get_started_jobs()
        if started_jobs:
            log_msg = _("Jobs that were started before: {count}.", log=True)[1]
            log_msg = log_msg.format(count=len(started_jobs))
            self.logger.info(log_msg)

        log_msg = _("{full_name} started", log=True)[1]
        log_msg = log_msg.format(full_name=self.full_name)
        self.logger.info(log_msg)
        log_msg = _("Asking for jobs every {interval}s. Jobs we ran: {done}.", log=True)[1]
        log_msg = log_msg.format(interval=self.job_check_interval,
                                done=len(self.done_jobs))
        self.logger.info(log_msg)

        # Notify controld that we are ready.
        self.comm_handler.send("controld", command="ready")

        process_jobs = False
        last_job_check = 0.0
        while True:
            try:
                # While a job runs we only wait for its result, and that
                # is worth looking for more often than once a minute:
                # a job that is over in a second should not have its
                # result sit here for the rest of the round.
                if process_jobs:
                    if self.running_job:
                        recv_timeout = self.result_check_interval
                    else:
                        recv_timeout = self.job_check_interval
                else:
                    recv_timeout = self.result_check_interval
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv(recv_timeout)
                except ExitOnSignal:
                    break
                except TimeoutReached:
                    daemon_command = None
                except Exception as e:
                    msg, log_msg = _("Error receiving daemon message: {error}", log=True)
                    msg = msg.format(error=e)
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg)
                    raise OTPmeException(msg) from e

                # Make sure, floating IP is ready on master nodes.
                process_jobs = False
                if config.host_type == "node":
                    if config.cluster_status:
                        if config.master_node:
                            if config.cluster_ip:
                                if not config.master_failover:
                                    process_jobs = True
                        elif config.master_node is False:
                            if not config.master_failover:
                                process_jobs = True
                else:
                    process_jobs = True

                if process_jobs:
                    now = time.time()
                    if self.running_job:
                        # Nothing but looking for the result file: what the
                        # runner is doing, and whether it still is, belongs
                        # to the full round below.
                        try:
                            self.collect_results()
                        except Exception as e:
                            log_msg = _("Failed to collect job results: {e}", log=True)[1]
                            log_msg = log_msg.format(e=e)
                            self.logger.warning(log_msg)
                        if not self.running_job:
                            # It is finished and its result is out, so the
                            # next job can start right away.
                            last_job_check = 0.0
                    if (now - last_job_check) >= self.job_check_interval:
                        try:
                            self.process_jobs()
                        except Exception as e:
                            log_msg = _("Failed to process jobs: {e}", log=True)[1]
                            log_msg = log_msg.format(e=e)
                            self.logger.warning(log_msg)
                        try:
                            self.remove_outdated_logs()
                        except Exception as e:
                            log_msg = _("Failed to remove outdated job logs: {e}", log=True)[1]
                            log_msg = log_msg.format(e=e)
                            self.logger.warning(log_msg)
                        try:
                            self.remove_outdated_jobs()
                        except Exception as e:
                            log_msg = _("Failed to remove outdated jobs: {e}", log=True)[1]
                            log_msg = log_msg.format(e=e)
                            self.logger.warning(log_msg)
                        try:
                            self.update_inventory()
                        except Exception as e:
                            log_msg = _("Failed to update inventory: {e}", log=True)[1]
                            log_msg = log_msg.format(e=e)
                            self.logger.warning(log_msg)
                        last_job_check = time.time()

                if daemon_command is None:
                    continue

                # Check if command can be handled by parent class.
                try:
                    self._handle_daemon_command(sender, daemon_command, data)
                except UnknownCommand as e:
                    log_msg = str(e)
                    self.logger.warning(log_msg)
                except DaemonQuit:
                    break
                except DaemonReload:
                    restart = self.configure()
                    if restart:
                        break
                    # Inform controld that we finished our reload.
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                config.raise_exception()
                log_msg = _("Unhandled error in confd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)

    def process_jobs(self):
        """ Get the jobs for this host and have them run, oldest first.

        In this order: what the runners left behind goes out first, then
        the jobs that are still on their way are looked after, and only
        then is the next job handed out. """
        self.collect_results()
        self.check_running_jobs()
        if self.signers_changed():
            log_msg = _("Signers changed, asking for refused jobs again.", log=True)[1]
            self.logger.info(log_msg)
            self.clear_refused_jobs()
        if self.running_job:
            log_msg = _("Waiting for job {job_uuid} to finish.", log=True)[1]
            log_msg = log_msg.format(job_uuid=self.running_job)
            self.logger.debug(log_msg)
            return
        log_msg = _("Asking for jobs ({done} done, {refused} refused)...", log=True)[1]
        log_msg = log_msg.format(done=len(self.done_jobs),
                                refused=len(self.refused_jobs))
        self.logger.debug(log_msg)
        try:
            jobs = self.get_jobs()
        except Exception as e:
            log_msg = _("Failed to get jobs from site: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return
        if not jobs:
            log_msg = _("No jobs for us.", log=True)[1]
            self.logger.debug(log_msg)
            return
        log_msg = _("Got {count} job(s) to process.", log=True)[1]
        log_msg = log_msg.format(count=len(jobs))
        self.logger.info(log_msg)
        for job in jobs:
            job_uuid = job.get('uuid')
            if not job_uuid:
                continue
            if job_uuid in self.done_jobs:
                # We ran it, the result did not make it through. Send it
                # again rather than run it again.
                log_msg = _("Job {job_uuid} was run already, sending its result again.", log=True)[1]
                log_msg = log_msg.format(job_uuid=job_uuid)
                self.logger.info(log_msg)
                self.resend_result(job)
                continue
            if os.path.exists(self.get_started_file(job_uuid)):
                # A runner has it, we just do not have its result yet.
                continue
            self.process_job(job)
            if self.running_job:
                # One job at a time. The rest comes with the next round,
                # when this one has left its result behind.
                break

    def process_job(self, job):
        """ Check one job and hand it to a runner.

        The checking happens here so that a job we will not run is
        refused right away, and the whole of the reason goes back to the
        nodes. The runner checks it again before it does anything. """
        job_uuid = job['uuid']
        try:
            signer_uuid = confd_job.verify_job(job)
            # May we, and can we. A job that names something we have
            # not synced yet is refused and not failed, so it runs by
            # itself once the object is here.
            confd_job.check_job_ready(job)
        except Exception as e:
            # JobNotReady is the refusal we take back by ourselves: the
            # object is on its way, and the job is looked at again every
            # round until it is here.
            retry = isinstance(e, JobNotReady)
            log_msg = _("Refusing job {job_uuid}: {e}", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, e=e)
            self.logger.warning(log_msg)
            # On the host, because this is where it is decided. The
            # nodes hear that it was refused (report_refusal()), but
            # the reason is a thing about this host -- no signer it
            # trusts, a signature that does not hold -- and the record
            # of it belongs where it was found.
            self.audit_job("job_refused",
                        level='warning',
                        job=job_uuid,
                        job_type=job.get('job_type'),
                        action=job.get('action'),
                        reason=str(e))
            self.report_refusal(job, str(e), retry=retry)
            return
        # It runs now, so a refusal we reported before is over.
        self.del_refused_job(job_uuid)
        log_msg = _("Running job {job_uuid}: {job_type} {action}", log=True)[1]
        log_msg = log_msg.format(job_uuid=job_uuid,
                                job_type=job['job_type'],
                                action=job['action'])
        self.logger.info(log_msg)
        # The signer goes in here and not with the result: this is the
        # moment the host established who it acts for.
        #
        # By uuid, because that is all a host has. A signature carries
        # no OID (see OTPmeSignature._attributes) and a signer is held
        # by uuid (OTPmeSigner.object_uuid) -- a host holds no users
        # and no roles. Carrying a name along would mean writing down
        # one the host cannot check against anything, next to a uuid it
        # can. The name is on the nodes, in job_created, under the same
        # job uuid (see deploy.audit_job()).
        self.audit_job("job_started",
                    job=job_uuid,
                    job_type=job['job_type'],
                    action=job['action'],
                    signer_uuid=signer_uuid)
        try:
            self.start_runner(job)
        except Exception as e:
            log_msg = _("Failed to start job {job_uuid}: {e}", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, e=e)
            self.logger.warning(log_msg)
            self.audit_job("job_refused",
                        level='warning',
                        job=job_uuid,
                        job_type=job.get('job_type'),
                        action=job.get('action'),
                        reason=str(e))
            self.report_refusal(job, str(e))

    def audit_job(self, event, level='info', **fields):
        """ Audit one thing this host did with a job.

        The actor is this host: nobody is logged in on it, it acts on
        an instruction it was given and checked. Who gave it is on the
        nodes, next to the job (see deploy.audit_job()).

        By FQDN, which is what the nodes call a host in their own
        entries (OTPmeSyncP1.add_conf_result()), so both ends of one
        job say the same name.
        """
        try:
            actor = config.host_data['fqdn']
        except KeyError:
            actor = "unknown"
        emit_audit("Deploy", event,
                level=level,
                actor=actor,
                **fields)

    def report_refusal(self, job, reason, retry=False):
        """ Tell the nodes that we will not run this job.

        A job we hold no signer for would otherwise sit in the listing
        as waiting forever, and whoever made it would never learn that
        it is not going to happen here.

        Reported once, not once a minute: the reason may go away -- a
        signer that is added later is the whole point -- so the job is
        checked again every round, only the reporting is not repeated.

        <retry> for a reason that goes away without anybody doing
        anything, and that nothing tells us about: we then ask for the
        job again every round instead of waiting for our signers to
        change, see add_refused_job().
        """
        job_uuid = job['uuid']
        if job_uuid in self.refused_jobs:
            return
        now = time.time()
        log_file = confd_job.get_log_file(job_uuid)
        output = _("Job refused: {reason}")
        output = output.format(reason=reason)
        try:
            with open(log_file, "a") as fd:
                fd.write(f"{output}\n")
        except OSError as e:
            log_msg = _("Failed to write job log: {file}: {e}", log=True)[1]
            log_msg = log_msg.format(file=log_file, e=e)
            self.logger.warning(log_msg)
        result = confd_job.build_result(job=job,
                                    exit_code=1,
                                    output=output,
                                    log_file=log_file,
                                    started=now,
                                    finished=now,
                                    status="refused")
        try:
            self.send_result(result)
        except Exception as e:
            # Not noted as reported, so the next round tries again.
            log_msg = _("Failed to report refusal of job {job_uuid}: {e}", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, e=e)
            self.logger.warning(log_msg)
            return
        self.add_refused_job(job_uuid, retry=retry)

    def resend_result(self, job):
        """ Send the result of a job we ran again.

        The nodes still offer it, so our answer never arrived. What we
        know about the run is in its log file. """
        job_uuid = job['uuid']
        log_file = confd_job.get_log_file(job_uuid)
        exit_code = 0
        output = self.read_job_log(log_file)
        result = confd_job.build_result(job=job,
                                    exit_code=exit_code,
                                    output=output,
                                    log_file=log_file,
                                    started=job.get('created') or time.time(),
                                    finished=time.time())
        try:
            self.send_result(result)
        except Exception as e:
            log_msg = _("Failed to resend result of job {job_uuid}: {e}", log=True)[1]
            log_msg = log_msg.format(job_uuid=job_uuid, e=e)
            self.logger.warning(log_msg)
