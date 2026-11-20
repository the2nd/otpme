# -*- coding: utf-8 -*-
""" Jobs that run on the backup server, apart from the daemon.

The retention of a repository -- deleting the snapshots it no longer
keeps, and the repack after it -- can take hours. backupd used to run
it inside the connection of the client that asked for it, and the
client waited: it gave up when one SQLite statement took longer than
its read timeout (no keepalive gets out of a statement), called the
backup failed and left the daemon to finish on its own.

Now backupd starts a job and answers right away. The job is

    local-backup -d <repository> run-job <job id>

with the interpreter and the code of backupd, as a transient systemd
service where there is systemd: a child of PID 1, so stopping or
restarting OTPme does not stop it. Without systemd it is a process of
its own session, which is as far as we get.

What a job is, and what came of it, is a marker in the repository,
<repository>/jobs/<job id>.json. backupd writes it before it starts the
job, and the job updates it when it starts and when it is done. The
job logs what it does -- every snapshot it deletes, what the repack
frees, an error -- to the log file backupd gives it.

Standard library only: local-backup runs without the rest of OTPme.
"""
import os
import sys
import json
import time
import uuid
import fcntl
import shutil
import logging
import subprocess

JOBS_DIR_NAME = "jobs"
UNIT_PREFIX = "otpme-backup-job"
# Markers of jobs that are over stay this long, so they can be looked at.
KEEP_FINISHED = 7 * 24 * 3600

ACTIONS = ["retention"]

STATE_STARTED = "started"
STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_FAILED = "failed"
# Not written by anybody: a job that is started or running in its marker
# but has no process any more.
STATE_ABORTED = "aborted"


def get_jobs_dir(repo_root):
    """ Where the markers of the jobs of a repository go. """
    return os.path.join(repo_root, JOBS_DIR_NAME)


def get_job_file(repo_root, job_id):
    return os.path.join(get_jobs_dir(repo_root), f"{job_id}.json")


def get_unit(job_id):
    """ The transient service of a job. """
    return f"{UNIT_PREFIX}-{job_id}.service"


def write_job(repo_root, job):
    """ Write the marker of a job, whole or not at all. """
    jobs_dir = get_jobs_dir(repo_root)
    os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
    job_file = get_job_file(repo_root, job['id'])
    tmp_file = f"{job_file}.tmp"
    with open(tmp_file, "w") as fd:
        json.dump(job, fd, indent=1)
        fd.flush()
        os.fsync(fd.fileno())
    os.chmod(tmp_file, 0o600)
    os.replace(tmp_file, job_file)
    return job_file


def read_job(repo_root, job_id):
    job_file = get_job_file(repo_root, job_id)
    with open(job_file, "r") as fd:
        return json.load(fd)


def have_systemd():
    """ Whether a job can run as a transient service. """
    if not os.path.isdir("/run/systemd/system"):
        return False
    if not shutil.which("systemd-run"):
        return False
    return True


def job_alive(job):
    """ Whether the process of a job is still there.

    By its unit where it has one. Else by its pid, and the job id in the
    command line says it is still the same process and not one that got
    the number after it. """
    unit = job.get('unit')
    if unit:
        try:
            proc = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                check=False)
        except OSError:
            return False
        return proc.returncode == 0
    for pid in (job.get('pid'), job.get('runner_pid')):
        if not pid:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fd:
                cmdline = fd.read().decode(errors="replace")
        except OSError:
            continue
        if job['id'] in cmdline:
            return True
    return False


def job_state(job):
    """ The state of a job as it is now, not only as its marker says. """
    state = job.get('state')
    if state in (STATE_STARTED, STATE_RUNNING) and not job_alive(job):
        return STATE_ABORTED
    return state


def list_jobs(repo_root):
    """ The jobs of a repository, oldest first, each with its state now. """
    jobs_dir = get_jobs_dir(repo_root)
    try:
        names = os.listdir(jobs_dir)
    except FileNotFoundError:
        return []
    jobs = []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(jobs_dir, name), "r") as fd:
                job = json.load(fd)
        except (OSError, ValueError):
            continue
        job['state_now'] = job_state(job)
        jobs.append(job)
    jobs.sort(key=lambda j: j.get('created', 0))
    return jobs


def find_repositories(path, max_depth=4):
    """ The repositories at or below path: directories with snapshots/. """
    path = os.path.abspath(path)
    if os.path.isdir(os.path.join(path, "snapshots")):
        return [path]
    found = []
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, _unused_files in os.walk(path):
        if "snapshots" in dirs:
            found.append(root)
            dirs[:] = []
            continue
        if root.count(os.sep) - base_depth >= max_depth:
            dirs[:] = []
    return sorted(found)


def remove_outdated_jobs(repo_root, now=None):
    """ Forget jobs that have been over for longer than KEEP_FINISHED. """
    if now is None:
        now = time.time()
    for job in list_jobs(repo_root):
        if job['state_now'] in (STATE_STARTED, STATE_RUNNING):
            continue
        ended = job.get('finished') or job.get('created') or 0
        if now - ended < KEEP_FINISHED:
            continue
        try:
            os.remove(get_job_file(repo_root, job['id']))
        except OSError:
            pass


def runner_command(repo_root, job_id):
    """ The command line of a job: local-backup of the code we run. """
    # otpme/lib/classes/backup_job.py -> otpme/bin/backup_cli.py
    package_dir = os.path.dirname(os.path.dirname(os.path.dirname(
                                os.path.realpath(__file__))))
    backup_cli = os.path.join(package_dir, "bin", "backup_cli.py")
    return [sys.executable, backup_cli, "-d", repo_root, "run-job", job_id]


def start_job(repo_root, repository, action, log_file):
    """ Start a job for a repository, unless one is running already.

    Returns (job, started): the job that was started, or the one that
    was running already and False. """
    if action not in ACTIONS:
        raise ValueError(f"Unknown backup job action: {action}")
    repo_root = os.path.abspath(repo_root)
    jobs_dir = get_jobs_dir(repo_root)
    os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
    # Two clients asking at the same time must not start two jobs.
    with open(os.path.join(jobs_dir, ".lock"), "a") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            for job in list_jobs(repo_root):
                if job['state_now'] in (STATE_STARTED, STATE_RUNNING):
                    return job, False
            remove_outdated_jobs(repo_root)
            job_id = uuid.uuid4().hex[:12]
            job = {
                'id'        : job_id,
                'action'    : action,
                'repository': repository,
                'root'      : repo_root,
                'log_file'  : log_file,
                'created'   : time.time(),
                'state'     : STATE_STARTED,
                'unit'      : None,
                'pid'       : None,
                }
            command = runner_command(repo_root, job_id)
            if have_systemd():
                job['unit'] = get_unit(job_id)
                # The marker before the start: a job that is running
                # has to be known, whatever happens to us right after.
                write_job(repo_root, job)
                description = f"OTPme backup job {job_id} ({action} {repository})"
                systemd_command = ["systemd-run", "--quiet", "--collect",
                                f"--unit={job['unit']}",
                                f"--description={description}"] + command
                try:
                    proc = subprocess.run(systemd_command, check=False,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE)
                except Exception:
                    os.remove(get_job_file(repo_root, job_id))
                    raise
                if proc.returncode != 0:
                    os.remove(get_job_file(repo_root, job_id))
                    error = proc.stderr.decode(errors="replace").strip()
                    raise RuntimeError(f"systemd-run failed: {error}")
            else:
                write_job(repo_root, job)
                try:
                    proc = subprocess.Popen(command,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                        start_new_session=True)
                except Exception:
                    os.remove(get_job_file(repo_root, job_id))
                    raise
                job['pid'] = proc.pid
                write_job(repo_root, job)
            return job, True
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)


def _job_logger(job, logger):
    """ Send what the job and the backup module log to the job log. """
    handler = None
    log_file = job.get('log_file')
    if log_file:
        try:
            handler = logging.FileHandler(log_file)
        except OSError as e:
            logger.warning("Cannot write job log %s: %s", log_file, e)
    if handler is not None:
        fmt = (f"%(asctime)s local-backup[%(process)d]: {job['repository']}: "
                f"job {job['id']}: %(levelname)s: %(message)s")
        handler.setFormatter(logging.Formatter(fmt))
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
    if logger.getEffectiveLevel() > logging.INFO:
        logger.setLevel(logging.INFO)
    return handler


def run_job(server, job_id, logger):
    """ Run a job: the runner side, in local-backup. Returns 0 or 1. """
    repo_root = os.path.abspath(str(server.root))
    job = read_job(repo_root, job_id)
    handler = _job_logger(job, logger)
    job['state'] = STATE_RUNNING
    job['runner_pid'] = os.getpid()
    job['started'] = time.time()
    write_job(repo_root, job)
    logger.info("Started %s.", job['action'])
    try:
        if job['action'] == "retention":
            deleted = server.apply_retention()
            job['result'] = {'deleted': deleted}
            if deleted:
                logger.info("Retention deleted %d snapshot(s): %s",
                            len(deleted), ", ".join(deleted))
            else:
                logger.info("Retention deleted no snapshots.")
        else:
            raise ValueError(f"Unknown backup job action: {job['action']}")
        job['state'] = STATE_DONE
    except Exception as e:
        job['state'] = STATE_FAILED
        job['error'] = f"{type(e).__name__}: {e}"
        logger.error("%s failed: %s", job['action'], job['error'])
    finally:
        job['finished'] = time.time()
        write_job(repo_root, job)
        duration = int(job['finished'] - job['started'])
        logger.info("Finished %s: %s after %ds.", job['action'],
                    job['state'], duration)
        if handler is not None:
            logger.removeHandler(handler)
            handler.close()
    if job['state'] != STATE_DONE:
        return 1
    return 0


def format_jobs(rows, now=None):
    """ Lines for local-backup jobs: (repository root, job) pairs. """
    if now is None:
        now = time.time()

    def stamp(t):
        if not t:
            return ""
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))

    def took(job):
        start = job.get('started') or job.get('created')
        if not start:
            return ""
        end = job.get('finished') or now
        seconds = int(end - start)
        hours, rest = divmod(seconds, 3600)
        minutes, seconds = divmod(rest, 60)
        if hours:
            return f"{hours}h {minutes:02d}m"
        if minutes:
            return f"{minutes}m {seconds:02d}s"
        return f"{seconds}s"

    def outcome(job):
        if job.get('error'):
            return job['error']
        result = job.get('result') or {}
        if 'deleted' in result:
            deleted = result['deleted']
            if not deleted:
                return "nothing deleted"
            return f"deleted {len(deleted)}: {', '.join(deleted)}"
        return ""

    lines = [f"{'JOB':<12}  {'REPOSITORY':<30}  {'ACTION':<9}  {'STARTED':<19}  "
            f"{'DURATION':<8}  {'STATE':<8}  RESULT"]
    for repo_root, job in rows:
        repository = job.get('repository') or repo_root
        lines.append(f"{job['id']:<12}  {repository:<30}  {job.get('action', ''):<9}  "
                    f"{stamp(job.get('started') or job.get('created')):<19}  "
                    f"{took(job):<8}  {job['state_now']:<8}  {outcome(job)}")
    return lines
