# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Checking and running one configuration management job.

Used by confd, which decides which job runs when, and by the runner it
starts for the job itself (otpme/bin/confd_job.py). The runner checks
the job again rather than trusting the file it was handed: it is the
process that actually installs the package.

Where things go while a job is on its way:

    <spool>/confd/jobs/<uuid>.json      the job, for the runner
    <spool>/confd/results/<uuid>.json   what came of it, for confd
    <spool>/confd/started/<uuid>        it was started, and when
    <spool>/confd/done/<uuid>           it ran and the result went out
    <spool>/confd/refused/<uuid>        we will not run it, and said so
    <log>/confd/<uuid>.log              everything the run said
"""
import os
import sys
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib.classes import signing
from otpme.lib.confd.base import parse_bool_arg
from otpme.lib.classes.data_objects.conf_job import get_sign_data
from otpme.lib.classes.data_objects.conf_job import get_content_tags
from otpme.lib.classes.data_objects.conf_job import check_job_args
from otpme.lib.classes.data_objects.conf_job import CONF_JOB_ACTIONS

from otpme.lib.exceptions import *

# How much of the output travels to the nodes. The rest stays in the log
# file on this host, and the result says where.
RESULT_OUTPUT_LEN = 64 * 1024
# The tags of a job signature a host can work out itself, and which
# therefore have to match what the job says (see check_sign_tags). A
# "target:" tag of another host is not among them: a host does not know
# the names of the others, and each of them checks its own.
TAG_PREFIXES = ("job_type:", "action:", "arg:", "targets:")

def get_spool_dir(name):
    """ One of our spool directories, made if it is not there. """
    spool_dir = os.path.join(config.spool_dir, "confd", name)
    if not os.path.exists(spool_dir):
        filetools.create_dir(spool_dir, mode=0o700, user="root", group="root")
    return spool_dir

def get_job_file(job_uuid):
    """ Where the job waits for its runner. """
    return os.path.join(get_spool_dir("jobs"), f"{job_uuid}.json")

def get_result_file(job_uuid):
    """ Where the runner leaves what came of the job. """
    return os.path.join(get_spool_dir("results"), f"{job_uuid}.json")

def get_log_dir():
    """ Where the whole output of a run goes. """
    log_dir = os.path.join(config.log_dir, "confd")
    if not os.path.exists(log_dir):
        filetools.create_dir(log_dir, mode=0o700, user="root", group="root")
    return log_dir

def get_log_file(job_uuid):
    """ The log file of one job. """
    return os.path.join(get_log_dir(), f"{job_uuid}.log")

def write_job_file(job):
    """ Hand the job to its runner. """
    job_file = get_job_file(job['uuid'])
    filetools.create_file(path=job_file,
                        content=json.encode(job),
                        user="root",
                        group="root",
                        mode=0o600)
    return job_file

def read_job_file(job_file):
    """ The job a runner was handed. """
    with open(job_file, "r") as fd:
        return json.decode(fd.read())

def write_result_file(result):
    """ Leave the result for confd to send.

    Written next to its place and moved there, so confd never reads half
    a result: a rename within one directory is atomic. """
    result_file = get_result_file(result['job_uuid'])
    temp_file = f"{result_file}.tmp"
    filetools.create_file(path=temp_file,
                        content=json.encode(result),
                        user="root",
                        group="root",
                        mode=0o600)
    os.rename(temp_file, result_file)
    return result_file

def read_result_file(result_file):
    """ A result confd is about to send. """
    with open(result_file, "r") as fd:
        return json.decode(fd.read())

def log_job_message(log_file, message):
    """ One line of our own into the log file of a job.

    The runner has no log of its own -- it is started as a service for
    one job and says what it has to say where the run itself is written,
    which is the file the result points at. Marked like the commands a
    run makes, so it is clear who wrote it. """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_file, "a") as fd:
            fd.write(f"### {timestamp} {message}\n")
    except OSError as e:
        msg = _("Failed to write job log: {file}: {e}")
        msg = msg.format(file=log_file, e=e)
        sys.stderr.write(f"{msg}\n")

def get_expected_tags(job):
    """ The tags the signature of this job has to carry.

    Everything of them this host can work out itself: what the job does,
    how many hosts it is for, and that we are one of them. The names of
    the other hosts we cannot check -- we do not know them -- but each
    of them checks its own. """
    expected_tags = get_content_tags(job_type=job['job_type'],
                                    action=job['action'],
                                    args=job['args'])
    expected_tags.append(f"targets:{len(job['targets'])}")
    expected_tags.append(f"target:{config.host_data['name']}")
    return expected_tags

def check_sign_tags(sig, expected_tags):
    """ Refuse a signature whose tags say something else than the job
    does.

    The tags are what the user read before signing. A node that put
    other words in front of the user than into the job is caught here:
    the ones we can work out ourselves have to be there, and no other
    tag of the same kinds may be. """
    sign_tags = list(sig.tags)
    for tag in expected_tags:
        if tag in sign_tags:
            continue
        msg = _("Signature does not cover the job: {tag} missing.")
        msg = msg.format(tag=tag)
        raise OTPmeException(msg)
    for tag in sign_tags:
        if not tag.startswith(TAG_PREFIXES):
            continue
        if tag in expected_tags:
            continue
        msg = _("Signature says something else than the job: {tag}")
        msg = msg.format(tag=tag)
        raise OTPmeException(msg)

def signer_is_target(signer, target_oid, target_uuid):
    """ Whether a signer of this host is the one a job names.

    By UUID, the way the run itself finds it, and by the OID the signer
    file cached: a user or role that was deleted has no UUID to resolve
    anymore, and that signer is exactly the one a job may be about. """
    if target_uuid and signer.object_uuid == target_uuid:
        return True
    if signer.object_oid and signer.object_oid.full_oid == target_oid:
        return True
    return False

def check_self_lockout(job, sig, signers):
    """ Refuse a job that takes away the last signer it was signed by.

    A signer_mgmt job is verified against the signer_mgmt signers of
    this host, so such a job can take away the permission it runs
    under. Once the last signer that covers the user who signed it is
    gone, that user cannot send another job here, and putting a signer
    back is itself a signer_mgmt job: somebody has to walk to the host.

    It is not forbidden, only said out loud. remove_last_own_signer=yes
    allows it, and since the arguments of a job are part of its
    signature, whoever signed it read that word before they signed. """
    action = job['action']
    args = job['args'] or {}
    if action not in ("del_signer", "update_signer"):
        return
    if args.get("type") != job['job_type']:
        # A signer of another type does not say who may send us a job
        # of this type, so losing it locks nobody out.
        return
    if action == "update_signer":
        # Without it an update keeps every key it pinned, including the
        # ones of members a role does not have anymore.
        if not parse_bool_arg(args, "remove_gone"):
            return
    if parse_bool_arg(args, "remove_last_own_signer"):
        return
    own_signers = [x for x in signers if sig.signer_uuid in x.signers]
    if not own_signers:
        # A job we verified came from one of them, so this does not
        # happen. It is not the job of this check to rely on that.
        return
    target_oid = args.get("signer")
    target_uuid = None
    try:
        target_uuid = stuff.resolve_oid(oid.get(target_oid))
    except Exception:
        target_uuid = None
    signers_left = []
    for signer in own_signers:
        if not signer_is_target(signer, target_oid, target_uuid):
            signers_left.append(signer)
            continue
        if action == "del_signer":
            # The whole signer goes.
            continue
        # update_signer with remove_gone: the signer stays, but a
        # member the role does not have anymore loses its pinned key.
        try:
            gone = signer.check_outdated(sig.signer_uuid)
        except Exception:
            gone = None
        if gone in ("removed", "deleted"):
            continue
        signers_left.append(signer)
    if signers_left:
        return
    msg = _("Job removes the last signer that signed it: set remove_last_own_signer=yes to allow it.")
    raise OTPmeException(msg)

def verify_job(job):
    """ Whether this host runs this job.

    The signature is the permission: it has to be made by a signer this
    host holds for the job type (otpme-tool add_signer), and it covers
    everything that says what is to happen, to whom, and until when.
    Anything we cannot check we refuse.

    Asked by confd before it starts a runner, and by the runner before
    it does anything -- the runner is the one that installs the package,
    so it does not take the word of the file it was handed. """
    try:
        job_uuid = job['uuid']
        job_type = job['job_type']
        action = job['action']
        args = job['args']
        targets = job['targets']
        created = job['created']
        expiry = job['expiry']
        signature = job['signature']
    except KeyError as err:
        msg = _("Job misses attribute: {attribute}")
        msg = msg.format(attribute=err.args[0])
        raise OTPmeException(msg) from err
    if job_type not in CONF_JOB_ACTIONS:
        msg = _("Unknown job type: {job_type}")
        msg = msg.format(job_type=job_type)
        raise OTPmeException(msg)
    if action not in CONF_JOB_ACTIONS[job_type]:
        msg = _("Unknown action for job type '{job_type}': {action}")
        msg = msg.format(job_type=job_type, action=action)
        raise OTPmeException(msg)
    # Asked for when the job was made as well, and asked again here:
    # what we run is our own decision, not that of the node.
    check_job_args(job_type=job_type, action=action, args=args)
    if expiry and time.time() > expiry:
        msg = _("Job is expired.")
        raise OTPmeException(msg)
    if config.uuid not in targets:
        msg = _("Job is not meant for this host.")
        raise OTPmeException(msg)
    signers = signing.get_signers(signer_type=job_type)
    if not signers:
        msg = _("No signer for job type: {job_type}")
        msg = msg.format(job_type=job_type)
        raise OTPmeException(msg)
    log_msg = _("Verifying job {job_uuid} ({job_type} {action}) against {count} signer(s).", log=True)[1]
    log_msg = log_msg.format(job_uuid=job_uuid,
                            job_type=job_type,
                            action=action,
                            count=len(signers))
    config.logger.debug(log_msg)
    sign_data = get_sign_data(job_uuid=job_uuid,
                            job_type=job_type,
                            action=action,
                            args=args,
                            targets=targets,
                            created=created,
                            expiry=expiry)
    # Shaped the way an object carries its signatures, which is what
    # verify_signatures() walks: by signer and by signature ID. We have
    # the one signature of the job, so both come out of it.
    try:
        sig = signing.OTPmeSignature(signature=signature)
    except Exception as e:
        msg = _("Unreadable job signature: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    signatures = {
                sig.signer_uuid : {
                    sig.sign_id : {
                        'signature' : signature,
                        'tags'      : list(sig.tags),
                        },
                    },
                }
    # What the user was shown when they signed has to be what we are
    # about to do. The data itself is covered by the signature already;
    # this covers the words the user read.
    expected_tags = get_expected_tags(job)
    check_sign_tags(sig, expected_tags)
    try:
        signing.verify_signatures(signer_type=job_type,
                                signers=signers,
                                signatures=signatures,
                                sign_data=sign_data,
                                tags=expected_tags)
    except Exception as e:
        msg = _("Invalid job signature: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    # Only now: who signed it is worth reading once the signature said
    # so, and what it may do to our signers depends on who that was.
    check_self_lockout(job, sig, signers)
    # Who signed it, for whoever wants to write it down. A uuid and not
    # a name: a host holds signers, not the objects behind them, so the
    # name is a thing the nodes have (see deploy.audit_job(), which
    # says it there).
    return sig.signer_uuid

def check_job_ready(job):
    """ Whether everything this job names has reached us yet.

    Apart from verify_job(), which asks whether we may run a job at
    all. This asks whether we can. A signer_mgmt job names a user or a
    role, and the host looks that up in its own copy of the tree
    (ConfJobHandler.run_signer_mgmt() through stuff.resolve_oid()). A
    host that has not synced the object yet cannot.

    That is no reason to fail the job. The object is on its way, and a
    job runs once: failed it would stay failed, and somebody would have
    to make the same job again after the sync.

    So this refuses, with JobNotReady, which is the refusal that comes
    back by itself: the nodes hear about it once, and the job is looked
    at again every round until the object is here (see
    ConfDaemon.report_refusal()).

    Only add_signer. del_signer and update_signer name something that
    may be gone for good, and waiting for it to come back would be
    waiting for ever.
    """
    if job.get('job_type') != "signer_mgmt":
        return
    if job.get('action') != "add_signer":
        return
    args = job.get('args') or {}
    signer_oid = args.get('signer')
    if not signer_oid:
        return
    from otpme.lib import oid
    from otpme.lib import stuff
    try:
        object_oid = oid.get(signer_oid)
    except Exception:
        # Not our question: what the OID looks like is checked where
        # the job is run, and a broken one has to fail, not wait.
        return
    try:
        stuff.resolve_oid(object_oid)
    except UnknownOID:
        msg = _("Signer not here yet: {signer_oid}")
        msg = msg.format(signer_oid=signer_oid)
        raise JobNotReady(msg) from None

def run_job(job, log_file):
    """ Run one job. Returns exit code and output.

    What a job does depends on the system this host runs, so the doing
    itself lives in one handler per operating system family. """
    from otpme.lib import confd
    handler = confd.get_handler(logger=config.logger)
    return handler.run(job_type=job['job_type'],
                    action=job['action'],
                    args=job['args'] or {},
                    log_file=log_file)

def build_result(job, exit_code, output, log_file, started, finished,
    status=None):
    """ What goes back to the nodes: the tail of the output, and where
    the rest of it is.

    The status comes from the exit code, unless the caller names one:
    a refusal never ran, so it is neither ok nor failed. """
    log_size = 0
    try:
        log_size = os.path.getsize(log_file)
    except OSError:
        pass
    output = output or ""
    output_truncated = False
    if len(output) > RESULT_OUTPUT_LEN:
        # The tail: the end of a run says why it failed, the beginning
        # says what it started with.
        output = output[-RESULT_OUTPUT_LEN:]
        output_truncated = True
    if status is None:
        status = "ok"
        if exit_code != 0:
            status = "failed"
    result = {
            'job_uuid'          : job['uuid'],
            'job_type'          : job['job_type'],
            'action'            : job['action'],
            'status'            : status,
            'exit_code'         : exit_code,
            'output'            : output,
            'output_truncated'  : output_truncated,
            'log_path'          : log_file,
            'log_size'          : log_size,
            'started'           : started,
            'finished'          : finished,
            }
    return result

def run_spooled_job(job_file):
    """ Run the job of the given spool file and leave its result.

    This is what the runner does: check the job again, run it, write
    what came of it. It is started detached from confd (a transient
    systemd service), so it finishes even when the daemon that started
    it is restarted -- which is what a job that restarts OTPme itself
    does to it. """
    job = read_job_file(job_file)
    job_uuid = job['uuid']
    log_file = get_log_file(job_uuid)
    started = time.time()
    try:
        verify_job(job)
    except Exception as e:
        output = _("Job refused: {reason}")
        output = output.format(reason=e)
        log_job_message(log_file, output)
        result = build_result(job=job,
                            exit_code=1,
                            output=output,
                            log_file=log_file,
                            started=started,
                            finished=time.time(),
                            status="failed")
        write_result_file(result)
        return result
    try:
        check_job_ready(job)
    except JobNotReady as e:
        output = _("Job refused: {reason}")
        output = output.format(reason=e)
        log_job_message(log_file, output)
        # A refusal, said the same way confd says it
        # (ConfDaemon.report_refusal()). Without the status this became
        # "failed" from the exit code, and a failed job is never
        # offered again -- so a job this process refused for a reason
        # that goes away was over for good, while the very same refusal
        # one step earlier was not.
        #
        # Apart from the checking above, which is final: whoever made
        # the job has to make another one, and waiting for it to run
        # would be waiting for nothing. A confd that let the job
        # through and a runner that will not run it are a moment apart
        # -- the signers of this host changed in between.
        result = build_result(job=job,
                            exit_code=1,
                            output=output,
                            log_file=log_file,
                            started=started,
                            finished=time.time(),
                            status="refused")
        write_result_file(result)
        return result
    log_message = _("Running job {job_uuid}: {job_type} {action}")
    log_message = log_message.format(job_uuid=job_uuid,
                                    job_type=job['job_type'],
                                    action=job['action'])
    log_job_message(log_file, log_message)
    try:
        exit_code, output = run_job(job, log_file)
    except Exception as e:
        exit_code = 1
        output = _("Failed to run job: {e}")
        output = output.format(e=e)
        log_job_message(log_file, output)
    result = build_result(job=job,
                        exit_code=exit_code,
                        output=output,
                        log_file=log_file,
                        started=started,
                        finished=time.time())
    log_message = _("Job finished: {status} (exit {exit_code})")
    log_message = log_message.format(status=result['status'],
                                    exit_code=result['exit_code'])
    log_job_message(log_file, log_message)
    write_result_file(result)
    return result
