# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Making, showing and closing configuration management jobs.

This is the side of the nodes: it decides who may have a job made for
which host (allow_confd_jobs), signs the job with the sign key of the
user who asked for it, and keeps what the hosts report back. What a job
may then do to a host is decided on the host, by the signers it holds
for the job type -- see daemon/confd.py.
"""
import os
import time
from termcolor import colored

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.audit import emit_audit
from otpme.lib.messages import colored_grey
from otpme.lib.messages import colored_orange
from otpme.lib.humanize import units as humanize_units
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.data_objects.conf_job import ConfJob
from otpme.lib.classes.data_objects.conf_job import get_sign_data
from otpme.lib.classes.data_objects.conf_job import get_sign_tags
from otpme.lib.classes.data_objects.conf_job import get_job_types
from otpme.lib.classes.data_objects.conf_job import get_job_actions
from otpme.lib.classes.data_objects.conf_job import check_job_args
from otpme.lib.classes.data_objects.conf_job import check_job_objects
from otpme.lib.classes.data_objects.conf_job import CONF_JOB_MAX_AGE
from otpme.lib.classes.data_objects.conf_job import CONF_JOB_ACTIONS
from otpme.lib.classes.data_objects.conf_job import job_creation_allowed

from otpme.lib.exceptions import *

logger = config.logger
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.host"]

# How long a job may be run after it was made, if nobody says otherwise.
DEFAULT_JOB_TTL = 30 * 86400
commands = {
    'add'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['job_type', 'action'],
                    'oargs'             : [
                                        'job_args',
                                        'job_file',
                                        'job_key',
                                        'hosts',
                                        'units',
                                        'recursive',
                                        'roles',
                                        'groups',
                                        'job_ttl',
                                        ],
                    'job_type'          : 'thread',
                    },
                },
            },
    'list'   : {
            'default'    : {
                'exists'    : {
                    'oargs'             : ['host', 'failed', 'pending'],
                    'job_type'          : 'thread',
                    },
                },
            },
    # <conf_job> and not <job_uuid>: the protocol carries the UUID of the
    # server job a command runs in under that name (handle_job() in
    # mgmt1), and a command argument of the same name never reaches us.
    'show'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['conf_job'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'results'   : {
            'default'    : {
                'exists'    : {
                    'oargs'             : ['conf_job', 'host'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'ack'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['conf_job'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'cancel'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['conf_job'],
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def register():
    register_commands("deploy", commands)

def get_job(job_uuid, callback=default_callback):
    """ One job by its UUID, the way list_jobs() shows it. """
    job = backend.get_object(object_type="conf_job", uuid=job_uuid)
    if job is None:
        msg = _("Unknown job: {job_uuid}")
        msg = msg.format(job_uuid=job_uuid)
        return callback.error(msg)
    return job

def get_child_units(unit_uuid):
    """ The units below the given one, all the way down. """
    child_uuids = []
    result = backend.search(object_type="unit",
                            attribute="unit",
                            value=unit_uuid,
                            return_type="uuid")
    for x_uuid in result:
        if x_uuid in child_uuids:
            continue
        child_uuids.append(x_uuid)
        for y_uuid in get_child_units(x_uuid):
            if y_uuid in child_uuids:
                continue
            child_uuids.append(y_uuid)
    return child_uuids

def get_target_hosts(hosts=None, units=None, recursive=False,
    roles=None, groups=None, callback=default_callback):
    """ The hosts a job is meant for.

    Given by name, by the unit they are in -- with <recursive> the units
    below that one as well -- or by a role or a group that holds them.
    Resolved here and written into the job as UUIDs, because that is
    what the signature covers: a job must not change who it is for after
    it was signed, and a host moved into a unit afterwards is not part
    of a job that was made before.

    A role and a group hold hosts, never nodes (add_host() of both looks
    for a host), so those two never reach a node. """
    target_hosts = []
    if hosts:
        if isinstance(hosts, str):
            hosts = hosts.split(",")
        for x_host in hosts:
            x_host = x_host.strip()
            if not x_host:
                continue
            result = backend.search(object_types=["host", "node"],
                                    attribute="name",
                                    value=x_host,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                msg = _("Unknown host: {host}")
                msg = msg.format(host=x_host)
                return callback.error(msg)
            for x_result in result:
                if x_result in target_hosts:
                    continue
                target_hosts.append(x_result)
    if units:
        if isinstance(units, str):
            units = units.split(",")
        for x_unit in units:
            x_unit = x_unit.strip()
            if not x_unit:
                continue
            unit_result = backend.search(object_type="unit",
                                        attribute="rel_path",
                                        value=x_unit,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="uuid")
            if not unit_result:
                msg = _("Unknown unit: {unit}")
                msg = msg.format(unit=x_unit)
                return callback.error(msg)
            unit_uuids = list(unit_result)
            if recursive:
                for x_uuid in list(unit_uuids):
                    for y_uuid in get_child_units(x_uuid):
                        if y_uuid in unit_uuids:
                            continue
                        unit_uuids.append(y_uuid)
            for x_uuid in unit_uuids:
                result = backend.search(object_types=["host", "node"],
                                        attribute="unit",
                                        value=x_uuid,
                                        return_type="instance")
                for x_result in result:
                    if x_result in target_hosts:
                        continue
                    target_hosts.append(x_result)
    for x_type, x_names in [("role", roles), ("group", groups)]:
        if not x_names:
            continue
        if isinstance(x_names, str):
            x_names = x_names.split(",")
        for x_name in x_names:
            x_name = x_name.strip()
            if not x_name:
                continue
            result = backend.search(object_type=x_type,
                                    attribute="name",
                                    value=x_name,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                msg = _("Unknown {object_type}: {name}")
                msg = msg.format(object_type=x_type, name=x_name)
                return callback.error(msg)
            for x_object in result:
                for x_host in x_object.get_hosts(return_type="instance"):
                    if x_host in target_hosts:
                        continue
                    target_hosts.append(x_host)
    return target_hosts

def get_job_args(job_args=None, job_file=None, job_key=None,
    callback=default_callback):
    """ The arguments of a job, as the command line gave them.

    Every --arg is a <name>=<value>; a value with commas is a list, so
    that packages=libreoffice,gimp says what it looks like it says. The
    content of a file and the key of a repository come from files
    (--file, --key), because neither belongs on a command line. """
    args = {}
    if isinstance(job_args, dict):
        args = dict(job_args)
    elif job_args:
        if isinstance(job_args, str):
            job_args = [job_args]
        for x_arg in job_args:
            name, sep, value = str(x_arg).partition("=")
            name = name.strip()
            if not sep or not name:
                msg = _("Job argument must be <name>=<value>: {arg}")
                msg = msg.format(arg=x_arg)
                return callback.error(msg)
            if name in args:
                # Not merged and not overwritten: one of the two would
                # go missing without anybody noticing.
                msg = _("Job argument given twice, use a comma separated list: {name}")
                msg = msg.format(name=name)
                return callback.error(msg)
            if "," in value:
                value = [x.strip() for x in value.split(",") if x.strip()]
            args[name] = value
    if job_file is not None:
        args['content'] = job_file
    if job_key is not None:
        args['key'] = job_key
    return args

def add_job(job_type, action, job_args=None, job_file=None, job_key=None,
    hosts=None, units=None, recursive=False, roles=None, groups=None,
    job_ttl=None, _caller="API", callback=default_callback, **kwargs):
    """ Make a job and sign it.

    Two things have to be true for it: the token of whoever asks has to
    be named in allow_confd_jobs of every host the job is for, and that
    user has to have a sign key. Whether the job may then do anything is
    decided by the hosts, through their signers -- what we decide here
    is only who gets to ask. """
    if job_type not in CONF_JOB_ACTIONS:
        msg = _("Unknown job type: {job_type}. Known types: {job_types}")
        msg = msg.format(job_type=job_type,
                        job_types=", ".join(get_job_types()))
        return callback.error(msg)
    if action not in CONF_JOB_ACTIONS[job_type]:
        msg = _("Unknown action for job type '{job_type}': {action}. Known actions: {actions}")
        msg = msg.format(job_type=job_type,
                        action=action,
                        actions=", ".join(get_job_actions(job_type)))
        return callback.error(msg)
    job_args = get_job_args(job_args=job_args,
                            job_file=job_file,
                            job_key=job_key,
                            callback=callback)
    if not isinstance(job_args, dict):
        return job_args
    try:
        check_job_args(job_type=job_type, action=action, args=job_args)
        check_job_objects(job_type=job_type, action=action, args=job_args)
    except OTPmeException as e:
        return callback.error(str(e))

    signer = config.auth_user
    if not signer:
        msg = _("Not logged in.")
        return callback.error(msg, exception=NotLoggedIn)
    auth_token = config.auth_token
    if not auth_token:
        msg = _("No token to check against allow_confd_jobs.")
        return callback.error(msg)

    target_hosts = get_target_hosts(hosts=hosts,
                                    units=units,
                                    recursive=recursive,
                                    roles=roles,
                                    groups=groups,
                                    callback=callback)
    if not target_hosts:
        msg = _("Job without targets: use --host, --unit, --role or --group.")
        return callback.error(msg)
    for x_host in target_hosts:
        if job_creation_allowed(x_host, auth_token):
            continue
        audit_job("job_denied",
                level='warning',
                job_type=job_type,
                action=action,
                host=x_host.name,
                reason="allow_confd_jobs")
        msg = _("Token '{token}' may not have jobs made for host '{host}'.")
        msg = msg.format(token=auth_token.rel_path, host=x_host.name)
        return callback.error(msg, exception=PermissionDenied)
    target_uuids = [x.uuid for x in target_hosts]

    if job_ttl is None:
        job_ttl = DEFAULT_JOB_TTL
    else:
        try:
            job_ttl = humanize_units.time2int(job_ttl, time_unit="s")
        except Exception as e:
            msg = _("Invalid job lifetime: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
    created = time.time()
    expiry = created + job_ttl

    job_uuid = stuff.gen_uuid()
    sign_data = get_sign_data(job_uuid=job_uuid,
                            job_type=job_type,
                            action=action,
                            args=job_args,
                            targets=target_uuids,
                            created=created,
                            expiry=expiry)
    # What the user is asked about before signing: the job in words, not
    # just the hash of it.
    sign_tags = get_sign_tags(job_type=job_type,
                            action=action,
                            args=job_args,
                            target_names=[x.name for x in target_hosts])
    try:
        signature = sign_job(signer=signer,
                            job_uuid=job_uuid,
                            sign_tags=sign_tags,
                            sign_data=sign_data,
                            callback=callback)
    except Exception as e:
        msg = _("Failed to sign job: {e}")
        msg = msg.format(e=e)
        return callback.error(msg)
    if not signature:
        return callback.abort()

    job = ConfJob(realm=config.realm,
                site=config.site,
                job_uuid=job_uuid,
                job_type=job_type,
                action=action,
                args=job_args,
                targets=target_uuids,
                created=created,
                expiry=expiry,
                signature=signature,
                signer_uuid=signer.uuid,
                token_uuid=auth_token.uuid,
                token_path_cache=auth_token.rel_path)
    add_status = job.add(callback=callback)
    if not add_status:
        return add_status

    host_names = ", ".join(sorted([x.name for x in target_hosts]))
    # Said whole: what the job does and who it is for is the part that
    # matters later, and the arguments are what tells two of them
    # apart. A value too long to read is its size instead, the same way
    # the listing shows it.
    audit_job("job_created",
            job=job_uuid,
            job_type=job_type,
            action=action,
            args=get_args_summary(job_args),
            hosts=",".join(sorted([x.name for x in target_hosts])),
            host_count=len(target_hosts),
            signer=signer.name,
            expiry=int(expiry))
    msg = _("Added job {job_uuid} ({job_type} {action}) for: {hosts}")
    msg = msg.format(job_uuid=job_uuid,
                    job_type=job_type,
                    action=action,
                    hosts=host_names)
    return callback.ok(msg)

def sign_job(signer, job_uuid, sign_tags, sign_data, callback=default_callback):
    """ Have the user sign the job.

    The same way every object of OTPme is signed: the private key stays
    with the user, the key script does the signing, and the signature is
    verified before it is kept.

    The tags say what the job does and to whom. They are what the user
    is shown when asked whether to sign, and they are covered by the
    signature -- so a node cannot have a user sign one thing and then
    keep another, see get_content_tags(). """
    from otpme.lib.classes.signing import OTPmeSignature
    # Reload auth user (e.g. new keys).
    signer._load()
    sign_tags = list(sign_tags)
    sig = OTPmeSignature(signer_uuid=signer.uuid,
                        signer_oid=signer.oid.full_oid,
                        sign_obj=job_uuid,
                        sign_data=sign_data,
                        sign_ref=job_uuid,
                        tags=sign_tags)
    sign_request = {
                    'stdin_pass'    : False,
                    'key_mode'      : signer.key_mode,
                    'sign_key_type' : signer.sign_key_type,
                    'sign_info'     : sig.get_sign_info(),
                    'sign_data'     : sig.get_sign_template(),
                }
    # Request user (key script) to sign the data.
    signature = callback.sign(sign_request)
    if signature is False:
        return None
    if not signature:
        msg = _("Got empty signature.")
        raise OTPmeException(msg)
    sig.add_sign(signature)
    # What the hosts will do, done here as well: a signature we cannot
    # verify ourselves is not one to hand out.
    sig.verify(signer.sign_public_key, sign_data, tags=sign_tags)
    return sig.dumps()

def get_job_status(job, host_uuids=None):
    """ What became of a job: who has reported, and how it went. Only
    for the targets in <host_uuids>, if given.

    Returns the target names as (ok, failed, refused, pending, gone).
    Refused is told apart from failed because it is not a run: the host
    checked the job and said no, so nothing happened there.

    A host that was deleted before it reported is neither pending nor
    failed: it never will report, and the job must not wait for it. It
    stays in the targets of the job -- they are part of what was signed
    -- and is counted as gone here instead. """
    results = backend.search(object_type="conf_result",
                            attribute="job_uuid",
                            value=job.uuid,
                            return_type="instance")
    done = {}
    for x_result in results:
        done[x_result.host_uuid] = x_result.status
    pending = []
    failed = []
    refused = []
    ok = []
    gone = []
    for host_uuid in job.targets:
        if host_uuids is not None and host_uuid not in host_uuids:
            continue
        host_name = backend.get_oid(uuid=host_uuid, full=False)
        x_status = done.get(host_uuid)
        if x_status is None:
            if host_name is None:
                gone.append(str(host_uuid))
                continue
            pending.append(str(host_name))
            continue
        host_name = host_name or host_uuid
        if x_status == "ok":
            ok.append(str(host_name))
        elif x_status == "refused":
            # Not a run: the host said no before it did anything.
            refused.append(str(host_name))
        else:
            failed.append(str(host_name))
    return (sorted(ok), sorted(failed), sorted(refused),
            sorted(pending), sorted(gone))

def get_conf_job_max_age():
    """ How long jobs are kept on this site (conf_job_max_age).

    Without apply_getter=False the getter turns the value into time
    units ("3M"), which is what the CLI wants to show and what the
    cleanup below cannot count with. """
    own_site = backend.get_object(object_type="site",
                                realm=config.realm,
                                name=config.site)
    if not own_site:
        return CONF_JOB_MAX_AGE
    conf_job_max_age = own_site.get_config_parameter("conf_job_max_age",
                                                    apply_getter=False)
    if not conf_job_max_age:
        return CONF_JOB_MAX_AGE
    return int(conf_job_max_age)

def remove_outdated_jobs(still_allowed, logger):
    """ Remove the jobs that are older than conf_job_max_age, with their
    results.

    A job that failed somewhere and was not acked is kept, however old:
    somebody has to see it first. Results whose job is gone are removed
    as well.

    Runs on the master node only (see confd). <still_allowed> is asked
    before each job, so a failover stops the cleanup right away.
    Removed objects are removed on the other nodes too (cluster sync).
    Returns how many jobs were removed. """
    conf_job_max_age = get_conf_job_max_age()
    now = time.time()
    jobs = backend.search(object_type="conf_job",
                        attribute="job_type",
                        value="*",
                        return_type="instance")
    removed = 0
    kept_jobs = []
    for job in jobs:
        if not still_allowed():
            return removed
        created = job.created or 0
        if (now - created) <= conf_job_max_age:
            kept_jobs.append(job.uuid)
            continue
        ok, job_failed, job_refused, job_pending, job_gone = get_job_status(job)
        if (job_failed or job_refused) and not job.ack_time:
            log_msg = _("Keeping job {job_uuid}: it did not go through and was not acked.", log=True)[1]
            log_msg = log_msg.format(job_uuid=job.uuid)
            logger.debug(log_msg)
            kept_jobs.append(job.uuid)
            continue
        results = backend.search(object_type="conf_result",
                                attribute="job_uuid",
                                value=job.uuid,
                                return_type="instance")
        # Results first: a job without results only looks pending, a
        # result without a job is swept up below next time.
        for x_result in results:
            x_result.delete()
        job.delete()
        removed += 1
        log_msg = _("Removed job {job_uuid} ({job_type} {action}) and {count} result(s).", log=True)[1]
        log_msg = log_msg.format(job_uuid=job.uuid,
                                job_type=job.job_type,
                                action=job.action,
                                count=len(results))
        logger.info(log_msg)
    # Results of a job that is gone, for example because an earlier
    # cleanup was stopped between the results and the job.
    results = backend.search(object_type="conf_result",
                            attribute="job_uuid",
                            value="*",
                            return_type="instance")
    for x_result in results:
        if not still_allowed():
            return removed
        if x_result.job_uuid in kept_jobs:
            continue
        if backend.get_oid(uuid=x_result.job_uuid):
            continue
        x_result.delete()
        log_msg = _("Removed result of missing job {job_uuid}.", log=True)[1]
        log_msg = log_msg.format(job_uuid=x_result.job_uuid)
        logger.info(log_msg)
    return removed

def audit_job(event, level='info', **fields):
    """ Audit one thing that happened to a job.

    A job is an instruction to run something on somebody else's
    machine, so who asked for it, what it does and what became of it
    belong in the audit log. None of it goes through an object method,
    so no @audit_log sees it -- the same reason trash.py says its own.
    """
    actor = "API"
    if config.auth_token:
        actor = config.auth_token.rel_path
    emit_audit("Deploy", event, level=level, actor=actor, **fields)

def get_args_summary(args, max_len=48):
    """ The arguments of a job in one line.

    What tells two jobs apart is what they carry, so the listing shows
    it. A value too long to read -- the content of a file, the key of a
    repository -- is shown as its size instead. """
    if not args:
        return ""
    args = args.copy()
    parts = []
    for name in sorted(args):
        value = args[name]
        if isinstance(value, list):
            value = ",".join([str(x) for x in value])
        value = str(value)
        if len(value) > max_len:
            value = f"<{humanize_units.int2size(len(value))}>"
        parts.append(f"{name}={value}")
    return " ".join(parts)

def get_job_token(job):
    """ The token a job was made with, as user/token.

    Looked up by UUID, so a renamed token shows its new name; the path
    noted with the job if the token is gone. Jobs made before the token
    was noted have none. """
    if not job.token_uuid:
        return None
    token_oid = backend.get_oid(uuid=job.token_uuid, instance=True)
    if token_oid:
        return token_oid.rel_path
    return job.token_path_cache or job.token_uuid

def caller_is_admin():
    """ Whether the caller may see and do everything with jobs. """
    auth_token = config.auth_token
    if not auth_token:
        # No token: the API, used by root on a node itself.
        return True
    return auth_token.is_admin()

def get_visible_hosts(job, host_cache=None):
    """ The targets of <job> the caller may see.

    Whoever may make jobs for a host (allow_confd_jobs) may see the jobs
    of that host and what came of them; whoever made the job sees all
    of its hosts. <host_cache> keeps the answer per host for a caller
    that asks about many jobs. """
    if caller_is_admin():
        return list(job.targets)
    auth_token = config.auth_token
    if job.signer_uuid == auth_token.owner_uuid:
        return list(job.targets)
    if host_cache is None:
        host_cache = {}
    visible_hosts = []
    for host_uuid in job.targets:
        if host_uuid not in host_cache:
            x_host = backend.get_object(uuid=host_uuid)
            allowed = False
            if x_host:
                allowed = job_creation_allowed(x_host, auth_token)
            host_cache[host_uuid] = allowed
        if host_cache[host_uuid]:
            visible_hosts.append(host_uuid)
    return visible_hosts

def may_manage_job(job):
    """ Whether the caller may ack or cancel <job>.

    Both concern the whole job, so: whoever made it, or whoever may make
    jobs for every host it is for. A host that was deleted since does
    not count. """
    if caller_is_admin():
        return True
    auth_token = config.auth_token
    if job.signer_uuid == auth_token.owner_uuid:
        return True
    for host_uuid in job.targets:
        x_host = backend.get_object(uuid=host_uuid)
        if not x_host:
            continue
        if not job_creation_allowed(x_host, auth_token):
            return False
    return True

def get_visible_job(conf_job, callback=default_callback):
    """ One job, if the caller may see it.

    A job the caller may not see is unknown to them, the same answer as
    for a job that does not exist. """
    job = get_job(conf_job, callback=callback)
    if not job:
        return job
    if not get_visible_hosts(job):
        msg = _("Unknown job: {job_uuid}")
        msg = msg.format(job_uuid=conf_job)
        return callback.error(msg)
    return job

def list_jobs(host=None, failed=False, pending=False,
    _caller="API", callback=default_callback, **kwargs):
    """ The jobs of this site, oldest first. Only the jobs, and of those
    only the hosts, the caller may see (see get_visible_hosts()). """
    search_attribute = "job_type"
    search_value = "*"
    if host:
        host_result = backend.search(object_types=["host", "node"],
                                    attribute="name",
                                    value=host,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="uuid")
        if not host_result:
            msg = _("Unknown host: {host}")
            msg = msg.format(host=host)
            return callback.error(msg)
        search_attribute = "target_host"
        search_value = host_result[0]
    jobs = backend.search(object_type="conf_job",
                        attribute=search_attribute,
                        value=search_value,
                        return_type="instance")
    jobs = sorted(jobs, key=lambda x: x.created or 0)
    lines = []
    host_cache = {}
    for job in jobs:
        visible_hosts = get_visible_hosts(job, host_cache=host_cache)
        if not visible_hosts:
            continue
        ok, job_failed, job_refused, job_pending, job_gone = get_job_status(job,
                                                    host_uuids=visible_hosts)
        # --failed asks for the jobs that did not go through, and a
        # refusal is one of those.
        if failed and not (job_failed or job_refused):
            continue
        if pending and not job_pending:
            continue
        created = time.strftime("%Y-%m-%d %H:%M",
                                time.localtime(job.created or 0))
        job_status = _("{ok} ok, {failed} failed, {pending} pending")
        job_status = job_status.format(ok=len(ok),
                                    failed=len(job_failed),
                                    pending=len(job_pending))
        if job.is_cancelled():
            # The hosts that have not run it never will, so what is
            # still pending says nothing about the job anymore.
            job_status = _("cancelled, {ok} ok, {failed} failed")
            job_status = job_status.format(ok=len(ok), failed=len(job_failed))
        if job_refused:
            refused_status = _("{refused} refused")
            refused_status = refused_status.format(refused=len(job_refused))
            job_status = f"{job_status}, {refused_status}"
        if job_gone:
            gone_status = _("{gone} deleted")
            gone_status = gone_status.format(gone=len(job_gone))
            job_status = f"{job_status}, {gone_status}"
        if job.ack_time and (job_failed or job_refused):
            # Only next to what it answers: acknowledging a job that
            # worked everywhere says nothing about it.
            acked_status = _("acked")
            job_status = f"{job_status}, {acked_status}"
        hosts = _("{count} host(s)")
        hosts = hosts.format(count=len(visible_hosts))
        # The token names its user as well (user/token). A job made
        # before the token was noted shows who signed it instead.
        creator = get_job_token(job)
        if not creator:
            creator = backend.get_oid(uuid=job.signer_uuid, full=False)
            creator = str(creator or job.signer_uuid)
        job_line = [
                    job.uuid,
                    created,
                    f"{job.job_type} {job.action}",
                    get_args_summary(job.args),
                    hosts,
                    creator,
                    f"({job_status})",
                    ]
        job_line = " ".join([x for x in job_line if x])
        # At a glance, worst first: red where a host ran it and it broke,
        # yellow where a host would not run it, cyan where that has been
        # acknowledged, grey for a job that was taken back and has
        # nothing left to do, orange while a host has not run it yet,
        # green when every host ran it.
        #
        # Acknowledging is the answer to red and yellow, so it takes
        # their place: somebody has seen it, and a listing full of red
        # that nobody is going to act on hides the one line that is new.
        # It says nothing about a job that worked, which therefore stays
        # green, and nothing about one that is still running.
        #
        # Cancelled is grey once nothing is left to answer. A job that
        # was taken back is over, and over says more than what it was
        # over of -- but not while a host reported something that nobody
        # has looked at: taking a job back does not undo what it did on
        # the hosts that had it already. So after red and yellow, before
        # the cyan that says both have been seen, and before pending,
        # because the hosts counted there never will run it.
        #
        # force_color, because this runs in mgmtd and the line travels to
        # the client that prints it. Left to termcolor the color would be
        # there while the daemons run in a terminal and gone once they
        # run as daemons -- and the two colors of our own (orange, grey)
        # would stay either way, which is worse than no color at all.
        if job_failed and not job.ack_time:
            job_line = colored(job_line, "red", force_color=True)
        elif job_refused and not job.ack_time:
            job_line = colored(job_line, "yellow", force_color=True)
        elif job.is_cancelled():
            job_line = colored_grey(job_line)
        elif job_failed or job_refused:
            job_line = colored(job_line, "cyan", force_color=True)
        elif job_pending:
            job_line = colored_orange(job_line)
        else:
            job_line = colored(job_line, "green", force_color=True)
        lines.append(job_line)
    if not lines:
        return callback.ok(_("No jobs."))
    return callback.ok("\n".join(lines))

def show_job(conf_job, _caller="API", callback=default_callback, **kwargs):
    """ One job with its targets: done, failed, still waiting. Only the
    targets the caller may see. """
    job = get_visible_job(conf_job, callback=callback)
    if not job:
        return job
    visible_hosts = get_visible_hosts(job)
    ok, failed, refused, pending, gone = get_job_status(job,
                                                    host_uuids=visible_hosts)
    created = time.strftime("%Y-%m-%d %H:%M", time.localtime(job.created or 0))
    expiry = time.strftime("%Y-%m-%d %H:%M", time.localtime(job.expiry or 0))
    signer = backend.get_oid(uuid=job.signer_uuid, full=False) or job.signer_uuid
    lines = [
            f"uuid: {job.uuid}",
            f"type: {job.job_type}",
            f"action: {job.action}",
            f"args: {get_args_summary(job.args, max_len=512)}",
            f"created: {created}",
            f"expiry: {expiry}",
            f"signer: {signer}",
            f"token: {get_job_token(job) or '-'}",
            ]
    if job.cancel_time:
        cancel_user = backend.get_oid(uuid=job.cancel_user_uuid, full=False)
        cancel_time = time.strftime("%Y-%m-%d %H:%M",
                                    time.localtime(job.cancel_time))
        lines.append(f"cancelled: {cancel_time} ({cancel_user})")
    if job.ack_time:
        ack_user = backend.get_oid(uuid=job.ack_user_uuid, full=False)
        ack_time = time.strftime("%Y-%m-%d %H:%M",
                                time.localtime(job.ack_time))
        lines.append(f"acked: {ack_time} ({ack_user})")
    lines.append(f"ok: {', '.join(ok) or '-'}")
    lines.append(f"failed: {', '.join(failed) or '-'}")
    if refused:
        lines.append(f"refused: {', '.join(refused)}")
    lines.append(f"pending: {', '.join(pending) or '-'}")
    if gone:
        lines.append(f"deleted: {', '.join(gone)}")
    return callback.ok("\n".join(lines))

def show_results(conf_job=None, host=None,
    _caller="API", callback=default_callback, **kwargs):
    """ What the hosts made of a job. """
    if not conf_job and not host:
        msg = _("Need a job or a host.")
        return callback.error(msg)
    if conf_job:
        results = backend.search(object_type="conf_result",
                                attribute="job_uuid",
                                value=conf_job,
                                return_type="instance")
    else:
        host_result = backend.search(object_types=["host", "node"],
                                    attribute="name",
                                    value=host,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="uuid")
        if not host_result:
            msg = _("Unknown host: {host}")
            msg = msg.format(host=host)
            return callback.error(msg)
        results = backend.search(object_type="conf_result",
                                attribute="host_uuid",
                                value=host_result[0],
                                return_type="instance")
    results = sorted(results, key=lambda x: x.finished or 0)
    lines = []
    # The arguments belong to the job, not to its result, and several
    # results of one job would ask for the same job again and again.
    job_args = {}
    # Which hosts of a job the caller may see, per job. None: all of them.
    visible_hosts = {}
    host_cache = {}
    for result in results:
        if result.job_uuid not in visible_hosts:
            job = backend.get_object(object_type="conf_job",
                                    uuid=result.job_uuid)
            if job:
                visible_hosts[result.job_uuid] = get_visible_hosts(job,
                                                    host_cache=host_cache)
            elif caller_is_admin():
                # A result whose job is gone: without the job there is
                # nothing to decide by, so only an admin sees it.
                visible_hosts[result.job_uuid] = None
            else:
                visible_hosts[result.job_uuid] = []
        job_hosts = visible_hosts[result.job_uuid]
        if job_hosts is not None and result.host_uuid not in job_hosts:
            continue
        host_name = backend.get_oid(uuid=result.host_uuid, full=False)
        host_name = host_name or result.host_uuid
        finished = time.strftime("%Y-%m-%d %H:%M",
                                time.localtime(result.finished or 0))
        if result.job_uuid not in job_args:
            job = backend.get_object(object_type="conf_job",
                                    uuid=result.job_uuid)
            # A job that is already cleaned up leaves its result behind,
            # so there is not always one to ask.
            job_args[result.job_uuid] = get_args_summary(job.args) if job else ""
        if lines:
            # One empty line between what two runs said.
            lines.append("")
        header = [
                "###",
                str(host_name),
                f"{result.job_type} {result.action}",
                job_args[result.job_uuid],
                result.status,
                f"(exit {result.exit_code})",
                finished,
                f"job {result.job_uuid}",
                ]
        header = " ".join([x for x in header if x])
        # How a run ended is the one thing to see at a glance when
        # scrolling through the output of a dozen hosts. The same colors
        # a job has in the listing (see list_jobs()): a refusal is not a
        # run that went wrong.
        if result.status == "ok":
            header = colored(header, "green", force_color=True)
        elif result.status == "refused":
            header = colored(header, "yellow", force_color=True)
        else:
            header = colored(header, "red", force_color=True)
        lines.append(header)
        if result.output:
            lines.append(result.output.rstrip("\n"))
        if result.output_truncated:
            hint = _("[output truncated, whole log on the host: {log_path} ({log_size} bytes)]")
            hint = hint.format(log_path=result.log_path,
                            log_size=result.log_size)
            lines.append(hint)
    if not lines:
        return callback.ok(_("No results."))
    return callback.ok("\n".join(lines))

def ack_job(conf_job, _caller="API", callback=default_callback, **kwargs):
    """ Note that somebody has seen a job that failed somewhere.

    A job is removed after conf_job_max_age. One that failed somewhere stays
    until this: nobody should have to find out from a log that something
    went wrong weeks ago. """
    job = get_visible_job(conf_job, callback=callback)
    if not job:
        return job
    if not may_manage_job(job):
        msg = _("Permission denied: {job_uuid}")
        msg = msg.format(job_uuid=conf_job)
        return callback.error(msg, exception=PermissionDenied)
    auth_token = config.auth_token
    job.ack_time = time.time()
    if auth_token:
        job.ack_user_uuid = auth_token.owner_uuid
    job._write(callback=callback)
    audit_job("job_acked",
            job=job.uuid,
            job_type=job.job_type,
            action=job.action)
    msg = _("Job acknowledged: {job_uuid}")
    msg = msg.format(job_uuid=conf_job)
    return callback.ok(msg)

def cancel_job(conf_job, _caller="API", callback=default_callback, **kwargs):
    """ Take back a job.

    A host that has not asked for it yet will never see it. What was
    done is done, and the results of it stay.

    Noted on the job rather than done by deleting it: somebody looking
    for a job that never ran on half the hosts has to be able to see
    that it was taken back, not just that it is gone. """
    job = get_visible_job(conf_job, callback=callback)
    if not job:
        return job
    if not may_manage_job(job):
        msg = _("Permission denied: {job_uuid}")
        msg = msg.format(job_uuid=conf_job)
        return callback.error(msg, exception=PermissionDenied)
    if job.is_cancelled():
        msg = _("Job is cancelled already: {job_uuid}")
        msg = msg.format(job_uuid=conf_job)
        return callback.error(msg)
    auth_token = config.auth_token
    job.cancel_time = time.time()
    if auth_token:
        job.cancel_user_uuid = auth_token.owner_uuid
    job._write(callback=callback)
    audit_job("job_cancelled",
            job=job.uuid,
            job_type=job.job_type,
            action=job.action)
    msg = _("Job cancelled: {job_uuid}")
    msg = msg.format(job_uuid=conf_job)
    return callback.ok(msg)
