# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" A signed job for the configuration management of hosts.

A job is one command for a fixed set of hosts: install a package, add a
repository, write a file. A user creates it and signs it with their sign
key. The hosts it names fetch it from their site (confd asks syncd), and
before a host runs anything it verifies the signature against the
signers it was given for that job type (config/signers/<job type>/, see
classes/signing.py). What may be done to a host is therefore decided on
the host itself, not by whoever reaches the nodes.

The job is immutable once it exists: the signature covers everything
that says what is to happen, to whom, and until when -- see
get_sign_data(). Only what the nodes note about it afterwards, that
somebody has seen a failed run, is written later.
"""
import os
import time
from typing import List
from typing import Union

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
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.locking import object_lock
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeBaseObject
from otpme.lib.classes.otpme_object import OTPmeDataObject
from otpme.lib.classes.otpme_object import token_role_list_setter
from otpme.lib.classes.otpme_object import token_role_list_getter
from otpme.lib.classes.otpme_object import token_role_list_allows

from otpme.lib.exceptions import *

logger = config.logger
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]
CONF_JOB_DIR = os.path.join(config.data_dir, "data", "conf_job")

# The job types, and what each of them may be asked to do. Every type is
# a signer type of its own (classes/signing.py): a host runs a job only
# if it holds a signer for that type, so the right to install a package
# is not also the right to swap the signers of the host.
#
# Each action says which arguments it needs and which it may have, so a
# job that cannot work is refused where it is made instead of failing on
# every host it was sent to. What the values may look like is checked by
# the host, which is the one that has to work with them
# (otpme/lib/confd).
# How long a job and its results are kept by default (conf_job_max_age).
CONF_JOB_MAX_AGE = 90 * 86400

CONF_JOB_ACTIONS = {
                'repo_mgmt'     : {
                                'add_repo'  : {
                                    'args'  : ['name', 'line', 'key'],
                                    },
                                'del_repo'  : {
                                    'args'  : ['name'],
                                    },
                                'update'    : {},
                                },
                'sw_mgmt'       : {
                                'install'   : {
                                    'args'  : ['packages'],
                                    },
                                'remove'    : {
                                    'args'  : ['packages'],
                                    'oargs' : ['autoremove'],
                                    },
                                'upgrade'   : {
                                    'args'  : ['packages'],
                                    },
                                'autoremove': {},
                                },
                'signer_mgmt'   : {
                                # Asks and changes nothing, so it names
                                # no signer: without a type it answers
                                # with every signer the host holds.
                                'show_signer'   : {
                                    'oargs' : ['type'],
                                    },
                                'add_signer'    : {
                                    'args'  : ['type', 'signer'],
                                    'oargs' : ['tags'],
                                    },
                                # remove_last_own_signer allows a job to
                                # take away the signer it was signed by,
                                # which locks whoever signed it out of
                                # this host (see check_self_lockout).
                                'del_signer'    : {
                                    'args'  : ['type', 'signer'],
                                    'oargs' : ['remove_last_own_signer'],
                                    },
                                'update_signer' : {
                                    'args'  : ['type', 'signer'],
                                    'oargs' : ['remove_gone',
                                            'remove_last_own_signer'],
                                    },
                                },
                'service_mgmt'  : {
                                'start'     : {
                                    'args'  : ['unit'],
                                    },
                                'stop'      : {
                                    'args'  : ['unit'],
                                    },
                                'restart'   : {
                                    'args'  : ['unit'],
                                    },
                                'enable'    : {
                                    'args'  : ['unit'],
                                    },
                                'disable'   : {
                                    'args'  : ['unit'],
                                    },
                                },
                'file_mgmt'     : {
                                'put_file'  : {
                                    'args'  : ['path', 'content'],
                                    'oargs' : ['mode', 'owner', 'group'],
                                    },
                                'del_file'  : {
                                    'args'  : ['path'],
                                    },
                                },
                'host_mgmt'     : {
                                'reboot'        : {},
                                'dist_upgrade'  : {},
                                },
                }

def register():
    register_oid()
    register_backend()
    register_sync_settings()
    register_config_params()

def register_config_params():
    """ Register config parameters. """
    # Who may have a job made for a host at all. The signers of the host
    # decide what may be done to it; this decides who gets to ask, and it
    # is resolved per target host, so a role can be allowed to work on
    # the hosts of one unit and nowhere else. Unset means nobody.
    config.register_config_parameter(name="allow_confd_jobs",
                                    ctype=list,
                                    warn_if_exists=True,
                                    setter=token_role_list_setter,
                                    getter=token_role_list_getter,
                                    object_types=[
                                                'site',
                                                'unit',
                                                'host',
                                                'node',
                                                ])
    # How long a job is kept, with its results. A job that went through
    # is kept as well: the list of jobs is also the record of what was
    # sent, and without it nobody can tell whether a job was sent
    # already. A job that failed somewhere is kept until it is acked.
    #
    # Stored as seconds, shown in time units. The cleanup wants the
    # seconds, so it reads the value with apply_getter=False -- see
    # deploy.get_conf_job_max_age().
    def conf_job_max_age_setter(max_age, **kwargs):
        from otpme.lib.humanize import units
        try:
            max_age = units.time2int(max_age, time_unit="s")
        except Exception as err:
            msg = _("Invalid job max age.")
            raise ValueError(msg) from err
        if max_age < 86400:
            msg = _("Job max age must be at least one day.")
            raise ValueError(msg)
        return max_age
    def conf_job_max_age_getter(max_age, **kwargs):
        from otpme.lib.humanize import units
        try:
            return units.int2time(max_age, time_unit="s")[0]
        except Exception as err:
            msg = _("Invalid job max age.")
            raise ValueError(msg) from err
    config.register_config_parameter(name="conf_job_max_age",
                                    ctype=int,
                                    setter=conf_job_max_age_setter,
                                    getter=conf_job_max_age_getter,
                                    default_value=CONF_JOB_MAX_AGE,
                                    object_types=['site'])

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'uuid' ]
    read_oid_schema = None
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    conf_job_oid_re = (f'conf_job[|]{realm_name_re}'
                        f'[/]{site_name_re}[/]{oid.uuid_re}')
    oid.register_oid_schema(object_type="conf_job",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=conf_job_oid_re)
    rel_path_getter = lambda x: x[-1:]
    oid.register_rel_path_getter(object_type="conf_job",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings.

    Between the nodes of our own site and nowhere else. A job says what
    is to be done to one of our hosts, which is no business of another
    site, and the hosts ask for their jobs themselves (confd) instead of
    being sent them. """
    config.register_cluster_sync(object_type="conf_job")

def get_conf_job_dir(realm, site, job_uuid):
    """ The directory of one job. """
    config_dir = os.path.join(CONF_JOB_DIR, realm, site)
    return os.path.join(config_dir, job_uuid)

def register_backend():
    """ Register object for the file backend. """
    path_id = "conf_job"
    backend.register_data_dir(name=path_id,
                            path=CONF_JOB_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(CONF_JOB_DIR):
            return
        path = path.rstrip("/")
        if os.path.basename(path) == config.object_config_file_name:
            path = os.path.dirname(path)
        job_uuid = os.path.basename(path)
        if not stuff.is_uuid(job_uuid):
            return
        site_dir = os.path.dirname(path)
        object_site = os.path.basename(site_dir)
        realm_dir = os.path.dirname(site_dir)
        object_realm = os.path.basename(realm_dir)
        object_id = oid.OTPmeOid(object_type="conf_job",
                                realm=object_realm,
                                site=object_site,
                                uuid=job_uuid)
        return object_id
    def path_getter(object_id, object_uuid):
        config_dir = get_conf_job_dir(object_id.realm,
                                    object_id.site,
                                    object_id.uuid)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild(object_dir=None):
        if object_dir:
            object_dir = object_dir.rstrip("/")
        conf_job_dir = backend.get_data_dir(path_id)
        for x_realm in filetools.list_dir(conf_job_dir):
            realm_dir = os.path.join(conf_job_dir, x_realm)
            for x_site in filetools.list_dir(realm_dir):
                site_dir = os.path.join(realm_dir, x_site)
                job_dirs = [x for x in filetools.list_dir(site_dir)
                            if stuff.is_uuid(x)]
                counter = 0
                files_count = len(job_dirs)
                for x in job_dirs:
                    counter += 1
                    x_path = os.path.join(site_dir, x)
                    if object_dir:
                        if x_path != object_dir:
                            continue
                    x_file = os.path.join(x_path, config.object_config_file_name)
                    log_msg = _("Processing {path_id} ({counter}/{files_count}): {x_file}", log=True)[1]
                    log_msg = log_msg.format(path_id=path_id,
                                            counter=counter,
                                            files_count=files_count,
                                            x_file=x_file)
                    logger.debug(log_msg)
                    x_oid = oid_getter(x_path)
                    if not x_oid:
                        continue
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="conf_job",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["host"],
                            object_cache=256,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'uuid'])
    # Register index attributes.
    # A config job is handed out by the site that runs it, to the host
    # it names. No other site has anything to do with it.
    job_types = ["conf_job"]
    config.register_index_attribute('job_type', sync=[],
                                    object_types=job_types)
    config.register_index_attribute('target_host', sync=[],
                                    object_types=job_types)
    # Who signed the job. A revoked signature says the same thing and
    # needs it everywhere, see revoked_signature.py; a config job is
    # run by the site that hands it out and by nobody else.
    config.register_index_attribute('signer_uuid', sync=[],
                                    object_types=job_types)
    # When the job stops being valid. confd reads it off the job rather
    # than the index; the used hashes carry one too, see used_hash.py.
    config.register_index_attribute('expiry', sync=[],
                                    object_types=job_types)
    # Register object to backend.
    class_getter = lambda: ConfJob
    backend.register_object_type(object_type="conf_job",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

def get_job_types():
    """ The job types there are. """
    return sorted(CONF_JOB_ACTIONS)

def get_job_actions(job_type):
    """ The actions the given job type knows. """
    try:
        return sorted(CONF_JOB_ACTIONS[job_type])
    except KeyError:
        msg = _("Unknown job type: {job_type}")
        msg = msg.format(job_type=job_type)
        raise OTPmeException(msg) from None

def check_job_args(job_type, action, args):
    """ Whether the arguments of a job are the ones its action needs.

    Checked where the job is made, so a missing path does not become a
    failed run on every host it was sent to, and again on the host,
    which trusts nothing it is sent. """
    try:
        action_args = CONF_JOB_ACTIONS[job_type][action]
    except KeyError:
        msg = _("Unknown action for job type '{job_type}': {action}")
        msg = msg.format(job_type=job_type, action=action)
        raise OTPmeException(msg) from None
    required_args = action_args.get('args', [])
    optional_args = action_args.get('oargs', [])
    known_args = required_args + optional_args
    if args is None:
        args = {}
    missing_args = [x for x in required_args if x not in args]
    if missing_args:
        msg = _("Job misses argument(s): {args}")
        msg = msg.format(args=", ".join(missing_args))
        raise OTPmeException(msg)
    unknown_args = [str(x) for x in args if x not in known_args]
    if unknown_args:
        msg = _("Unknown job argument(s): {args}. Known: {known}")
        msg = msg.format(args=", ".join(sorted(unknown_args)),
                        known=", ".join(known_args) or "-")
        raise OTPmeException(msg)

def check_job_objects(job_type, action, args):
    """ Whether what a job names exists at all.

    A signer_mgmt job names a user or a role, and the host looks it up
    in its own copy of the tree. A name nobody ever had is a typo, and
    a typo should be said here rather than come back as a refusal from
    every host, for ever.

    A host that has the object still to come is another matter and not
    this one: the host refuses such a job and runs it once the object
    arrives, see confd/job.py check_job_ready().
    """
    if job_type != "signer_mgmt":
        return
    if action not in ("add_signer", "del_signer", "update_signer"):
        return
    if not args:
        return
    signer_oid = args.get('signer')
    if not signer_oid:
        return
    # del_signer and update_signer may name the signer entry of a host
    # by its uuid, which is what is left once the object is deleted
    # (see ConfJobHandler.run_signer_mgmt()). Nothing here can say
    # anything about such a uuid: the entry is on the host.
    if stuff.is_uuid(signer_oid):
        if action == "add_signer":
            msg = _("add_signer needs a user or a role: {signer_oid}")
            msg = msg.format(signer_oid=signer_oid)
            raise OTPmeException(msg)
        return
    try:
        object_oid = oid.get(signer_oid)
    except Exception as e:
        msg = _("Invalid signer: {signer_oid}")
        msg = msg.format(signer_oid=signer_oid)
        raise OTPmeException(msg) from e
    if object_oid.object_type not in ("user", "role"):
        msg = _("Not a user or role: {signer_oid}")
        msg = msg.format(signer_oid=signer_oid)
        raise OTPmeException(msg)
    if not backend.get_uuid(object_oid):
        msg = _("Unknown signer: {signer_oid}")
        msg = msg.format(signer_oid=signer_oid)
        raise OTPmeException(msg)

def job_creation_allowed(host, token):
    """ Whether <token> may have a job made for <host>.

    allow_confd_jobs of the host, of its unit, of its site -- the most
    specific one wins, like every config parameter. It holds the UUIDs
    of tokens and of roles; a token counts as named when it is in a
    named role, however deep the role nesting goes.

    This is the half of the decision the nodes make. What the job may
    then do to the host is decided by the host, through the signers it
    holds for the job type -- neither half replaces the other. """
    try:
        allowed = host.get_config_parameter("allow_confd_jobs",
                                            apply_getter=False)
    except Exception:
        allowed = None
    return token_role_list_allows(allowed, token)

# How much of an argument goes into the tags of a signature. What is
# longer is named by its size and its hash: a user who is asked whether
# to sign something has to be able to read it, and 5 KiB of file content
# in a yes/no question is not read by anybody.
ARG_TAG_MAX_LEN = 64

def get_arg_tag_value(value):
    """ One argument of a job, short enough to be read.

    A value too long for that is named by its size and its hash, which
    is what one can compare against the file it came from:

        sha256sum <file>
    """
    if isinstance(value, (list, tuple)):
        value = ",".join([str(x) for x in value])
    value = str(value)
    if len(value) > ARG_TAG_MAX_LEN:
        value_hash = stuff.gen_sha256(value)
        value = f"<{len(value)} bytes, sha256:{value_hash}>"
    return value

def get_content_tags(job_type, action, args):
    """ The tags that say what a job does.

    They are part of the signature (its ID is the hash of its tags), so
    they cannot be changed after signing, and they are what the user is
    shown when asked whether to sign it -- everything else about a
    signature is a hash. The host builds them again from the job it got
    and refuses one whose tags say something else than the job does.
    """
    tags = [
        f"job_type:{job_type}",
        f"action:{action}",
        ]
    if args:
        args = args.copy()
        for name in sorted(args):
            tags.append(f"arg:{name}={get_arg_tag_value(args[name])}")
    return tags

def get_sign_tags(job_type, action, args, target_names):
    """ The tags of a job signature: what it does, and to whom. """
    tags = get_content_tags(job_type, action, args)
    tags.append(f"targets:{len(target_names)}")
    for target_name in sorted(target_names):
        tags.append(f"target:{target_name}")
    return tags

def get_sign_data(job_uuid, job_type, action, args, targets, created, expiry):
    """ What the signature of a job covers, as a base64 string.

    Everything that says what is to happen, to whom, and until when. The
    same string is built when a job is signed and when a host verifies
    it, so it is built here and nowhere else.

    The targets are sorted: the signature must not depend on the order
    somebody wrote them down in. """
    if args is None:
        args = {}
    if targets is None:
        targets = []
    # A job is signed on a node, where its arguments are the dict of an
    # object config, and verified on a host, where they came off the
    # wire as plain ones. copy() gives a plain dict or list for either,
    # so both sides hash the same thing.
    sign_data = {
                'uuid'      : job_uuid,
                'job_type'  : job_type,
                'action'    : action,
                'args'      : args.copy(),
                'targets'   : sorted(targets.copy()),
                'created'   : created,
                'expiry'    : expiry,
                }
    return json.encode(data=sign_data, sort_keys=True, encoding="base64")

@match_class_typing
class ConfJob(OTPmeDataObject):
    """ Class that implements a configuration management job. """
    def __init__(
        self,
        job_uuid: Union[str,None]=None,
        job_type: Union[str,None]=None,
        action: Union[str,None]=None,
        args: Union[dict,None]=None,
        targets: Union[List,None]=None,
        created: Union[float,None]=None,
        expiry: Union[float,None]=None,
        signature: Union[str,None]=None,
        signer_uuid: Union[str,None]=None,
        token_uuid: Union[str,None]=None,
        token_path_cache: Union[str,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "conf_job"
        # The UUID is part of the OID, so unlike the other data objects
        # this one cannot wait for add() to generate it. It goes to the
        # base class, which sets self.uuid before set_oid() runs.
        self.job_type = job_type
        self.action = action
        self.created = created
        self.expiry = expiry
        self.signature = signature
        self.signer_uuid = signer_uuid
        # The token the job was made with: the one allow_confd_jobs was
        # checked against. Its path is kept too, so a job still says
        # which token it was after the token is gone.
        self.token_uuid = token_uuid
        self.token_path_cache = token_path_cache
        # What the nodes note about the job, and what the signature
        # therefore does not cover: who has seen that it failed
        # somewhere, and who took it back.
        self.ack_time = None
        self.ack_user_uuid = None
        self.cancel_time = None
        self.cancel_user_uuid = None
        # Call parent class init.
        super().__init__(object_id=object_id, uuid=job_uuid, **kwargs)
        # List and dict attributes must be set after calling super because
        # self.incremental_update is only available after calling super.
        self.args = args
        self.targets = targets
        # No _sync_fields: the object goes to the nodes of our own site
        # through the cluster and to nobody else, see
        # register_sync_settings().

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'JOB_TYPE'                  : {
                                                        'var_name'  : 'job_type',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'ACTION'                    : {
                                                        'var_name'  : 'action',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'ARGS'                      : {
                                                        'var_name'  : 'args',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
                        'TARGETS'                   : {
                                                        'var_name'  : 'targets',
                                                        'type'      : list,
                                                        'required'  : True,
                                                    },
                        'CREATED'                   : {
                                                        'var_name'  : 'created',
                                                        'type'      : float,
                                                        'required'  : True,
                                                    },
                        'EXPIRY'                    : {
                                                        'var_name'  : 'expiry',
                                                        'type'      : float,
                                                        'required'  : True,
                                                    },
                        'SIGNATURE'                 : {
                                                        'var_name'  : 'signature',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'SIGNER_UUID'               : {
                                                        'var_name'  : 'signer_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        # Not required: jobs made before it was noted
                        # have none.
                        'TOKEN_UUID'                : {
                                                        'var_name'  : 'token_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'TOKEN_PATH_CACHE'          : {
                                                        'var_name'  : 'token_path_cache',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'ACK_TIME'                  : {
                                                        'var_name'  : 'ack_time',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        'ACK_USER_UUID'             : {
                                                        'var_name'  : 'ack_user_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'CANCEL_TIME'               : {
                                                        'var_name'  : 'cancel_time',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        'CANCEL_USER_UUID'          : {
                                                        'var_name'  : 'cancel_user_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            uuid=self.uuid)

    def get_sign_data(self):
        """ What our signature covers. """
        return get_sign_data(job_uuid=self.uuid,
                            job_type=self.job_type,
                            action=self.action,
                            args=self.args,
                            targets=self.targets,
                            created=self.created,
                            expiry=self.expiry)

    def is_expired(self):
        """ Whether the job is past its expiry. """
        if not self.expiry:
            return False
        return time.time() > self.expiry

    def is_cancelled(self):
        """ Whether the job was taken back. """
        return bool(self.cancel_time)

    @object_lock(full_lock=True)
    def add(
        self,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        write: bool=True,
        **kwargs,
        ):
        """ Add the object. """
        if self.job_type not in CONF_JOB_ACTIONS:
            msg = _("Unknown job type: {job_type}")
            msg = msg.format(job_type=self.job_type)
            return callback.error(msg)
        if self.action not in CONF_JOB_ACTIONS[self.job_type]:
            msg = _("Unknown action for job type '{job_type}': {action}")
            msg = msg.format(job_type=self.job_type, action=self.action)
            return callback.error(msg)
        if not self.targets:
            msg = _("Job without targets.")
            return callback.error(msg)
        if not self.uuid:
            msg = _("Job without UUID.")
            return callback.error(msg)
        if backend.object_exists(self.oid):
            msg = _("Job already exists.")
            return callback.error(msg, exception=AlreadyExists)
        self.add_index('job_type', self.job_type)
        if self.signer_uuid:
            self.add_index('signer_uuid', self.signer_uuid)
        for host_uuid in self.targets:
            self.add_index('target_host', host_uuid)
        if self.expiry:
            self.add_index('expiry', self.expiry)
        # Not OTPmeDataObject.add(): that one generates a UUID, and ours
        # is part of the OID and covered by the signature.
        return OTPmeBaseObject.add(self,
                                verbose_level=verbose_level,
                                callback=callback,
                                write=write,
                                **kwargs)
