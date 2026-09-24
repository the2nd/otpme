# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" What one host made of one configuration management job.

A host writes one of these for every job it ran (confd) and sends it to
its site, where it is kept after the job itself is gone -- the job is
the order, this is the history. The whole output stays on the host; what
travels is the tail of it, see OUTPUT and LOG_PATH.

One result per job and host, which is also the OID: a host that sends
the same result again, because the first attempt was lost on the way,
overwrites its own instead of piling up.
"""
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeDataObject

from otpme.lib.exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]
CONF_RESULT_DIR = os.path.join(config.data_dir, "data", "conf_result")

# How a run ended. "refused" is not a run: the host checked the job and
# said no, so it never did anything. That is why it is told apart from
# a run that failed -- a refusal may be worth another look, a run that
# happened must not repeat itself on its own.
CONF_RESULT_STATUS = [
                    'ok',
                    'failed',
                    'refused',
                    ]
# How long a result is kept. A config parameter of its own once the
# cleanup of jobs and results is there; until then this is what the
# nodes stamp on a result that comes in.
CONF_RESULT_MAX_AGE = 90 * 86400

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'job_uuid', 'host_uuid' ]
    read_oid_schema = None
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    conf_result_oid_re = (f'conf_result[|]{realm_name_re}[/]{site_name_re}'
                        f'[/]{oid.uuid_re}[/]{oid.uuid_re}')
    oid.register_oid_schema(object_type="conf_result",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=conf_result_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="conf_result",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. Between the nodes of our own site and
    nowhere else, for the same reason as the job itself. """
    config.register_cluster_sync(object_type="conf_result")

def get_conf_result_dir(realm, site, job_uuid, host_uuid):
    """ The directory of one result. """
    config_dir = os.path.join(CONF_RESULT_DIR, realm, site)
    config_dir = os.path.join(config_dir, job_uuid)
    return os.path.join(config_dir, host_uuid)

def register_backend():
    """ Register object for the file backend. """
    path_id = "conf_result"
    backend.register_data_dir(name=path_id,
                            path=CONF_RESULT_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(CONF_RESULT_DIR):
            return
        path = path.rstrip("/")
        if os.path.basename(path) == config.object_config_file_name:
            path = os.path.dirname(path)
        host_uuid = os.path.basename(path)
        if not stuff.is_uuid(host_uuid):
            return
        job_dir = os.path.dirname(path)
        job_uuid = os.path.basename(job_dir)
        if not stuff.is_uuid(job_uuid):
            return
        site_dir = os.path.dirname(job_dir)
        object_site = os.path.basename(site_dir)
        realm_dir = os.path.dirname(site_dir)
        object_realm = os.path.basename(realm_dir)
        object_id = oid.OTPmeOid(object_type="conf_result",
                                realm=object_realm,
                                site=object_site,
                                job_uuid=job_uuid,
                                host_uuid=host_uuid)
        return object_id
    def path_getter(object_id, object_uuid):
        config_dir = get_conf_result_dir(object_id.realm,
                                        object_id.site,
                                        object_id.job_uuid,
                                        object_id.host_uuid)
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
        conf_result_dir = backend.get_data_dir(path_id)
        for x_realm in filetools.list_dir(conf_result_dir):
            realm_dir = os.path.join(conf_result_dir, x_realm)
            for x_site in filetools.list_dir(realm_dir):
                site_dir = os.path.join(realm_dir, x_site)
                for job_uuid in filetools.list_dir(site_dir):
                    if not stuff.is_uuid(job_uuid):
                        continue
                    job_dir = os.path.join(site_dir, job_uuid)
                    host_dirs = [x for x in filetools.list_dir(job_dir)
                                if stuff.is_uuid(x)]
                    counter = 0
                    files_count = len(host_dirs)
                    for x in host_dirs:
                        counter += 1
                        x_path = os.path.join(job_dir, x)
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
    config.register_object_type(object_type="conf_result",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["conf_job"],
                            object_cache=256,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'job_uuid',
                                                'host_uuid'])
    # Register index attributes.
    # Which job, and which host reported it -- to its own site.
    result_types = ["conf_result"]
    config.register_index_attribute('job_uuid', sync=[],
                                    object_types=result_types)
    config.register_index_attribute('host_uuid', sync=[],
                                    object_types=result_types)
    # Which kind of job this is the result of. conf_job.py registers the
    # attribute for the job itself.
    config.register_index_attribute('job_type', sync=[],
                                    object_types=result_types)
    # What a host reported back to its own site about a job it ran.
    config.register_index_attribute('job_result_status', sync=[],
                                    object_types=result_types)
    # When the result stops being kept, read on the site that holds it.
    config.register_index_attribute('expiry', sync=[],
                                    object_types=result_types)
    # Register object to backend.
    class_getter = lambda: ConfResult
    backend.register_object_type(object_type="conf_result",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

@match_class_typing
class ConfResult(OTPmeDataObject):
    """ Class that implements the result of a configuration job. """
    def __init__(
        self,
        job_uuid: Union[str,None]=None,
        host_uuid: Union[str,None]=None,
        job_type: Union[str,None]=None,
        action: Union[str,None]=None,
        status: Union[str,None]=None,
        exit_code: Union[int,None]=None,
        output: Union[str,None]=None,
        output_truncated: bool=False,
        log_path: Union[str,None]=None,
        log_size: Union[int,None]=None,
        started: Union[float,None]=None,
        finished: Union[float,None]=None,
        expiry: Union[float,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "conf_result"
        self.job_uuid = job_uuid
        self.host_uuid = host_uuid
        self.job_type = job_type
        self.action = action
        self.status = status
        self.exit_code = exit_code
        self.output = output
        self.output_truncated = output_truncated
        self.log_path = log_path
        self.log_size = log_size
        self.started = started
        self.finished = finished
        self.expiry = expiry
        # Call parent class init.
        super().__init__(object_id=object_id, **kwargs)
        # No _sync_fields: the object goes to the nodes of our own site
        # through the cluster and to nobody else, see
        # register_sync_settings().

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'JOB_UUID'                  : {
                                                        'var_name'  : 'job_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        'HOST_UUID'                 : {
                                                        'var_name'  : 'host_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
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
                        'STATUS'                    : {
                                                        'var_name'  : 'status',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'EXIT_CODE'                 : {
                                                        'var_name'  : 'exit_code',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },
                        # The tail of the output. The whole of it stays
                        # on the host, see LOG_PATH.
                        'OUTPUT'                    : {
                                                        'var_name'  : 'output',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'OUTPUT_TRUNCATED'          : {
                                                        'var_name'  : 'output_truncated',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },
                        'LOG_PATH'                  : {
                                                        'var_name'  : 'log_path',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'LOG_SIZE'                  : {
                                                        'var_name'  : 'log_size',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },
                        'STARTED'                   : {
                                                        'var_name'  : 'started',
                                                        'type'      : float,
                                                        'required'  : True,
                                                    },
                        'FINISHED'                  : {
                                                        'var_name'  : 'finished',
                                                        'type'      : float,
                                                        'required'  : True,
                                                    },
                        'EXPIRY'                    : {
                                                        'var_name'  : 'expiry',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            job_uuid=self.job_uuid,
                            host_uuid=self.host_uuid)

    def add(self, **kwargs):
        """ Add the object. """
        if self.status not in CONF_RESULT_STATUS:
            msg = _("Unknown job result status: {status}")
            msg = msg.format(status=self.status)
            raise OTPmeException(msg)
        self.add_index('job_uuid', self.job_uuid)
        self.add_index('host_uuid', self.host_uuid)
        self.add_index('job_type', self.job_type)
        self.add_index('job_result_status', self.status)
        if self.expiry:
            self.add_index('expiry', self.expiry)
        # Call base class add method.
        return super().add(**kwargs)
