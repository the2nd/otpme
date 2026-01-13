# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#from typing import List
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeDataObject

from otpme.lib.exceptions import *

logger = config.logger
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]
JOBS_DIR = os.path.join(config.data_dir, "data", "jobs")

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'uuid' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    job_oid_re = (f'job|{realm_name_re}[/]{site_name_re}[/]{oid.uuid_re}')
    oid.register_oid_schema(object_type="job",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=job_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="job",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_cluster_sync(object_type="job")

def register_backend():
    """ Register object for the file backend. """
    path_id = "job"
    backend.register_data_dir(name=path_id,
                            path=JOBS_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(JOBS_DIR):
            return
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        if x_dir_name != path_id:
            return
        object_realm = os.path.dirname(path)
        object_realm = os.path.dirname(object_realm)
        object_realm = os.path.dirname(object_realm)
        object_realm = os.path.basename(object_realm)
        object_site = os.path.dirname(path)
        object_site = os.path.dirname(object_site)
        object_site = os.path.basename(object_site)
        job_uuid = os.path.dirname(path)
        job_uuid = os.path.basename(job_uuid)
        object_id = oid.OTPmeOid(object_type="job",
                                realm=object_realm,
                                site=object_site,
                                uuid=job_uuid)
        return object_id
    def path_getter(object_id, object_uuid):
        jobs_dir = backend.get_data_dir(path_id)
        realm = object_id.realm
        site = object_id.site
        job_uuid = object_id.uuid
        config_dir = os.path.join(jobs_dir, realm, site)
        config_dir = os.path.join(config_dir, job_uuid)
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
        jobs_dir = backend.get_data_dir(path_id)
        for realm_dir in filetools.list_dir(jobs_dir):
            realm_dir = os.path.join(jobs_dir, realm_dir)
            for sites_dir in filetools.list_dir(realm_dir):
                sites_dir = os.path.join(realm_dir, sites_dir)
                for job_uuid in filetools.list_dir(sites_dir):
                    if not stuff.is_uuid(job_uuid):
                        continue
                    job_dir = os.path.join(sites_dir, job_uuid)
                    job_files = filetools.list_dir(job_dir)
                    counter = 0
                    files_count = len(job_files)
                    for x in job_files:
                        counter += 1
                        x_path = os.path.join(job_dir, x)
                        if object_dir:
                            if x_path != x_path:
                                continue
                        x_file = os.path.join(x_path, config.object_config_file_name)
                        log_msg = _("Processing {path_id} ({counter}/{files_count}): {x_file}", log=True)[1]
                        log_msg = log_msg.format(path_id=path_id,
                                                counter=counter,
                                                files_count=files_count,
                                                x_file=x_file)
                        logger.debug(log_msg)
                        x_oid = oid_getter(x_path)
                        backend.index_add(object_id=x_oid,
                                        object_config="auto",
                                        full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="job",
                            tree_object=False,
                            uniq_name=False,
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'uuid'])
    # Register object to backend.
    class_getter = lambda: OTPmeTreeJob
    backend.register_object_type(object_type="job",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)
    # Register search attributes.
    config.register_index_attribute('job_name')
    config.register_index_attribute('job_status')

@match_class_typing
class OTPmeTreeJob(OTPmeDataObject):
    """ Class that implements OTPme tree job object. """
    def __init__(
        self,
        realm: str=None,
        site: str=None,
        src_realm: str=None,
        src_site: str=None,
        job_name: Union[str,None]=None,
        job_data: Union[dict,None]={},
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "job"
        self.realm = realm
        self.site = site
        self.src_realm = src_realm
        self.src_site = src_site
        self.job_name = job_name
        self.job_status = "New"
        self.uuid = stuff.gen_uuid()
        # Call parent class init.
        super(OTPmeTreeJob, self).__init__(realm=self.realm,
                                            site=self.site,
                                            uuid=self.uuid,
                                            object_id=object_id,
                                            **kwargs)
        # List and dict attributes must be set after calling super because
        # self.incremental_update is only available after calling super.
        self.job_data = job_data
        self.valid_actions = [
                                'add_gidnumber',
                                'add_token_to_role',
                                'add_token_to_group',
                                'add_default_group_user',
                            ]

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'SRC_REALM'                 : {
                                                        'var_name'  : 'src_realm',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'SRC_SITE'                  : {
                                                        'var_name'  : 'src_site',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'JOB_NAME'                  : {
                                                        'var_name'  : 'job_name',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'JOB_DATA'                 : {
                                                        'var_name'  : 'job_data',
                                                        'type'      : dict,
                                                        'required'  : True,
                                                    },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            uuid=self.uuid)

    def add(self):
        """ Add the object. """
        self.add_index('job_name', self.job_name)
        self.add_index('job_status', self.job_status)
        # Call base class add method.
        return super(OTPmeTreeJob, self).add()

    @property
    def action(self):
        try:
            action = self.job_data['action']
        except KeyError:
            msg, log_msg = _("Job data misses action.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        return action

    def add_gidnumber(self, check_only, callback):
        try:
            user_uuid = self.job_data['user_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses user UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        # Try to get user.
        user = backend.get_object(uuid=user_uuid)
        if not user:
            msg, log_msg = _("Unknown user: {user_uuid}", log=True)
            log_msg = log_msg.format(user_uuid=user_uuid)
            logger.warning(log_msg)
            msg = msg.format(user_uuid=user_uuid)
            raise OTPmeException(msg)
        if not user.group_uuid:
            msg, log_msg = _("User without default group: {user}", log=True)
            log_msg = log_msg.format(user=user)
            logger.warning(log_msg)
            msg = msg.format(user=user)
            raise OTPmeException(msg)
        if check_only:
            return
        # Add gidNumber attribute.
        try:
            status = user.add_attribute(attribute="gidNumber",
                                        ignore_ro=True,
                                        verify_acls=False,
                                        callback=callback)
        except Exception as e:
            msg, log_msg = _("Adding gidNumber failed: {user}", log=True)
            log_msg = log_msg.format(user=user)
            logger.warning(log_msg)
            msg = msg.format(user=user)
            raise OTPmeException(msg)
        if status is False:
            msg = f"Failed: {callback.job.return_value}"
            logger.warning(msg)
            raise OTPmeException(msg)
        # Write objects on success.
        callback.write_modified_objects()

    def add_token_to_role(self, check_only, callback):
        try:
            role_uuid = self.job_data['role_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses role UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        try:
            token_uuid = self.job_data['token_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses user UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        # Try to get role.
        role = backend.get_object(uuid=role_uuid)
        if not role:
            msg, log_msg = _("Unknown role: {role_uuid}", log=True)
            log_msg = log_msg.format(role_uuid=role_uuid)
            logger.warning(log_msg)
            msg = msg.format(role_uuid=role_uuid)
            raise OTPmeException(msg)
        # Try to get token.
        token = backend.get_object(uuid=token_uuid)
        if token:
            token_path = token.rel_path
        else:
            if not check_only:
                msg, log_msg = _("Unknown token: {token_uuid}", log=True)
                log_msg = log_msg.format(token_uuid=token_uuid)
                logger.warning(log_msg)
                msg = msg.format(token_uuid=token_uuid)
                raise OTPmeException(msg)
            token_path = "dummyuser/dummytoken"
        verify_acls = False
        verify_acls_only = False
        if check_only:
            verify_acls = True
            verify_acls_only = check_only
        try:
            status = role.add_token(token_path=token_path,
                                    callback=callback,
                                    verify_acls=verify_acls,
                                    verify_acls_only=verify_acls_only)
        except Exception as e:
            log_msg = _("Error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.warning(log_msg)
            msg = _("Error adding token.")
            raise OTPmeException(msg)
        if status is False:
            if verify_acls_only:
                msg = _("Permission denied.")
                raise OTPmeException(msg)
            else:
                msg = f"Failed: {callback.job.return_value}"
                raise OTPmeException(msg)
        # Write objects on success.
        if not check_only:
            callback.write_modified_objects()

    def add_token_to_group(self, check_only, callback):
        try:
            group_uuid = self.job_data['group_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses group UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        try:
            token_uuid = self.job_data['token_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses user UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        # Try to get group.
        group = backend.get_object(uuid=group_uuid)
        if not group:
            msg, log_msg = _("Unknown group: {group_uuid}", log=True)
            log_msg = log_msg.format(group_uuid=group_uuid)
            logger.warning(log_msg)
            msg = msg.format(group_uuid=group_uuid)
            raise OTPmeException(msg)
        # Try to get token.
        token = backend.get_object(uuid=token_uuid)
        if token:
            token_path = token.rel_path
        else:
            if not check_only:
                msg, log_msg = _("Unknown token: {token_uuid}", log=True)
                log_msg = log_msg.format(token_uuid=token_uuid)
                logger.warning(log_msg)
                msg = msg.format(token_uuid=token_uuid)
                raise OTPmeException(msg)
            token_path = "dummyuser/dummytoken"
        verify_acls = False
        verify_acls_only = False
        if check_only:
            verify_acls = True
            verify_acls_only = check_only
        try:
            status = group.add_token(token_path=token_path,
                                    callback=callback,
                                    verify_acls=verify_acls,
                                    verify_acls_only=verify_acls_only)
        except Exception as e:
            log_msg = _("Error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.warning(log_msg)
            msg = _("Error adding token.")
            raise OTPmeException(msg)
        if status is False:
            if verify_acls_only:
                msg = _("Permission denied.")
                raise OTPmeException(msg)
            msg = f"Failed: {callback.job.return_value}"
            raise OTPmeException(msg)
        # Write objects on success.
        if not check_only:
            callback.write_modified_objects()

    def add_default_group_user(self, check_only, callback):
        try:
            group_uuid = self.job_data['group_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses group UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        try:
            user_uuid = self.job_data['user_uuid']
        except KeyError:
            msg, log_msg = _("Job data misses user UUID.", log=True)
            logger.warning(log_msg)
            raise OTPmeException(msg)
        # Try to get group.
        group = backend.get_object(uuid=group_uuid)
        if not group:
            msg, log_msg = _("Unknown group: {group_uuid}", log=True)
            log_msg = log_msg.format(group_uuid=group_uuid)
            logger.warning(log_msg)
            msg = msg.format(group_uuid=group_uuid)
            raise OTPmeException(msg)
        verify_acls = False
        verify_acls_only = False
        if check_only:
            verify_acls = True
            verify_acls_only = check_only
        try:
            status = group.add_default_group_user(user_uuid=user_uuid,
                                                callback=callback,
                                                verify_acls=verify_acls,
                                                verify_acls_only=verify_acls_only)
        except Exception as e:
            log_msg = _("Error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            logger.warning(log_msg)
            msg = _("Error setting default group.")
            raise OTPmeException(msg)
        if status is False:
            if verify_acls_only:
                msg = _("Permission denied.")
                raise OTPmeException(msg)
            self.job_status = f"Failed: {callback.job.return_value}"
            self.update_index('job_status', self.job_status)
            self._write()
            msg = self.job_status
            raise OTPmeException(msg)
        # Write objects on success.
        if not check_only:
            callback.write_modified_objects()

    def commit(
        self,
        check_only: bool=False,
        callback: JobCallback=default_callback,
        ):
        # Check job action.
        if self.action not in self.valid_actions:
            msg, log_msg = _("Unknown job action: {action}", log=True)
            log_msg = log_msg.format(action=self.action)
            logger.warning(log_msg)
            msg = msg.format(action=self.action)
            raise OTPmeException(msg)
        # Process actions.
        if self.action == "add_default_group_user":
            try:
                self.add_default_group_user(check_only=check_only,
                                            callback=callback)
            except Exception as e:
                self.job_status = str(e)
                self.update_index('job_status', self.job_status)
                self._write()
                msg = self.job_status
                raise OTPmeException(msg)

        if self.action == "add_token_to_group":
            try:
                self.add_token_to_group(check_only=check_only,
                                        callback=callback)
            except Exception as e:
                self.job_status = str(e)
                self.update_index('job_status', self.job_status)
                self._write()
                msg = self.job_status
                raise OTPmeException(msg)

        if self.action == "add_token_to_role":
            try:
                self.add_token_to_role(check_only=check_only,
                                        callback=callback)
            except Exception as e:
                self.job_status = str(e)
                self.update_index('job_status', self.job_status)
                self._write()
                msg = self.job_status
                raise OTPmeException(msg)

        if self.action == "add_gidnumber":
            try:
                self.add_gidnumber(check_only=check_only,
                                    callback=callback)
            except Exception as e:
                self.job_status = str(e)
                self.update_index('job_status', self.job_status)
                self._write()
                msg = self.job_status
                raise OTPmeException(msg)
