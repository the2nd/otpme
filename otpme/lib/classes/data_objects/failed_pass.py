# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.classes.data_objects.used_hash import UsedHash

logger = config.logger
FAILED_DIR = os.path.join(config.data_dir, "data", "failed")

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.user",
                "otpme.lib.classes.data_objects.used_hash",
                ]

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'user_uuid', 'accessgroup_uuid', 'object_hash' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    failed_pass_oid_re = ('failed_pass|%s[/]%s[/]%s[:]%s[/][a-f0-9]*'
            % (realm_name_re, site_name_re, oid.uuid_re, oid.uuid_re))
    oid.register_oid_schema(object_type="failed_pass",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=failed_pass_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="failed_pass",
                                getter=rel_path_getter)

def register_sync_settings():
    config.register_cluster_sync(object_type="failed_pass")

def register_backend():
    """ Register object for the file backend. """
    path_id = "failed_pass"
    backend.register_data_dir(name=path_id,
                            path=FAILED_DIR,
                            drop=True,
                            perms=0o770)
    def upath_getter(user_oid, user_uuid):
        failed_dir = os.path.join(FAILED_DIR, user_uuid, path_id)
        return failed_dir
    backend.register_object_dir(object_type="user",
                                name=path_id,
                                getter=upath_getter,
                                drop=True)
    def oid_getter(path):
        if not path.startswith(FAILED_DIR):
            return
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.basename(x_dir_name)
        if x_dir_name != path_id:
            return
        object_realm = config.realm
        object_site = config.site
        object_hash = os.path.basename(path)
        x_dir_name = os.path.dirname(path)
        accessgroup_uuid = os.path.basename(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        user_uuid = os.path.basename(x_dir_name)
        user_uuid = os.path.basename(user_uuid)
        object_id = oid.OTPmeOid(object_type="failed_pass",
                                realm=object_realm,
                                site=object_site,
                                user_uuid=user_uuid,
                                accessgroup_uuid=accessgroup_uuid,
                                object_hash=object_hash)
        return object_id
    def path_getter(object_id, object_uuid):
        user_oid = backend.get_oid(object_id.user_uuid,
                                    object_type="user",
                                    instance=True)
        user_uuid = backend.get_uuid(user_oid)
        x = backend.get_object_path_settings("user")['path_getter']
        user_paths = x(user_oid, user_uuid)
        failed_pass_dir = user_paths[path_id]
        failed_pass_dir = os.path.join(failed_pass_dir, object_id.accessgroup_uuid)
        sign_hash = object_id.object_hash
        config_dir = os.path.join(failed_pass_dir, sign_hash)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild():
        failed_dir = backend.get_data_dir(path_id)
        for user_uuid in filetools.list_dir(failed_dir):
            if not stuff.is_uuid(user_uuid):
                continue
            user_failed_dir = os.path.join(failed_dir, user_uuid, path_id)
            for ag_uuid in filetools.list_dir(user_failed_dir):
                if not stuff.is_uuid(ag_uuid):
                    continue
                failed_pass_dir = os.path.join(user_failed_dir, ag_uuid)
                failed_pass_files = filetools.list_dir(failed_pass_dir)
                counter = 0
                files_count = len(failed_pass_files)
                for x in failed_pass_files:
                    counter += 1
                    x_path = os.path.join(failed_pass_dir, x)
                    x_file = os.path.join(x_path, config.object_config_file_name)
                    msg = ("Processing %s (%s/%s): %s"
                        % (path_id, counter, files_count, x_file))
                    logger.debug(msg)
                    x_oid = oid_getter(x_path)
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="failed_pass",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["user"],
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                            'site',
                                            'user_uuid',
                                            'accessgroup_uuid',
                                            'object_hash'])
    # Register object to backend.
    class_getter = lambda: FailedPass
    backend.register_object_type(object_type="failed_pass",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

class FailedPass(UsedHash):
    """ Class that implements used OTP. """
    def __init__(self, **kwargs):
        # Set our type (used in parent class).
        self.type = "failed_pass"
        # Call parent class init.
        super(FailedPass, self).__init__(**kwargs)
