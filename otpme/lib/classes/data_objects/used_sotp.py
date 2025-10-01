# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

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
from otpme.lib.classes.data_objects.used_hash import UsedHash

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.data_objects.used_hash",
                ]

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'user_uuid', 'object_hash' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    used_sotp_oid_re = (f'used_sotp|{realm_name_re}[/]{site_name_re}[/]{oid.uuid_re}[/][a-f0-9]*')
    oid.register_oid_schema(object_type="used_sotp",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=used_sotp_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="used_sotp",
                                getter=rel_path_getter)

def register_sync_settings():
    config.register_cluster_sync(object_type="used_sotp")

def register_backend():
    """ Register object for the file backend. """
    path_id = "used_sotp"
    used_dir = backend.get_data_dir("used")
    def upath_getter(object_id, object_uuid):
        try:
            user_used_dir = backend.get_object_dir(object_id,
                                                object_uuid,
                                                "used_dir")
            user_used_dir = user_used_dir['used_dir']['path']
            used_sotp_dir = os.path.join(user_used_dir, path_id)
        except:
            return
        return used_sotp_dir
    backend.register_object_dir(object_type="user",
                                name=path_id,
                                getter=upath_getter,
                                drop=True)
    def oid_getter(path):
        if not path.startswith(used_dir):
            return
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.basename(x_dir_name)
        if x_dir_name != path_id:
            return
        object_realm = config.realm
        object_site = config.site
        object_hash = os.path.basename(path)
        user_uuid = os.path.dirname(path)
        user_uuid = os.path.dirname(user_uuid)
        user_uuid = os.path.basename(user_uuid)
        object_id = oid.OTPmeOid(object_type="used_sotp",
                                realm=object_realm,
                                site=object_site,
                                user_uuid=user_uuid,
                                object_hash=object_hash)
        return object_id
    def path_getter(object_id, object_uuid):
        user_oid = backend.get_oid(object_id.user_uuid,
                                    object_type="user",
                                    instance=True)
        user_uuid = backend.get_uuid(user_oid)
        x = backend.get_object_path_settings("user")['path_getter']
        user_paths = x(user_oid, user_uuid)
        used_sotp_dir = user_paths[path_id]
        sotp_hash = object_id.object_hash
        config_dir = os.path.join(used_sotp_dir, sotp_hash)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild():
        for user_uuid in filetools.list_dir(used_dir):
            if not stuff.is_uuid(user_uuid):
                continue
            user_used_dir = os.path.join(used_dir, user_uuid)
            used_sotp_dir = os.path.join(user_used_dir, path_id)
            used_sotp_files = filetools.list_dir(used_sotp_dir)
            counter = 0
            files_count = len(used_sotp_files)
            for x in used_sotp_files:
                counter += 1
                x_path = os.path.join(used_sotp_dir, x)
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
    config.register_object_type(object_type="used_sotp",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["user"],
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'user_uuid',
                                                'object_hash'])
    # Register object to backend.
    class_getter = lambda: UsedSOTP
    backend.register_object_type(object_type="used_sotp",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

class UsedSOTP(UsedHash):
    """ Class that implements used SOTP. """
    def __init__(self, **kwargs):
        # Set our type (used in parent class).
        self.type = "used_sotp"
        # Call parent class init.
        super(UsedSOTP, self).__init__(**kwargs)
