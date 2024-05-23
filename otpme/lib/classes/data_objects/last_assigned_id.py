# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.classes.otpme_object import OTPmeDataObject

logger = config.logger
default_callback = config.get_callback()
path_id = "last_assigned_ids"
LAST_ASSIGNED_IDS_DIR = os.path.join(config.data_dir, "data", path_id)

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

def register():
    register_oid()
    register_backend()
    register_sync_settings()
    config.register_index_attribute("id_type")

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'policy_uuid', 'id_type', 'last_assigned_id' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    last_assigned_id_oid_re = ('last_assigned_id|%s[/]%s[/][a-zA-Z][/]%s'
                        % (realm_name_re, site_name_re, oid.int_re))
    oid.register_oid_schema(object_type="last_assigned_id",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=last_assigned_id_oid_re)
    rel_path_getter = lambda x: x[-1:]
    oid.register_rel_path_getter(object_type="last_assigned_id",
                                getter=rel_path_getter)

def register_sync_settings():
    config.register_cluster_sync(object_type="last_assigned_id")

def register_backend():
    """ Register object for the file backend. """
    backend.register_data_dir(name="last_assigned_id",
                            path=LAST_ASSIGNED_IDS_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(LAST_ASSIGNED_IDS_DIR):
            return
        # FIXME: make this work if data dir is not /var/lib/otpme -> while x_dir_name != path_id....
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.basename(x_dir_name)
        if x_dir_name != path_id:
            return
        object_realm = config.realm
        object_site = config.site
        last_assigned_id = os.path.basename(path)
        x_dir_name = os.path.dirname(path)
        policy_uuid = os.path.basename(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        id_type = os.path.basename(x_dir_name)
        object_id = oid.OTPmeOid(id_type=id_type,
                                object_type="last_assigned_id",
                                realm=object_realm,
                                site=object_site,
                                policy_uuid=policy_uuid,
                                last_assigned_id=last_assigned_id)
        return object_id
    def path_getter(object_id):
        id_type = object_id.id_type
        last_assigned_id = str(object_id.last_assigned_id)
        policy_uuid = object_id.policy_uuid
        config_dir = os.path.join(LAST_ASSIGNED_IDS_DIR,
                                    id_type, policy_uuid,
                                    last_assigned_id)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild():
        last_assigned_dirs = filetools.list_dir(LAST_ASSIGNED_IDS_DIR)
        counter = 0
        files_count = len(last_assigned_dirs)
        for id_type in last_assigned_dirs:
            id_type_dir = os.path.join(LAST_ASSIGNED_IDS_DIR, id_type)
            for policy_uuid in filetools.list_dir(id_type_dir):
                policy_uuid_dir = os.path.join(id_type_dir, policy_uuid)
                for x_id in filetools.list_dir(policy_uuid_dir):
                    counter += 1
                    x_path = os.path.join(policy_uuid_dir, x_id)
                    x_file = os.path.join(x_path, config.object_config_file_name)
                    x_oid = oid_getter(x_path)
                    msg = ("Processing %s (%s/%s): %s"
                        % (path_id, counter, files_count, x_file))
                    logger.debug(msg)
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="last_assigned_id",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["user"],
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'policy_uuid',
                                                'id_type',
                                                'last_assigned_id'])
    # Register object to backend.
    class_getter = lambda: LastAssignedID
    backend.register_object_type(object_type="last_assigned_id",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

class LastAssignedID(OTPmeDataObject):
    """ Class that implements last used object. """
    def __init__(self, id_type=None, last_assigned_id=None, policy_uuid=None, **kwargs):
        self.id_type = id_type
        self.policy_uuid = policy_uuid
        self.last_assigned_id = last_assigned_id
        self.type = "last_assigned_id"
        # Call parent class init.
        super(LastAssignedID, self).__init__(**kwargs)

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'ID_TYPE'           : {
                                                'var_name'  : 'id_type',
                                                'type'      : str,
                                                'required'  : True,
                                            },
                        'POLICY_UUID' : {
                                                'var_name'  : 'policy_uuid',
                                                'type'      : 'uuid',
                                                'required'  : True,
                                            },
                        'LAST_ASSIGNED_ID' : {
                                                'var_name'  : 'last_assigned_id',
                                                'type'      : int,
                                                'required'  : True,
                                            },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.OTPmeOid(object_type=self.type,
                                realm=self.realm,
                                site=self.site,
                                id_type=self.id_type,
                                policy_uuid=self.policy_uuid,
                                last_assigned_id=self.last_assigned_id)

    def add(self, callback=default_callback):
        """ Add the object. """
        # Add policy UUID to index.
        self.add_index('id_type', self.id_type)
        self.add_index('policy_uuid', self.policy_uuid)
        # Call base class add method.
        return super(LastAssignedID, self).add(callback=callback)
