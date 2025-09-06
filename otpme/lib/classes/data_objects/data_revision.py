# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeDataObject

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]
DATA_REVISION_DIR = os.path.join(config.data_dir, "data", "data_revision")

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    data_revision_oid_re = ('data_revision|%s[/]%s'
                        % (realm_name_re, site_name_re))
    oid.register_oid_schema(object_type="data_revision",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=data_revision_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="data_revision",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    #config.register_cluster_sync(object_type="data_revision")
    config.register_object_sync(host_type="node", object_type="data_revision")

def register_backend():
    """ Register object for the file backend. """
    path_id = "data_revision"
    backend.register_data_dir(name=path_id,
                            path=DATA_REVISION_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(DATA_REVISION_DIR):
            return
        x_dir_name = os.path.basename(path)
        if x_dir_name != path_id:
            return
        object_realm = config.realm
        object_site = config.site
        data_revision = os.path.dirname(path)
        data_revision = os.path.basename(data_revision)
        object_id = oid.OTPmeOid(object_type="data_revision",
                                realm=object_realm,
                                site=object_site)
        return object_id
    def path_getter(object_id, object_uuid):
        data_revision_dir = backend.get_data_dir(path_id)
        config_dir = os.path.join(data_revision_dir)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def site_getter(object_id):
        """ Get object site from OID. """
        object_site = None
        oid_parts = object_id.split("|")[1].split("/")
        if len(oid_parts) > 1:
            object_site = oid_parts[1]
        return object_site
    oid.register_site_getter(object_type="data_revision",
                        getter=site_getter)
    def index_rebuild():
        data_revision_dir = backend.get_data_dir(path_id)
        data_revision_file = os.path.join(data_revision_dir, config.object_config_file_name)
        if not os.path.exists(data_revision_file):
            return
        msg = ("Processing %s %s" % (path_id, data_revision_file))
        logger.debug(msg)
        x_oid = oid_getter(data_revision_dir)
        backend.index_add(object_id=x_oid,
                        object_config="auto",
                        full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="data_revision",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["site"],
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm', 'site'])
    # Register index attributes.
    config.register_index_attribute('data_revision')
    # Register object to backend.
    class_getter = lambda: DataRevision
    backend.register_object_type(object_type="data_revision",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

@match_class_typing
class DataRevision(OTPmeDataObject):
    """ Class that implements data revision object. """
    def __init__(
        self,
        data_revision: Union[float,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "data_revision"

        # Call parent class init.
        super(DataRevision, self).__init__(object_id=object_id, **kwargs)

        self._data_revision = None
        self.data_revision = data_revision

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "DATA_REVISION",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "DATA_REVISION",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'DATA_REVISION'             : {
                                                        'var_name'  : 'data_revision',
                                                        'type'      : float,
                                                        'force_type': True,
                                                        'required'  : True,
                                                    },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site)

    @property
    def data_revision(self):
        return self._data_revision

    @data_revision.setter
    def data_revision(self, data_revision: float):
        old_data_revision = self._data_revision
        self._data_revision = data_revision
        if data_revision is None:
            return
        self.add_index("data_revision", data_revision)
        if old_data_revision:
            self.del_index("data_revision", old_data_revision)

    def add(self):
        """ Add the object. """
        # Call base class add method.
        return super(DataRevision, self).add()
