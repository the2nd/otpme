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
from otpme.lib.classes.otpme_object import OTPmeDataObject

path_id = "skip_sync"
logger = config.logger
SKIP_DIR = os.path.join(config.data_dir, "data", path_id)

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'skip_hash' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    skip_sync_oid_re = ('skip_sync|%s[/]%s[/][a-f0-9]*'
                    % (realm_name_re, site_name_re))
    oid.register_oid_schema(object_type="skip_sync",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=skip_sync_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="skip_sync",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node",
                                object_type="skip_sync",
                                sync_once_only=False,
                                sync_deletions=False,
                                cluster=True)
    config.register_object_sync(host_type="host",
                                object_type="skip_sync",
                                sync_once_only=False,
                                sync_deletions=False)

def register_backend():
    """ Register object for the file backend. """
    backend.register_data_dir(name="skip_sync",
                            path=SKIP_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(SKIP_DIR):
            return
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.basename(x_dir_name)
        if x_dir_name != path_id:
            return
        skip_hash = os.path.basename(path)
        x_dir_name = os.path.dirname(path)
        object_site = os.path.basename(x_dir_name)
        x_dir_name = os.path.dirname(x_dir_name)
        object_realm = os.path.basename(x_dir_name)
        object_id = oid.OTPmeOid(object_type="skip_sync",
                                realm=object_realm,
                                site=object_site,
                                skip_hash=skip_hash)
        return object_id
    def path_getter(object_id):
        config_dir = os.path.join(SKIP_DIR,
                                object_id.realm,
                                object_id.site,
                                object_id.skip_hash)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild():
        for realm in filetools.list_dir(SKIP_DIR):
            realm_dir = os.path.join(SKIP_DIR, realm)
            for site in filetools.list_dir(realm_dir):
                site_dir = os.path.join(realm_dir, site)
                skip_sync_dirs = filetools.list_dir(site_dir)
                counter = 0
                files_count = len(skip_sync_dirs)
                for object_uuid in skip_sync_dirs:
                    counter += 1
                    if not stuff.is_uuid(object_uuid):
                        continue
                    x_path = os.path.join(site_dir, object_uuid)
                    x_file = os.path.join(x_path, config.object_config_file_name)
                    x_oid = oid_getter(x_path)
                    msg = ("Processing %s (%s/%s): %s"
                        % (path_id, counter, files_count, x_file))
                    logger.debug(msg)
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="skip_sync",
                            tree_object=False,
                            uniq_name=False,
                            object_cache=1024,
                            cache_region="data_object")
    # Register object to backend.
    class_getter = lambda: SkipSync
    backend.register_object_type(object_type="skip_sync",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

class SkipSync(OTPmeDataObject):
    """ Class that implements last used object. """
    def __init__(self, skip_object=None, object_id=None, **kwargs):
        # Set our type (used in parent class).
        self.type = "skip_sync"
        # The OID of the object to skip.
        self.skip_object = skip_object
        if skip_object:
            self.skip_hash = stuff.gen_md5(skip_object)

        # Call parent class init.
        super(SkipSync, self).__init__(object_id=object_id, **kwargs)

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'SKIP_OBJECT'               : {
                                                        'var_name'  : 'skip_object',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'SKIP_HASH'                 : {
                                                        'var_name'  : 'skip_hash',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        }

        return object_config


    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.OTPmeOid(object_type=self.type,
                                realm=self.realm,
                                site=self.site,
                                skip_hash=self.skip_hash)
