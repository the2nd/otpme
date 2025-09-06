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

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.data_objects.used_hash",
                ]

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'token_uuid', 'object_hash' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    used_otp_oid_re = ('used_otp|%s[/]%s[/]%s[/][a-f0-9]*'
                % (realm_name_re, site_name_re, oid.uuid_re))
    oid.register_oid_schema(object_type="used_otp",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=used_otp_oid_re)
    rel_path_getter = lambda x: x[-3:]
    oid.register_rel_path_getter(object_type="used_otp",
                                getter=rel_path_getter)

def register_sync_settings():
    config.register_cluster_sync(object_type="used_otp")

def register_backend():
    """ Register object for the file backend. """
    path_id = "used_otp"
    used_dir = backend.get_data_dir("used")
    def oid_getter(path):
        path_id = "used_otp"
        if not path.startswith(used_dir):
            return
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.basename(x_dir_name)
        if x_dir_name != path_id:
            return
        object_realm = config.realm
        object_site = config.site
        token_uuid = os.path.dirname(path)
        token_uuid = os.path.basename(token_uuid)
        object_hash = os.path.basename(path)
        object_id = oid.OTPmeOid(object_type="used_otp",
                                realm=object_realm,
                                site=object_site,
                                token_uuid=token_uuid,
                                object_hash=object_hash)
        return object_id
    def path_getter(object_id, object_uuid):
        token_uuid = object_id.token_uuid
        otp_hash = object_id.object_hash
        token_oid = backend.get_oid(token_uuid,
                                object_type="token",
                                instance=True)
        user_oid = oid.get(object_type="user",
                            realm=token_oid.realm,
                            site=token_oid.site,
                            name=token_oid.user)

        user_uuid = backend.get_uuid(user_oid)
        config_dir = os.path.join(used_dir,
                                user_uuid,
                                path_id,
                                token_uuid,
                                otp_hash)
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
            user_used_dir = os.path.join(used_dir, user_uuid, path_id)
            for token_uuid in filetools.list_dir(user_used_dir):
                if not stuff.is_uuid(token_uuid):
                    continue
                used_otp_dir = os.path.join(user_used_dir, token_uuid)
                used_otp_files = filetools.list_dir(used_otp_dir)
                counter = 0
                files_count = len(used_otp_files)
                for x in used_otp_files:
                    counter += 1
                    x_path = os.path.join(used_otp_dir, x)
                    x_file = os.path.join(x_path, config.object_config_file_name)
                    msg = ("Processing %s (%s/%s): %s"
                        % (path_id, counter, files_count, x_file))
                    logger.debug(msg)
                    x_oid = oid_getter(x_path)
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="used_otp",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["token"],
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                             'site',
                                             'token_uuid',
                                             'object_hash' ])
    # Register object to backend.
    class_getter = lambda: UsedOTP
    backend.register_object_type(object_type="used_otp",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

class UsedOTP(UsedHash):
    """ Class that implements used OTP. """
    def __init__(self, **kwargs):
        # Set our type (used in parent class).
        self.type = "used_otp"
        # Call parent class init.
        super(UsedOTP, self).__init__(**kwargs)
