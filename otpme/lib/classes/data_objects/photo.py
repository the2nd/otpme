# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The photo of a user, as an object of its own.

It used to live in the user object, twice (PHOTO and the jpegPhoto LDIF
attribute), and with it in the index: every load of a user and every
LDAP search over users read it, whether anybody wanted the photo or not.
Here it is read only when it is asked for.

One photo per user, stored under the user's UUID, so the file can be
found without the index: read_photo() opens it directly. That is the
fast path for LDAP, which may hand out the photos of all users in one
search. It takes no file lock -- the backend rewrites a file in place,
so a read can catch one half written, and a half written JSON file never
parses: then it reads again the regular way, under the lock.
"""
import os
from typing import Union

# The same JSON module the file backend writes with.
try:
    import simdjson as json
except Exception:
    try:
        import ujson as json
    except Exception:
        import json

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
REGISTER_AFTER = [
                "otpme.lib.classes.site",
                "otpme.lib.classes.user",
                "otpme.lib.classes.data_objects.used_hash",
                ]
PHOTO_DIR = os.path.join(config.data_dir, "data", "photo")

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'user_uuid' ]
    read_oid_schema = None
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    photo_oid_re = (f'photo[|]{realm_name_re}[/]{site_name_re}'
                    f'[/]{oid.uuid_re}')
    oid.register_oid_schema(object_type="photo",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=photo_oid_re)
    rel_path_getter = lambda x: x[-1:]
    oid.register_rel_path_getter(object_type="photo",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. Between the nodes of the site, and to the
    nodes of other sites, which serve the photo of a user of ours on their
    portal and LDAP. Not to hosts: nothing there needs it. """
    config.register_cluster_sync(object_type="photo")
    config.register_object_sync(host_type="node", object_type="photo")

def get_photo_dir(user_uuid):
    """ The directory of the photo of <user_uuid>. The UUID alone says
    where it is, which is what lets read_photo() skip the index. """
    return os.path.join(PHOTO_DIR, user_uuid)

def register_backend():
    """ Register object for the file backend. """
    path_id = "photo"
    backend.register_data_dir(name=path_id,
                            path=PHOTO_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(PHOTO_DIR):
            return
        path = path.rstrip("/")
        if os.path.basename(path) == config.object_config_file_name:
            path = os.path.dirname(path)
        user_uuid = os.path.basename(path)
        if not stuff.is_uuid(user_uuid):
            return
        # Realm and site are not in the path -- see get_photo_dir() --
        # so they come from the object itself.
        config_file = os.path.join(path, config.object_config_file_name)
        try:
            object_config = filetools.read_data_file(config_file)
        except Exception:
            return
        realm_oid = backend.get_oid(object_config.get('REALM'),
                                    object_type="realm",
                                    instance=True)
        site_oid = backend.get_oid(object_config.get('SITE'),
                                    object_type="site",
                                    instance=True)
        if not realm_oid or not site_oid:
            return
        object_id = oid.OTPmeOid(object_type="photo",
                                realm=realm_oid.name,
                                site=site_oid.name,
                                user_uuid=user_uuid)
        return object_id
    def path_getter(object_id, object_uuid):
        config_dir = get_photo_dir(object_id.user_uuid)
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
        photo_dir = backend.get_data_dir(path_id)
        user_uuids = [x for x in filetools.list_dir(photo_dir)
                    if stuff.is_uuid(x)]
        counter = 0
        files_count = len(user_uuids)
        for user_uuid in user_uuids:
            counter += 1
            x_path = get_photo_dir(user_uuid)
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
    # Register object to config. A small object cache: the objects are
    # large, and the fast path does not use it.
    config.register_object_type(object_type="photo",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["user"],
                            object_cache=128,
                            cache_region="data_object",
                            backup_attributes=['realm',
                                                'site',
                                                'user_uuid'])
    # Register object to backend.
    class_getter = lambda: Photo
    backend.register_object_type(object_type="photo",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

def get_photo_oid(user):
    """ The OID of the photo of <user>. """
    return oid.get(object_type="photo",
                    realm=user.realm,
                    site=user.site,
                    user_uuid=user.uuid)

def get_photo_object(user):
    """ The photo object of <user>, or None. """
    return backend.get_object(get_photo_oid(user))

def read_photo(user_uuid):
    """ The photo of <user_uuid> as base64 JPEG, or None -- without the
    index and without a file lock, see the module docstring. """
    if not stuff.is_uuid(user_uuid):
        return None
    config_file = os.path.join(get_photo_dir(user_uuid),
                                config.object_config_file_name)
    try:
        with open(config_file) as fh:
            object_config = json.loads(fh.read())
    except FileNotFoundError:
        return None
    except Exception:
        # Caught mid write, or stored compressed: read it the regular
        # way, under the file lock.
        try:
            object_config = filetools.read_data_file(config_file)
        except Exception as e:
            log_msg = _("Failed to read photo: {config_file}: {error}", log=True)[1]
            log_msg = log_msg.format(config_file=config_file, error=e)
            logger.warning(log_msg)
            return None
    photo = object_config.get('PHOTO')
    if not photo:
        return None
    return photo

@match_class_typing
class Photo(OTPmeDataObject):
    """ The photo of a user. """
    def __init__(
        self,
        user_uuid: Union[str,None]=None,
        photo: Union[str,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "photo"
        self.user_uuid = user_uuid
        self.photo = photo
        # Call parent class init.
        super().__init__(object_id=object_id, **kwargs)
        # A site we do not trust gets the object, not the photo.
        self._sync_fields = {
                    'node'  : {
                        'untrusted'  : [
                            "USER_UUID",
                            "CHECKSUM",
                            "SYNC_CHECKSUM",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'USER_UUID'                 : {
                                                        'var_name'  : 'user_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        # Base64 JPEG. Not encrypted: read_photo() reads
                        # the value straight from the file.
                        'PHOTO'                     : {
                                                        'var_name'  : 'photo',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        }
        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            user_uuid=self.user_uuid)

    def add(self, **kwargs):
        """ Add the object. """
        if self.user_uuid:
            self.add_index('user_uuid', self.user_uuid)
        return super().add(**kwargs)
