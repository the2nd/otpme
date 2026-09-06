# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Result of a tiqr login attempt, waiting to be collected.

A tiqr login runs over two connections: the phone posts its response to
whichever node the load balancer picks, and the browser polls from
somewhere else entirely. Something cluster wide has to bridge the two,
and a shared dict cannot (host local), nor can the redis cache (unix
socket, also host local).

This object is that bridge, and it is written only once the phone has
answered correctly. Nothing exists before that: the challenge and the
poll id are derived from the session key rather than stored (see
protocols/tiqr_helpers.py), so an unauthenticated caller cannot make us
write anything at all -- which matters, because OTPme has no reaper and
a record with no token behind it would be nobody's to clean up.

Found by the hash of the poll id, never by the poll id itself, the same
way OIDC stores authcode_hash rather than the code. The poll id is what
the browser holds in its session; the session key beside it is public,
it is printed as a QR code.

Cleaned up in two places: TiqrToken.delete_used_data_objects() when the
token or its user goes, and lazily on the next answered login for the
same token, which is how used_otp handles the same problem.
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
from otpme.lib.classes.data_objects.used_hash import UsedHash
# Plain SHA-256 hex digest despite the module name, and OIDC uses it for
# exactly this purpose: storing the hash of a handle instead of the
# handle itself.
from otpme.lib.protocols.oidc_helpers import hash_token

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
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    tiqr_auth_result_oid_re = (f'tiqr_auth_result[|]{realm_name_re}[/]{site_name_re}'
                            f'[/]{oid.uuid_re}[/][a-f0-9]+')
    oid.register_oid_schema(object_type="tiqr_auth_result",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=tiqr_auth_result_oid_re)
    rel_path_getter = lambda x: x[-3:]
    oid.register_rel_path_getter(object_type="tiqr_auth_result",
                                getter=rel_path_getter)

def register_sync_settings():
    config.register_cluster_sync(object_type="tiqr_auth_result")

def register_backend():
    """ Register object for the file backend. """
    # The browser polls knowing nothing but its poll id -- no token, no
    # user -- so the hash of it has to be searchable. UsedHash.add()
    # indexes the uuids and the expiry but not object_hash, which is
    # fine for used_otp (it searches by token and compares in Python)
    # and useless here.
    config.register_index_attribute('object_hash')
    path_id = "tiqr_auth_result"
    # Shared with used_otp, used_sotp and token_counter: transient
    # per-token authentication artifacts all live here.
    used_dir = backend.get_data_dir("used")
    def oid_getter(path):
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
        object_id = oid.OTPmeOid(object_type="tiqr_auth_result",
                                realm=object_realm,
                                site=object_site,
                                token_uuid=token_uuid,
                                object_hash=object_hash)
        return object_id
    def path_getter(object_id, object_uuid):
        token_uuid = object_id.token_uuid
        poll_hash = object_id.object_hash
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
                                poll_hash)
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
        for user_uuid in filetools.list_dir(used_dir):
            if not stuff.is_uuid(user_uuid):
                continue
            user_used_dir = os.path.join(used_dir, user_uuid, path_id)
            for token_uuid in filetools.list_dir(user_used_dir):
                if not stuff.is_uuid(token_uuid):
                    continue
                result_dir = os.path.join(user_used_dir, token_uuid)
                result_files = filetools.list_dir(result_dir)
                counter = 0
                files_count = len(result_files)
                for x in result_files:
                    counter += 1
                    x_path = os.path.join(result_dir, x)
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
                    backend.index_add(object_id=x_oid,
                                    object_config="auto",
                                    full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="tiqr_auth_result",
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
    class_getter = lambda: TiqrAuthResult
    backend.register_object_type(object_type="tiqr_auth_result",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

def hash_poll_id(poll_id):
    """ What we store and search by, instead of the poll id itself. """
    return hash_token(poll_id)

def get_by_poll_id(poll_id):
    """ Find the answered login a browser is waiting for.

    Returns the instance or None. The poll id is never written down, so
    the lookup goes through its hash. """
    result = backend.search(object_type="tiqr_auth_result",
                            attribute="object_hash",
                            value=hash_poll_id(poll_id),
                            return_type="instance")
    if not result:
        return None
    return result[0]


class TiqrAuthResult(UsedHash):
    """ An answered tiqr login attempt, waiting for its browser. """
    def __init__(
        self,
        session_key: Union[str,None]=None,
        response: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class).
        self.type = "tiqr_auth_result"
        # Both are needed to rebuild the smartcard_data the AuthHandler
        # verifies at poll time. They outlive the phone's request by at
        # most one challenge window and go once collected.
        self.session_key = session_key
        self.response = response
        # Call parent class init.
        super().__init__(**kwargs)

    def _get_object_config(self):
        """ Add our fields to the ones from the parent class. """
        object_config = super()._get_object_config()
        object_config['SESSION_KEY'] = {
                                        'var_name'  : 'session_key',
                                        'type'      : str,
                                        'required'  : True,
                                        'encryption': config.disk_encryption,
                                    }
        object_config['RESPONSE'] = {
                                        'var_name'  : 'response',
                                        'type'      : str,
                                        'required'  : True,
                                        'encryption': config.disk_encryption,
                                    }
        return object_config

    def add(self):
        """ Add the object, plus the index the browser looks us up by. """
        if self.object_hash:
            self.add_index('object_hash', self.object_hash)
        return super().add()
