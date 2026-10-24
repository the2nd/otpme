# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

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
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.protocols.utils import register_commands
from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

commands = {
    'restore_object'   : {
            'default'    : {
                'exists'    : {
                    'args'              : ['object_data'],
                    'oargs'             : ['force'],
                    'job_type'          : 'process',
                    },
                },
            },
    }

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    register_commands("backup", commands)

def backup_object(object_id, decrypt=False):
    x_oc = backend.read_config(object_id, decrypt=decrypt)
    if not x_oc:
        msg = _("Unknown object: {object_id}")
        msg = msg.format(object_id=object_id)
        raise OTPmeException(msg)
    if decrypt:
        x_oc = x_oc.copy()
    object_uuid = x_oc['UUID']
    last_used = backend.get_last_used(object_uuid,
                                    object_type=object_id.object_type)
    file_content = {
                    'object_id'     : object_id.full_oid,
                    'object_uuid'   : object_uuid,
                    'object_config' : x_oc,
                    'last_used'     : last_used,
                }
    # Class getter for backup object.
    class_getter, \
    getter_args = backend.get_class_getter(object_id.object_type)
    # Get class.
    _getter_args = {}
    if getter_args:
        for x in getter_args:
            try:
                val = x_oc[x]
            except KeyError:
                continue
            para = getter_args[x]
            _getter_args[para] = val
    oc = class_getter(**_getter_args)
    file_content = oc.get_backup_data(object_id, object_uuid, x_oc, file_content)
    file_content = json.dumps(file_content)
    return file_content

def upgrade_restored_object(object_uuid, callback=default_callback):
    """ Store a restored object in the versions its site writes.

    Returns True when it is stored in them, or the result of
    callback.error().
    """
    x_object = backend.get_object(uuid=object_uuid, add_to_cache=False)
    if not x_object:
        msg = _("Failed to load restored object: {object_uuid}")
        msg = msg.format(object_uuid=object_uuid)
        return callback.error(msg)
    if not x_object.config_upgraded:
        return True
    x_object.acquire_lock(lock_caller="restore")
    try:
        result = x_object._write(update_last_modified=False,
                                update_last_modified_by=False,
                                callback=callback)
    except Exception as e:
        result = False
        log_msg = _("Failed to upgrade object config: {oid}: {error}", log=True)[1]
        log_msg = log_msg.format(oid=x_object.oid, error=e)
        logger.warning(log_msg)
    finally:
        x_object.release_lock(lock_caller="restore")
    if result is False:
        msg = _("Failed to store restored object in the current version: {oid}")
        msg = msg.format(oid=x_object.oid)
        return callback.error(msg)
    msg = _("Stored in the current version: {oid}")
    msg = msg.format(oid=x_object.oid)
    callback.send(msg)
    return True

def restore_object(object_data, force=False, callback=default_callback, **kwargs):
    """ Restore object. """
    object_id = object_data['object_id']
    object_id = oid.get(object_id)
    msg = _("Restoring: {object_id}")
    msg = msg.format(object_id=object_id)
    callback.send(msg)

    object_config = object_data['object_config']

    # Class getter for backup object.
    class_getter, \
    getter_args = backend.get_class_getter(object_id.object_type)
    # Get class.
    _getter_args = {}
    if getter_args:
        for x in getter_args:
            try:
                val = object_config[x]
            except KeyError:
                continue
            para = getter_args[x]
            _getter_args[para] = val
    oc = class_getter(**_getter_args)
    object_uuid = object_data['object_uuid']

    x_object = backend.get_object(uuid=object_uuid)
    if x_object:
        if x_object.oid != object_id:
            msg = _("Object with UUID exists: {x_object}")
            msg = msg.format(x_object=x_object)
            return callback.error(msg)
    if object_id.object_type == "user":
        user_object = backend.get_object(object_type="user",
                                        realm=config.realm,
                                        name=object_id.name)
        if user_object and user_object.site != config.site:
            msg = _("User with this name exists: {user_object}")
            msg = msg.format(user_object=user_object)
            return callback.error(msg)
    x_object = backend.get_object(object_id)
    if not force:
        if x_object:
            msg = _("Object exists. Overwrite?:")
            answer = callback.ask(msg)
            if answer.lower() != "y":
                return False
    try:
        backend.write_config(object_id=object_id,
                    object_config=object_config,
                    full_index_update=True,
                    full_data_update=True,
                    full_ldif_update=True,
                    full_acl_update=True,
                    encrypt=False,
                    cluster=True)
    except Exception as e:
        msg = _("Failed to restore object: {object_id}: {e}")
        msg = msg.format(object_id=object_id, e=e)
        return callback.error(msg)
    # Clear caches.
    cache.clear()
    # What comes back is stored as it was deleted or backed up, maybe
    # in a version this site has left. Loading brings it up, and it is
    # stored the way "otpme-site upgrade" does (Site.write_object_to_
    # upgrade()): only where the site is at the newer version.
    upgrade_result = upgrade_restored_object(object_uuid, callback=callback)
    if upgrade_result is not True:
        return upgrade_result
    # Run class restore method.
    oc.restore_object_data(object_id, object_uuid, object_data, callback)
    # Set last used time.
    last_used = object_data['last_used']
    if last_used is not None:
        backend.set_last_used(object_id, object_uuid, last_used)
    return callback.ok()
