# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.protocols.utils import register_commands
from otpme.lib.exceptions import *

default_callback = config.get_callback()

commands = {
    'restore_object'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'args'              : [
                                        'object_data',
                                        ],
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
    last_used = backend.get_last_used(object_uuid)
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

def restore_object(object_data, callback=default_callback, **kwargs):
    """ Restore object. """
    object_id = object_data['object_id']
    object_id = oid.get(object_id)
    msg = _("Restoring: {object_id}")
    msg = msg.format(object_id=object_id)
    callback.send(msg)

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
    object_config = object_data['object_config']
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
                    encrypt=False,
                    cluster=True)
    except Exception as e:
        msg = _("Failed to restore object: {object_id}: {e}")
        msg = msg.format(object_id=object_id, e=e)
        return callback.error(msg)
    oc.restore_object_data(object_id, object_uuid, object_data, callback)
    # Set last used time.
    last_used = object_data['last_used']
    if last_used is not None:
        backend.set_last_used(object_id.object_type, object_uuid, last_used)
    return callback.ok()
