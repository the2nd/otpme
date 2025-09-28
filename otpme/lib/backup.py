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

from otpme.lib.exceptions import *

default_callback = config.get_callback()

def backup_object(object_id, decrypt=False):
    x_oc = backend.read_config(object_id, decrypt=decrypt)
    if decrypt:
        x_oc = x_oc.copy()
    if not x_oc:
        msg = _("Unknown object: {object_id}")
        msg = msg.format(object_id=object_id)
        raise OTPmeException(msg)
    object_uuid = x_oc['UUID']
    last_used = backend.get_last_used(object_uuid)
    file_content = {
                    'object_id'     : object_id.full_oid,
                    'object_uuid'   : object_uuid,
                    'object_config' : x_oc,
                    'last_used'     : last_used,
                }
    if object_id.object_type == "user":
        result = backend.search(object_type="group",
                                attribute="user",
                                value=object_uuid,
                                realm=config.realm,
                                site=config.site)
        if result:
            file_content['user_group'] = result[0]
    if object_id.object_type == "token":
        # Get token roles.
        token_roles = backend.search(object_type="role",
                                    attribute="token",
                                    value=object_uuid,
                                    realm=config.realm,
                                    site=config.site)
        x_token_roles_opts = []
        for x in token_roles:
            x_token_role = backend.get_object(uuid=x)
            try:
                x_token_opts = x_token_role.token_options[object_uuid]
            except KeyError:
                x_token_opts = None
            try:
                x_token_login_interfaces = x_token_role.token_login_interfaces[object_uuid]
            except KeyError:
                x_token_login_interfaces = []
            x_token_roles_opts.append((x, x_token_opts, x_token_login_interfaces))
        file_content['token_roles'] = x_token_roles_opts
        # Get token groups.
        token_groups = backend.search(object_type="group",
                                    attribute="token",
                                    value=object_uuid,
                                    realm=config.realm,
                                    site=config.site)
        x_token_groups_opts = []
        for x in token_groups:
            x_token_group = backend.get_object(uuid=x)
            try:
                x_token_opts = x_token_group.token_options[object_uuid]
            except KeyError:
                x_token_opts = None
            try:
                x_token_login_interfaces = x_token_group.token_login_interfaces[object_uuid]
            except KeyError:
                x_token_login_interfaces = []
            x_token_groups_opts.append((x, x_token_opts, x_token_login_interfaces))
        file_content['token_groups'] = x_token_groups_opts
    if object_id.object_type == "role":
        # Get role roles.
        role_roles = backend.search(object_type="role",
                                    attribute="role",
                                    value=object_uuid,
                                    realm=config.realm,
                                    site=config.site)
        file_content['role_roles'] = role_roles
        # Get role groups.
        role_groups = backend.search(object_type="group",
                                    attribute="role",
                                    value=object_uuid,
                                    realm=config.realm,
                                    site=config.site)
        file_content['role_groups'] = role_groups
    file_content = json.dumps(file_content)
    return file_content

def restore_object(object_data, callback=default_callback, **kwargs):
    """ Restore object. """
    object_id = object_data['object_id']
    object_id = oid.get(object_id)
    msg = _("Restoring: {object_id}")
    msg = msg.format(object_id=object_id)
    callback.send(msg)
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
    if object_id.object_type == "user":
        user_group_uuid = object_data['user_group']
        user_group = backend.get_object(uuid=user_group_uuid)
        if not user_group:
            msg = _("Unknown group: {user_group_uuid}")
            msg = msg.format(user_group_uuid=user_group_uuid)
            return callback.error(msg)
        user_group.add_default_group_user(user_uuid=object_uuid,
                                            callback=callback,
                                            verify_acls=False)
    if object_id.object_type == "token":
        token_groups = object_data['token_groups']
        for x in token_groups:
            x_group_uuid = x[0]
            x_token_opts = x[1]
            x_token_login_interfaces = x[2]
            x_group = backend.get_object(uuid=x_group_uuid)
            if not x_group:
                msg = _("Unknown group: {x_group_uuid}")
                msg = msg.format(x_group_uuid=x_group_uuid)
                return callback.error(msg)
            x_group.add_token(token_path=object_id.rel_path,
                            token_options=x_token_opts,
                            login_interfaces=x_token_login_interfaces,
                            callback=callback,
                            verify_acls=False)
        x_token_roles = object_data['token_roles']
        for x in x_token_roles:
            x_role_uuid = x[0]
            x_token_opts = x[1]
            x_token_login_interfaces = x[2]
            x_role = backend.get_object(uuid=x_role_uuid)
            if not x_role:
                msg = _("Unknown role: {x_role_uuid}")
                msg = msg.format(x_role_uuid=x_role_uuid)
                return callback.error(msg)
            x_role.add_token(token_path=object_id.rel_path,
                            token_options=x_token_opts,
                            login_interfaces=x_token_login_interfaces,
                            callback=callback,
                            verify_acls=False)
    if object_id.object_type == "role":
        role_roles = object_data['role_groups']
        for x_group_uuid in role_roles:
            x_group = backend.get_object(uuid=x_group_uuid)
            if not x_group:
                msg = _("Unknown group: {x_group_uuid}")
                msg = msg.format(x_group_uuid=x_group_uuid)
                return callback.error(msg)
            x_group.add_role(role_uuid=object_uuid,
                            callback=callback,
                            verify_acls=False)
        role_roles = object_data['role_roles']
        for x_role_uuid in role_roles:
            x_role = backend.get_object(uuid=x_role_uuid)
            if not x_role:
                msg = _("Unknown role: {x_role_uuid}")
                msg = msg.format(x_role_uuid=x_role_uuid)
                return callback.error(msg)
            x_role.add_role(role_uuid=object_uuid,
                            callback=callback,
                            verify_acls=False)
    # Set last used time.
    last_used = object_data['last_used']
    if last_used is not None:
        backend.set_last_used(object_id.object_type, object_uuid, last_used)
    return callback.ok()
