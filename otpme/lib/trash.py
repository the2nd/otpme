# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import datetime

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

from prettytable import NONE
from prettytable import FRAME
from prettytable import PrettyTable

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import backup
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import multiprocessing
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.daemon.clusterd import cluster_sync_object

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

TRASH_DIR = "%s/trash" % config.data_dir
DELETED_BY_FILENAME = ".deleted_by"

REGISTER_BEFORE = []
REGISTER_AFTER = []

trash_ids = {}

commands = {
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'oargs'              : [
                                        'max_len',
                                        'output_fields',
                                        'sort_by',
                                        'reverse',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        ],
                    'job_type'          : 'thread',
                    },
                },
            },
    'restore'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'args'              : [
                                        'trash_id',
                                        ],
                    'oargs'             : [
                                        'objects',
                                        ],
                    'job_type'          : 'process',
                    },
                },
            },
    'del'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'args'              : [
                                        'trash_id',
                                        ],
                    'job_type'          : 'thread',
                    },
                },
            },
    'empty'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def register():
    register_backend()
    register_commands("trash", commands)

def register_backend():
    """ Register object for the file backend. """
    backend.register_data_dir(name="trash",
                            path=TRASH_DIR,
                            drop=True,
                            perms=0o770)

def get_trash_id():
    global trash_ids
    thread_id = multiprocessing.get_id()
    try:
        trash_id = trash_ids[thread_id]
    except KeyError:
        trash_id = str(time.time()) + "-" + stuff.gen_uuid()
        trash_ids[thread_id] = trash_id
    return trash_id

def get_trash_dir(trash_id=None):
    if trash_id is None:
        trash_id = get_trash_id()
    trash_dir = os.path.join(TRASH_DIR, trash_id)
    return trash_dir

def get_deleted_by_file(trash_id=None):
    trash_dir = get_trash_dir(trash_id)
    deleted_by_file = os.path.join(trash_dir, DELETED_BY_FILENAME)
    return deleted_by_file

def get_trash_file(object_id, trash_id=None):
    trash_dir = get_trash_dir(trash_id)
    trash_file_name = object_id.full_oid.replace("/", "+")
    trash_file = os.path.join(trash_dir, trash_file_name)
    if not os.path.exists(trash_dir):
        filetools.create_dir(trash_dir)
    return trash_file

def get_trash_data():
    trash_ids = {}
    for root, dirs, files in os.walk(TRASH_DIR):
        for x_dir in dirs:
            x_trash_id = x_dir
            x_dir = os.path.join(TRASH_DIR, x_dir)
            for x_root, x_dirs, x_files in os.walk(x_dir):
                if x_trash_id not in trash_ids:
                    trash_ids[x_trash_id] = []
                for x_file in x_files:
                    x_oid = x_file.replace("+", "/")
                    trash_ids[x_trash_id].append(x_oid)
    return trash_ids

def get_deleted_by(trash_id):
    deleted_by_file = get_deleted_by_file(trash_id)
    try:
        fd = open(deleted_by_file, "r")
    except Exception as e:
        msg = ("Failed to open deleted by file: %s: %s"
                % (deleted_by_file, e))
        logger.warning(msg)
        deleted_by = "Unknown"
    else:
        try:
            deleted_by = fd.read()
        except Exception as e:
            msg = ("Failed to read deleted by file: %s: %s"
                    % (deleted_by_file, e))
            logger.warning(msg)
            deleted_by = "Unknown"
        finally:
            fd.close()
    return deleted_by

def read_entry(trash_id, object_id):
    # Get OID.
    object_id = oid.get(object_id)
    # Get trash file.
    trash_file = get_trash_file(object_id, trash_id=trash_id)
    # Read data from file.
    try:
        file_content = filetools.read_file(trash_file)
    except Exception as e:
        msg = ("Failed to read object from trash: %s: %s"
                % (trash_file, e))
        raise OTPmeException(msg)
    # Decode data.
    try:
        object_data = json.loads(file_content)
    except Exception as e:
        msg = ("Failed to parse JSON data from trash file: %s: %s"
                % (trash_file, e))
        raise OTPmeException(msg)
    # Get object config.
    try:
        object_config = object_data['object_config']
    except KeyError:
        msg = "JSON data misses object object_config."
        raise OTPmeException(msg)
    # Decrypt object config.
    object_config = ObjectConfig(object_id, object_config)
    object_config = object_config.decrypt(config.master_key)
    object_data['object_config'] = object_config
    return object_data

def write_entry(trash_id, object_id, object_data, deleted_by):
    try:
        object_config = object_data['object_config']
    except KeyError:
        msg = "Missing object object_config."
        raise OTPmeException(msg)
    # Encrypt object config.
    object_id = oid.get(object_id)
    object_config = ObjectConfig(object_id, object_config, encrypted=False)
    object_config = object_config.encrypt(config.master_key,
                                        update_checksums=False)
    object_data['object_config'] = object_config
    # Encode to JSON.
    file_content = json.dumps(object_data)
    # Get trash file.
    trash_file = get_trash_file(object_id, trash_id=trash_id)
    try:
        filetools.create_file(path=trash_file, content=file_content)
    except Exception as e:
        msg = ("Failed to write trash file: %s: %s: %s"
                    % (object_id, trash_file, e))
        raise OTPmeException(msg)
    # Get deleted by file.
    deleted_by_file = get_deleted_by_file(trash_id)
    try:
        filetools.create_file(path=deleted_by_file, content=deleted_by)
    except Exception as e:
        msg = ("Failed to write deleted by file: %s: %s: %s"
                    % (object_id, deleted_by_file, e))
        raise OTPmeException(msg)

def add(object_id, deleted_by, callback=default_callback):
    trash_id = get_trash_id()
    trash_file = get_trash_file(object_id, trash_id=trash_id)
    deleted_by_file = get_deleted_by_file(trash_id)
    try:
        trash_data = backup.backup_object(object_id)
    except Exception as e:
        msg = "Failed to create object trash data: %s: %s" % (object_id, e)
        return callback.error(msg)
    filetools.create_file(path=trash_file, content=trash_data)
    filetools.create_file(path=deleted_by_file, content=deleted_by)
    # Cluster trash write.
    try:
        trash_data = backup.backup_object(object_id, decrypt=True)
    except Exception as e:
        msg = "Failed to create object trash data: %s: %s" % (object_id, e)
        return callback.error(msg)
    event_data = cluster_sync_object(object_id=object_id,
                                    object_data=trash_data,
                                    trash_id=trash_id,
                                    deleted_by=deleted_by,
                                    action="trash_write")
    cluster_event = event_data[0]
    if cluster_event:
        cluster_event.wait()

def delete(trash_id=None, cluster=True, callback=default_callback, **kwargs):
    if not trash_id:
        msg = "Need <trash_id>."
        raise OTPmeException(msg)
    trash_dir = os.path.join(TRASH_DIR, trash_id)
    if not os.path.exists(trash_dir):
        msg = "Unknown trash entry: %s" % trash_id
        return callback.error(msg)

    if config.auth_token:
        deleted_by = get_deleted_by(trash_id)
        deleted_by_token = "token:%s" % config.auth_token.rel_path
        if deleted_by != deleted_by_token:
            msg = "Permission denied"
            return callback.error(msg)

    try:
        filetools.remove_dir(trash_dir, recursive=True, remove_non_empty=True)
    except Exception as e:
        msg = "Failed to delete trash ID: %s: %s" % (trash_id, e)
        return callback.error(msg)
    if not cluster:
        return callback.ok()
    # Cluster trash ID deletion.
    event_data = cluster_sync_object(action="trash_delete", trash_id=trash_id)
    cluster_event = event_data[0]
    if cluster_event:
        cluster_event.wait()
    return callback.ok()

def restore(trash_id=None, objects=None, callback=default_callback, **kwargs):
    if not trash_id:
        msg = "Need <trash_id>."
        raise OTPmeException(msg)
    restore_objects = {}
    trash_dir = os.path.join(TRASH_DIR, trash_id)
    if not os.path.exists(trash_dir):
        msg = "Unknown trash entry: %s" % trash_id
        return callback.error(msg)

    if config.auth_token:
        deleted_by = get_deleted_by(trash_id)
        deleted_by_token = "token:%s" % config.auth_token.rel_path
        if deleted_by != deleted_by_token:
            msg = "Permission denied"
            return callback.error(msg)

    restore_objects_count = 0
    for root, dirs, files in os.walk(trash_dir):
        for x_file in files:
            if x_file == DELETED_BY_FILENAME:
                continue
            x_oid = x_file.replace("+", "/")
            x_trash_file = os.path.join(trash_dir, x_file)
            if objects:
                if x_oid not in objects:
                    continue
            x_oid = oid.get(x_oid)
            try:
                x_list = restore_objects[x_oid.object_type]
            except KeyError:
                x_list = []
            x_list.append((x_oid, x_trash_file))
            restore_objects[x_oid.object_type] = x_list
            restore_objects_count += 1

    restore_counter = 0
    for object_type in config.object_add_order:
        try:
            x_objects = restore_objects[object_type]
        except KeyError:
            continue

        x_restore_order = {}
        for x in x_objects:
            x_oid = x[0]
            x_trash_file = x[1]
            x_path_len = len(x_oid.path.split("/"))
            x_restore_order[x_oid] = {}
            x_restore_order[x_oid]['path_len'] = x_path_len
            x_restore_order[x_oid]['trash_file'] = x_trash_file

        x_sort = lambda x: x_restore_order[x]['path_len']
        x_restore_order_sorted = sorted(x_restore_order, key=x_sort)
        for x_oid in x_restore_order_sorted:
            x_trash_file = x_restore_order[x_oid]['trash_file']
            try:
                file_content = filetools.read_file(x_trash_file)
            except Exception as e:
                msg = ("Failed to read object from trash: %s: %s"
                        % (x_trash_file, e))
                return callback.error(msg)
            try:
                object_data = json.loads(file_content)
            except Exception as e:
                msg = ("Failed to parse JSON data from trash file: %s: %s"
                        % (x_trash_file, e))
                return callback.error(msg)
            try:
                restore_status = backup.restore_object(object_data,
                                                callback=callback)
            except Exception as e:
                msg = ("Failed to restore object from trash: %s: %s"
                        % (x_oid, e))
                return callback.error(msg)
            if not restore_status:
                return callback.abort()
            restore_counter += 1

    if restore_objects_count == restore_counter:
        try:
            delete(trash_id, cluster=True, callback=callback)
        except Exception as e:
            msg = "Failed to remove trash entry: %s: %s" % (trash_id, e)
            return callback.error(msg)

    msg = "Restored %s objects." % restore_counter
    return callback.ok(msg)

def empty(cluster=True, callback=default_callback, **kwargs):
    for root, dirs, files in os.walk(TRASH_DIR):
        for x_dir in dirs:
            trash_dir = os.path.join(TRASH_DIR, x_dir)
            try:
                filetools.remove_dir(trash_dir,
                                    recursive=True,
                                    remove_non_empty=True)
            except Exception as e:
                msg = "Failed to delete trash dir: %s: %s" % (x_dir, e)
                return callback.error(msg)
    if not cluster:
        return callback.ok()
    # Cluster trash empty.
    event_data = cluster_sync_object(action="trash_empty")
    cluster_event = event_data[0]
    if cluster_event:
        cluster_event.wait()
    return callback.ok()

def show_trash(max_len=10, border=True, header=True,
    output_fields=[], callback=default_callback, **kwargs):
    table_headers = [
                    "trash_id",
                    "object",
                    "deleted_by",
                    "deletion_date",
                    ]

    # Define output table using prettytable.
    table = PrettyTable(table_headers,
                        header_style="title",
                        vrules=NONE,
                        hrules=FRAME)
    table.align = "l"
    table.padding_width = 0
    table.right_padding_width = 1

    # Use a list copy of output fields to prevent changing of given list.
    if output_fields:
        output_fields = list(output_fields)
    else:
        output_fields = list(table_headers)

    entry_counter = 0
    for root, dirs, files in os.walk(TRASH_DIR):
        x_dirs = {}
        for x_dir in dirs:
            x_timestamp = os.path.basename(x_dir)
            x_timestamp = float(x_timestamp.split("-")[0])
            x_dirs[x_dir] = {}
            x_dirs[x_dir]['timestamp'] = x_timestamp

        x_sort = lambda x: x_dirs[x]['timestamp']
        x_dirs_sorted = sorted(x_dirs, key=x_sort, reverse=True)
        for x_dir in x_dirs_sorted:
            entry_counter += 1
            if entry_counter > max_len:
                continue
            x_dir = os.path.join(TRASH_DIR, x_dir)
            trash_id = os.path.basename(x_dir)
            deleted_by = get_deleted_by(trash_id)
            if config.auth_token and not config.auth_token.is_admin():
                deleted_by_token = "token:%s" % config.auth_token.rel_path
                if deleted_by != deleted_by_token:
                    continue
            deletion_date = float(trash_id.split("-")[0])
            deletion_date = datetime.datetime.fromtimestamp(deletion_date)
            deletion_date = deletion_date.strftime('%d.%m.%Y %H:%M:%S')
            for i in os.walk(x_dir):
                for y in i:
                    if y == x_dir:
                        continue
                    trash_id_added = False
                    for x in sorted(y):
                        if x == DELETED_BY_FILENAME:
                            continue
                        x_oid = x.replace("+", "/")
                        if trash_id_added:
                            x_row = ["", x_oid, deleted_by, deletion_date]
                        else:
                            trash_id_added = True
                            x_row = [trash_id, x_oid, deleted_by, deletion_date]
                        table.add_row(x_row)

    if entry_counter > max_len:
        footer = (_("Size limit exceeded. Listed %s entries out of %s.")
                    % (max_len, entry_counter))
    else:
        footer = (_("Total %s entries.") % entry_counter)

    # Get output string from table.
    output = table.get_string(start=0,
                        border=border,
                        header=header,
                        fields=output_fields)

    if border:
        output = "\n".join(output.split("\n")[1:-1])
    output = "%s\n\n%s" % (output, footer)

    return callback.ok(output)
