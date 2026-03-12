# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.client.fs import OTPmeFsClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-backup-1.0"

def register():
    config.register_otpme_protocol("backupd", PROTOCOL_VERSION)

class OTPmeBackupP1(OTPmeFsClient1):
    """ Class that implements management client for protocol OTPme-backup-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "backupd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeBackupP1, self).__init__(self.daemon, **kwargs)

    def send(self, command, command_args, binary_data=None):
        status, \
        response_code, \
        response, \
        binary_data = self.connection.send(command=command,
                                        command_args=command_args,
                                        binary_data=binary_data,
                                        handle_response=False,
                                        encrypt_request=False,
                                        encode_request=False,
                                        compress_request=False)
        return status, response_code, response, binary_data

    def mount(self, repo_id, username, default_group, groups):
        command_args = {
                        'repository'    : repo_id,
                        'username'      : username,
                        'default_group' : default_group,
                        'groups'        : groups,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="mount",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def open_repository(self, repository, password, write=False):
        command_args = {
                        'repository': repository,
                        'password'  : password,
                        'write'     : write,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="open_repository",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def start_backup(self, mode="pack"):
        command_args = {'mode':mode}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="start_backup",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def start_restore(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="start_restore",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def get_mode(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="get_mode",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def get_salt(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="get_salt",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return binary_data

    def list_snapshots(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="list_snapshots",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def lock_repo(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="lock_repo",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

    def unlock_repo(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="unlock_repo",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

    def create_snapshot(self, snap_name):
        command_args = {
                        'snap_name'     : snap_name,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="create_snapshot",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def write_entry(self, snap_name, path, metadata):
        command_args = {
                        'snap_name'     : snap_name,
                        'path'          : path,
                        'metadata'      : metadata,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="write_entry",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def block_exists(self, h):
        command_args = {
                        'h'     : h,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="block_exists",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False

        return status

    def store_block(self, h, blob):
        command_args = {
                        'h'     : h,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="store_block",
                                    command_args=command_args,
                                    binary_data=blob)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def retrieve_block(self, h):
        command_args = {
                        'h' : h,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="retrieve_block",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return binary_data

    def set_entry_metadata(self, snap_name, path, metadata):
        command_args = {
                        'snap_name'     : snap_name,
                        'path'          : path,
                        'metadata'      : metadata,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="set_entry_metadata",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def set_dirs_metadata(self, snap_name, dir_entries):
        command_args = {
                        'snap_name'     : snap_name,
                        'dir_entries'   : dir_entries,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="set_dirs_metadata",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return status

    def snap_dir(self, snap_name):
        command_args = {
                        'snap_name'     : snap_name,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="snap_dir",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def list_entries(self, snap_name, filter_path, full=False):
        command_args = {
                        'snap_name'     : snap_name,
                        'filter_path'   : filter_path,
                        'full'          : full,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="list_entries",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def link_entry(self, prev_snap, snap_name, rel, is_dir=None,
                   index_line=None, meta=None):
        command_args = {
                        'snap_name'     : snap_name,
                        'prev_snap'     : prev_snap,
                        'rel'           : rel,
                        'is_dir'        : is_dir,
                        'index_line'    : index_line,
                        'meta'          : meta,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="link_entry",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def get_entry_full(self, snap_name, rel):
        command_args = {
                        'snap_name'     : snap_name,
                        'rel'           : rel,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="get_entry_full",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def read_index(self, snap_name):
        command_args = {
                        'snap_name'     : snap_name,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="read_index",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def link_unchanged_entries(self, prev_snap, snap_name, entries):
        command_args = {
                        'prev_snap'     : prev_snap,
                        'snap_name'     : snap_name,
                        'entries'       : entries,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="link_unchanged_entries",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def set_running(self, name):
        command_args = {
                        'name'     : name,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="set_running",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def finalize_snapshot(self, name, total_bytes=0, stored_bytes=0, chunk_hashes=None):
        command_args = {
                        'name'          : name,
                        'total_bytes'   : total_bytes,
                        'stored_bytes'  : stored_bytes,
                        'chunk_hashes'  : sorted(chunk_hashes) if chunk_hashes else [],
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="finalize_snapshot",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def apply_retention(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="apply_retention",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status = False
            response = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(response)

        return response

    def exists(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="exists",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def get_mtime(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="get_mtime",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def get_ctime(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="get_ctime",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def access(self, path, amode):
        command_args = {'path': path, 'amode': amode}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="access",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def create(self, path, mode):
        command_args = {'path': path, 'mode': mode}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="create",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def getattr(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="getattr",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def link(self, target, source):
        command_args = {'target': target, 'source': source}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="link",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def read(self, path, size, offset):
        command_args = {'path': path, 'size': size, 'offset': offset}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="read",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            binary_data = None
        return status_code, binary_data

    def readdir(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="readdir",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def readlink(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="readlink",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def rename(self, old, new):
        command_args = {'old': old, 'new': new}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="rename",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def statfs(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="statfs",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def symlink(self, target, source):
        command_args = {'target': target, 'source': source}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="symlink",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def truncate(self, path, length):
        command_args = {'path': path, 'length': length}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="truncate",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def utimens(self, path, times):
        command_args = {'path': path, 'times': times}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="utimens",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def unlink(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="unlink",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def mkdir(self, path, mode):
        command_args = {'path': path, 'mode': mode}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="mkdir",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def rmdir(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="rmdir",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def chmod(self, path, mode):
        command_args = {'path': path, 'mode': mode}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="chmod",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def chown(self, path, uid, gid):
        command_args = {'path': path, 'uid': uid, 'gid': gid}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="chown",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def write(self, path, data, offset):
        command_args = {'path': path, 'offset': offset}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="write",
                                    command_args=command_args,
                                    binary_data=data)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def open(self, path, flags):
        command_args = {'path': path, 'flags': flags}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="open",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def release(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="release",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def getxattr(self, path, name, position):
        command_args = {'path': path, 'name': name, 'position': position}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="getxattr",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            binary_data = None
        return status_code, binary_data

    def setxattr(self, path, name, value, options, position):
        command_args = {
                        'path'      : path,
                        'name'      : name,
                        'value'     : value,
                        'options'   : options,
                        'position'  : position,
                    }
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="setxattr",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def listxattr(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="listxattr",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def removexattr(self, path, name):
        command_args = {'path': path, 'name': name}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="removexattr",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
            response = str(e)
        return status_code, response

    def read_restore_file(self, path):
        command_args = {'path': path}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="read_restore_file",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
        return status_code, binary_data

    def read_cryptfs_settings(self):
        command_args = {}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="read_cryptfs_settings",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
        return status_code, binary_data

    def get_chunk(self, h):
        command_args = {'h': h}
        try:
            status, \
            status_code, \
            response, \
            binary_data = self.send(command="get_chunk",
                                    command_args=command_args)
        except Exception as e:
            config.raise_exception()
            status_code = 400
        return status_code, binary_data
