# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import gzip
import stat
import errno
import setproctitle
from typing import Any
from functools import wraps
from typing import Optional

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import multiprocessing

from otpme.lib.protocols import status_codes
from otpme.lib.classes.backup import BackupServer
from otpme.lib.multiprocessing import drop_privileges
from otpme.lib.protocols.server.fs import OTPmeFsServer1

from otpme.lib.exceptions import *

filehandlers = {}

PASS_FILE = ".password"

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-backup-1.0"

def register():
    config.register_otpme_protocol("backupd", PROTOCOL_VERSION, server=True)

def fix_snapshot_path():
    def wrapper(f):
        @wraps(f)
        def wrapped(self, path, *args, **kwargs):
            try:
                skip = kwargs.pop('skip')
            except KeyError:
                skip = False
            if path == "/":
                self.snapshot = None
                path = path.split("/")
                path.insert(1, "snapshots")
                path = "/".join(path)
            if path != "/" and not path.startswith("/snapshots") and not path.startswith("/tree"):
                path = path.split("/")
                path_len = len(path)
                path.insert(1, "tree")
                if path_len > 1:
                    self.snapshot = path.pop(2)
                path = "/".join(path)
                if not skip:
                    if self.snapshot:
                        is_dir = False
                        try:
                            result = self.getattr(path, None, skip=True)
                        except Exception as e:
                            pass
                        else:
                            mode = result.get("st_mode", 0)
                            if stat.S_ISDIR(mode):
                                is_dir = True
                        if not is_dir:
                            x = f"{path}-{self.snapshot}"
                            if len(x) <= 255:
                                path = x
                            else:
                                basename = os.path.basename(path)
                                file_name = self.backup_handler._gen_hash_name(basename,
                                                                            self.snapshot)
                                path = path.split("/")
                                path[-1] = file_name
                                path = "/".join(path)
            return f(self, path, *args, **kwargs)
        return wrapped
    return wrapper

class OTPmeBackupP1(OTPmeFsServer1):
    """ Class that implements OTPme-backup-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "backupd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Backukpd does require host authentication on client connect.
        self.require_auth = "host"
        self.require_preauth = True
        # Allow non-otpme host/node clients.
        self.require_host = False
        # Instructs parent class to require a client certificate.
        self.require_client_cert = True
        # Auth request are allowed to any node.
        self.require_master_node = False
        # We need a clean cluster status.
        self.require_cluster_status = False
        # Will hold username/groups to drop permissions to.
        self.username = None
        self.default_group = None
        self.groups = None
        # Will hold repository name.
        self.repository = None
        # Will hold repository root when mounting as fuse fs.
        self.root = None
        # Will hold repository root when doing backup actions.
        self.backup_root = None
        # Snapshot to process.
        self.snapshot = None
        # Get logger.
        self.logger = config.logger
        # Dont compress filesystem data.
        self.compresss_response = False
        # Backup server handler.
        self.backup_handler = None
        # Client repo password.
        self.client_password = None
        # Password file.
        self.pass_file = None
        # Allow backup of disabled nodes.
        self.check_peer_disabled = False
        # Call parent class init.
        OTPmeFsServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def set_proctitle(self, repository, action):
        """ Set proctitle to contain repository and action. """
        if config.use_api:
            return
        new_proctitle ="{proctitle} Repository: {repository} Action: {action}"
        new_proctitle = new_proctitle.format(proctitle=self.proctitle,
                                            repository=repository,
                                            action=action)
        setproctitle.setproctitle(new_proctitle)

    def read_keep_file(self, file):
        try:
            fd = open(file, "r")
        except FileNotFoundError:
            return 0
        except Exception as e:
            log_msg = _("Failed to open keep file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        try:
            keep = int(fd.read().split("\n")[0])
        except Exception as e:
            log_msg = _("Failed to read keep file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        return keep

    def verify_client_pass(self):
        if not self.client_password:
            msg = _("Missing client password.")
            raise PermissionDenied(msg)
        try:
            fd = open(self.pass_file, "r")
        except Exception as e:
            msg = _("Failed to open password file {pass_file}")
            msg = msg.format(pass_file=self.pass_file)
            raise PermissionDenied(msg)
        try:
            repo_pass = fd.read()
        except Exception as e:
            msg = _("Failed to read password file {pass_file}")
            raise PermissionDenied(msg)
        if self.client_password == repo_pass:
            return True
        msg = _("Permission denied.")
        raise PermissionDenied(msg)

    def get_full_file_path(self, path):
        file_path = f"{self.root}/{path}"
        return file_path

    def _process(self, command, command_args, binary_data):
        """ Handle fuse requests. """
        if self.root:
            try:
                response = self.process_file_command(command,
                                                command_args,
                                                binary_data)
            except UnknownCommand:
                pass
            else:
                return response

        # All valid commands.
        valid_commands = [
                            "mount",
                            "open_repository",
                            "start_backup",
                            "start_restore",
                            "get_mode",
                            "get_salt",
                            "list_snapshots",
                            "create_snapshot",
                            "write_entry",
                            "block_exists",
                            "store_block",
                            "retrieve_block",
                            "set_entry_metadata",
                            "set_dirs_metadata",
                            "snap_dir",
                            "link_entry",
                            "get_entry_full",
                            "get_snap_index_info",
                            "get_snap_index_size",
                            "get_snap_index_chunk",
                            "get_snap_entry_ids",
                            "open_entry_cursor",
                            "next_entries",
                            "close_entry_cursor",
                            "link_unchanged_entries",
                            "set_running",
                            "finalize_snapshot",
                            "apply_retention",
                            "read_restore_file",
                            "read_cryptfs_settings",
                            "get_chunk",
                            "lock_repo",
                            "unlock_repo",
                        ]

        # Check if we got a valid command.
        if not command in valid_commands:
            message = _("Unknown command: {command}")
            message = message.format(command=command)
            status = False
            return self.build_response(status, message)

        status = True
        if command == "open_repository":
            if not os.path.exists(config.backup_dir):
                status = False
                message = _("Backup root dir does not exists: {backup_dir}")
                message = message.format(backup_dir=config.backup_dir)
                return self.build_response(status, message)
            if self.backup_handler:
                status = False
                message = _("Repository already opened: {repository}")
                message = message.format(repository=self.repository)
                return self.build_response(status, message)
            try:
                repository = command_args['repository']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing repository.")
                return self.build_response(status, message)
            try:
                write = command_args['write']
            except KeyError:
                write = False
            try:
                self.client_password = command_args['password']
            except KeyError:
                status = status_codes.PERMISSION_DENIED
                message = _("Need password.")
                return self.build_response(status, message)
            try:
                repo_type = repository.split("/")[0]
                repo_site = repository.split("/")[1]
                repo_name = repository.split("/")[2]
            except Exception:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Invalid repository id: {repository}")
                message = message.format(repository=repository)
                return self.build_response(status, message)
            self.repository = repository
            root_dir = os.path.join(config.backup_dir, repo_site, repo_type, repo_name)
            try:
                self.backup_root = os.path.realpath(root_dir)
            except Exception as e:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Failed to open repository: {repository}", log=True)
                message = message.format(repository=self.repository)
                log_msg = log_msg.format(repository=self.repository)
                log_msg = f"{log_msg}: {e}"
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            self.pass_file = os.path.join(self.backup_root, PASS_FILE)
            allow_new_repos = True
            if not config.allow_new_backup_repos:
                allow_new_repos = False
            elif isinstance(config.allow_new_backup_repos, list):
                if len(config.allow_new_backup_repos) > 0:
                    if self.client_cn not in config.allow_new_backup_repos:
                        allow_new_repos = False
            if not write:
                allow_new_repos = False
            if not allow_new_repos:
                if not os.path.exists(self.backup_root):
                    status = status_codes.UNKNOWN_OBJECT
                    message = _("Unknown repository: {repository}: {root_dir}")
                    message = message.format(repository=self.repository, root_dir=self.backup_root)
                    return self.build_response(status, message)
                try:
                    self.verify_client_pass()
                except Exception:
                    status = status_codes.PERMISSION_DENIED
                    message = _("Permission denied.")
                    return self.build_response(status, message)
            self.backup_handler = BackupServer(self.backup_root)
            self.set_proctitle(self.repository, action="open")
            message = _("Repository openend.")
            return self.build_response(status, message)

        elif command == "start_backup":
            if not self.backup_handler:
                status = False
                message = _("Open repository first.")
                message = message.format(repository=self.repository)
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                mode = "pack"
            if os.path.exists(self.pass_file):
                try:
                    self.verify_client_pass()
                except Exception as e:
                    status = status_codes.PERMISSION_DENIED
                    message = _("Permission denied.")
                    return self.build_response(status, message)
                status = True
                message = _("Password verified.")
            else:
                self.backup_handler.init_repository(mode=mode)
                try:
                    fd = open(self.pass_file, "w")
                except Exception as e:
                    status = status_codes.PERMISSION_DENIED
                    message = _("Failed to open password file {pass_file}")
                    message = message.format(pass_file=self.pass_file)
                    return self.build_response(status, message)
                try:
                    fd.write(self.client_password)
                except Exception as e:
                    status = status_codes.PERMISSION_DENIED
                    message = _("Failed to write password file {pass_file}")
                    message = message.format(pass_file=self.pass_file)
                    return self.build_response(status, message)
                status = True
                message = _("Repository initialized.")
            self.set_proctitle(self.repository, action="backup")
            return self.build_response(status, message)

        elif command == "start_restore":
            if not self.backup_handler:
                status = False
                message = _("Open repository first.")
                message = message.format(repository=self.repository)
                return self.build_response(status, message)
            try:
                self.verify_client_pass()
            except Exception as e:
                status = status_codes.PERMISSION_DENIED
                message = _("Permission denied.")
                return self.build_response(status, message)
            status = True
            message = _("Ready for restore.")
            self.set_proctitle(self.repository, action="restore")
            return self.build_response(status, message)

        elif command == "mount":
            if self.root:
                status = False
                message = _("Repository already mounted: {root}")
                message = message.format(root=self.root)
                return self.build_response(status, message)
            try:
                self.username = command_args['username']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing username.")
                return self.build_response(status, message)
            try:
                self.default_group = command_args['default_group']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing default_group.")
                return self.build_response(status, message)
            try:
                self.groups = command_args['groups']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing groups.")
                return self.build_response(status, message)
            try:
                repository = command_args['repository']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing repository.")
                return self.build_response(status, message)
            try:
                repo_type = repository.split("/")[0]
                repo_site = repository.split("/")[1]
                repo_name = repository.split("/")[2]
            except Exception:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Invalid repository id: {repository}")
                message = message.format(repository=repository)
                return self.build_response(status, message)
            self.repository = repository
            root_dir = os.path.join(config.backup_dir, repo_site, repo_type, repo_name)
            if not os.path.exists(root_dir):
                status = status_codes.UNKNOWN_OBJECT
                message = _("Unknown repository dir: {repository}: {root_dir}")
                message = message.format(repository=self.repository, root_dir=root_dir)
                return self.build_response(status, message)
            try:
                self.root = os.path.realpath(root_dir)
            except Exception as e:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Failed to mount repository: {repository}", log=True)
                message = message.format(repository=self.repository)
                log_msg = log_msg.format(repository=self.repository)
                log_msg = f"{log_msg}: {e}"
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            self.backup_handler = BackupServer(self.root)
            self.backup_handler.load_pack_index()
            try:
                drop_privileges(user=self.username, group=self.default_group, groups=self.groups)
            except Exception as e:
                status = status_codes.PERMISSION_DENIED
                message, log_msg = _("Failed to drop privileges: {error}", log=True)
                message = message.format(error=e)
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            self.set_proctitle(self.repository, action="mount")
            message = _("Repository mounted.")
            return self.build_response(status, message)

        elif command == "read_cryptfs_settings":
            if not self.root:
                status = False
                message = _("Mount first.")
                return self.build_response(status, message)
            try:
                conf_file_name = command_args['conf_file_name']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            backup_handler = BackupServer(self.root)
            snaps = backup_handler.list_snapshots()
            if not snaps:
                status = False
                message = _("Repository has no snapshots.")
                return self.build_response(status, message)
            snap = snaps[-1]['name']
            tree_dir = os.path.realpath(f"{self.root}/tree/")
            data_file = os.path.realpath(os.path.join(tree_dir, conf_file_name))
            if not data_file.startswith(tree_dir + "/"):
                status = False
                message = _("Invalid path.")
                return self.build_response(status, message)
            data_file = f"{data_file}-{snap}"
            try:
                fd = open(data_file, "rb")
            except Exception as e:
                log_msg = _("Failed to open cryptfs file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to open cryptfs file.")
                return self.build_response(status, message)
            try:
                raw_data = fd.read()
            except Exception as e:
                log_msg = _("Failed to read cryptfs file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to read cryptfs file.")
                return self.build_response(status, message)
            try:
                binary_data = gzip.decompress(raw_data)
            except Exception as e:
                log_msg = _("Failed to decrompress cryptfs file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to decrompress cryptfs file.")
                return self.build_response(status, message)
            status = True
            message = _("Cryptfs data.")
            self.set_proctitle(self.repository, action="read_cryptfs_settings")
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "read_restore_file":
            if not self.root:
                status = False
                message = _("Mount first.")
                message = message.format(repository=self.repository)
                return self.build_response(status, message)
            self.set_proctitle(self.repository, action="read_restore_file")
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                binary_data = self.read_restore_file(path)
            except Exception as e:
                log_msg = _("Failed to load restore file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to load restore file.")
                return self.build_response(status, message)
            status = True
            message = _("Restore file data.")
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "get_chunk":
            if not self.root:
                status = False
                message = _("Mount first.")
                message = message.format(repository=self.repository)
                return self.build_response(status, message)
            try:
                h = command_args['h']
            except KeyError:
                status = False
                message = _("Missing chunk.")
                return self.build_response(status, message)
            try:
                binary_data = self.backup_handler.retrieve_block(h)
            except Exception as e:
                log_msg = _("Failed to read block: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to read block.")
                return self.build_response(status, message)
            status = True
            message = _("Chunk file data.")
            self.set_proctitle(self.repository, action="get_chunk")
            return self.build_response(status, message, binary_data=binary_data)

        elif not self.backup_handler:
            message = _("Please open repository first.")
            status = False
            return self.build_response(status, message)

        elif command == "get_mode":
            try:
                message = self.backup_handler.get_mode()
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "get_salt":
            try:
                binary_data = self.backup_handler.get_salt()
                message = "Got salt."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
                binary_data = None
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "list_snapshots":
            try:
                message = self.backup_handler.list_snapshots()
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "create_snapshot":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.create_snapshot(snap_name)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "write_entry":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                metadata = command_args['metadata']
            except KeyError:
                status = False
                message = _("Missing metadata.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.write_entry(snap_name, path, metadata)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "block_exists":
            try:
                h = command_args['h']
            except KeyError:
                status = False
                message = _("Missing h.")
                return self.build_response(status, message)
            try:
                status = self.backup_handler.block_exists(h)
                message = "Block exists"
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "store_block":
            try:
                h = command_args['h']
            except KeyError:
                status = False
                message = _("Missing h.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.store_block(h, binary_data)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "retrieve_block":
            try:
                h = command_args['h']
            except KeyError:
                status = False
                message = _("Missing h.")
                return self.build_response(status, message)
            try:
                binary_data = self.backup_handler.retrieve_block(h)
                message = "Block retrieved"
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "set_entry_metadata":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                metadata = command_args['metadata']
            except KeyError:
                status = False
                message = _("Missing metadata.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.set_entry_metadata(snap_name, path, metadata)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "set_dirs_metadata":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                dir_entries = command_args['dir_entries']
            except KeyError:
                status = False
                message = _("Missing dir_entries.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.set_dirs_metadata(snap_name, dir_entries)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "snap_dir":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                message = str(self.backup_handler.snap_dir(snap_name))
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "link_entry":
            try:
                prev_snap = command_args['prev_snap']
            except KeyError:
                status = False
                message = _("Missing prev_snap.")
                return self.build_response(status, message)
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                rel = command_args['rel']
            except KeyError:
                status = False
                message = _("Missing rel.")
                return self.build_response(status, message)
            is_dir = command_args.get('is_dir', None)
            meta = command_args.get('meta', None)
            try:
                message = self.backup_handler.link_entry(prev_snap,
                                                        snap_name,
                                                        rel,
                                                        is_dir=is_dir,
                                                        meta=meta)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "get_entry_full":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                rel = command_args['rel']
            except KeyError:
                status = False
                message = _("Missing rel.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.get_entry_full(snap_name, rel)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "get_snap_index_info":
            try:
                snap_name = command_args.get('snap_name')
            except KeyError:
                snap_name = None
            try:
                info = self.backup_handler.get_snap_index_info(snap_name)
                message = f"{info['size']}:{info['fingerprint']}"
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "get_snap_index_size":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                message = str(self.backup_handler.get_snap_index_size(snap_name))
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "get_snap_index_chunk":
            try:
                snap_name = command_args['snap_name']
                offset = int(command_args['offset'])
                chunk_size = int(command_args['chunk_size'])
            except KeyError:
                status = False
                message = _("Missing arguments.")
                return self.build_response(status, message)
            if offset < 0 or chunk_size < 0 or chunk_size > 10 * 1024 * 1024:
                status = False
                message = _("Invalid offset or chunk_size.")
                return self.build_response(status, message)
            try:
                binary_data = self.backup_handler.get_snap_index_chunk(snap_name,
                                                                    offset,
                                                                    chunk_size)
                message = "Chunk data."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
                binary_data = None
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "get_snap_entry_ids":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing arguments.")
                return self.build_response(status, message)
            try:
                binary_data = self.backup_handler.get_snap_entry_ids(snap_name)
                if not binary_data:
                    binary_data = None
                message = "Entry IDs data."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
                binary_data = None
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "open_entry_cursor":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            filter_path = command_args.get('filter_path')
            full = command_args.get('full', False)
            try:
                self.backup_handler.open_entry_cursor(snap_name, filter_path, full)
                message = "Cursor opened."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "next_entries":
            count = int(command_args.get('count', 10000))
            try:
                message = self.backup_handler.next_entries(count)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "close_entry_cursor":
            try:
                self.backup_handler.close_entry_cursor()
                message = "Cursor closed."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "link_unchanged_entries":
            try:
                prev_snap = command_args['prev_snap']
            except KeyError:
                status = False
                message = _("Missing prev_snap.")
                return self.build_response(status, message)
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                entries = command_args['entries']
            except KeyError:
                status = False
                message = _("Missing entries.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.link_unchanged_entries(
                    prev_snap, snap_name, entries)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "set_running":
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = _("Missing name.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.set_running(name)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "finalize_snapshot":
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = _("Missing name.")
                return self.build_response(status, message)
            total_bytes = command_args.get('total_bytes', 0)
            stored_bytes = command_args.get('stored_bytes', 0)
            try:
                message = self.backup_handler.finalize_snapshot(
                    name, total_bytes=total_bytes, stored_bytes=stored_bytes)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "apply_retention":
            try:
                message = self.backup_handler.apply_retention()
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "lock_repo":
            if not self.backup_handler:
                status = False
                message = _("Open repository first.")
                return self.build_response(status, message)
            try:
                self.backup_handler.lock_repo()
                self.backup_handler.load_pack_index()
                message = _("Repository locked.")
            except Exception as e:
                status = False
                message = str(e)
            return self.build_response(status, message)

        elif command == "unlock_repo":
            if not self.backup_handler:
                status = False
                message = _("Open repository first.")
                return self.build_response(status, message)
            try:
                self.backup_handler.unlock_repo()
                message = _("Repository unlocked.")
            except Exception as e:
                status = False
                message = str(e)
            return self.build_response(status, message)

    def load_longname(self, file_path):
        longname_file = f"{self.root}/{file_path}"
        with gzip.open(longname_file, 'rt') as f:
            file_path = f.readline().replace("\n", "")
        return file_path

    def resolve_longname(self, path, name):
        if not name.endswith(".longname"):
            msg = _("Not logname.")
            raise OTPmeException(msg)
        file_path = f"{path}/{name}"
        name = re.sub('(.*).longname$', r'\1', name)
        if not name.endswith(self.snapshot):
            msg = _("Not from this snapshot.")
            raise OTPmeException(msg)
        file_path = self.load_longname(file_path)
        entry = os.path.basename(file_path)
        return name, entry, True

    def _read_restore_file(self, path):
        try:
            fd = open(path, "rb")
        except Exception as e:
            log_msg = _("Failed to open restore file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg)
        try:
            raw_data = fd.read()
        except Exception as e:
            log_msg = _("Failed to read restore file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg)
        try:
            binary_data = gzip.decompress(raw_data)
        except Exception as e:
            log_msg = _("Failed to decrompress restore file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg)
        return binary_data

    def _resolve_link(self, file_path):
        """ Resolve HARDLINK/SYMLINK entries to the target file path.
            Returns the resolved path or the original path if not a link. """
        try:
            with gzip.open(file_path, 'rt') as f:
                f.readline()  # line 0: rel_path
                header_line = f.readline().strip()
                if header_line in ("HARDLINK", "SYMLINK"):
                    dest = f.readline().strip().split()[0]
                    dest_file = f"{self.root}/tree/{dest}-{self.snapshot}"
                    return dest_file
        except (IOError, OSError, ValueError, IndexError):
            pass
        return file_path

    @fix_snapshot_path()
    def read_restore_file(self, path):
        restore_file = f"{self.root}/{path}"
        resolved = self._resolve_link(restore_file)
        return self._read_restore_file(resolved)

    def chmod(self, path: str, mode: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def chown(self, path: str, uid: int, gid: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def create(self, path: str, mode, fi=None) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def getattr(self, path: str, fh: Optional[int] = None) -> dict[str, Any]:
        result = super().getattr(path, fh)
        mode = result.get("st_mode", 0)
        # Directories are real dirs in tree/ — nothing to fix.
        if stat.S_ISDIR(mode):
            return result
        # For regular files the data/ entry is a small text file whose first
        # line contains the original size and mtime: "<size> <mtime>\n".
        # Replace st_size and st_blocks with the real values.
        if stat.S_ISREG(mode):
            try:
                file_path = self.get_full_file_path(path)
                # Follow links to get the actual file's size.
                file_path = self._resolve_link(file_path)
                with gzip.open(file_path, 'rt') as f:
                    f.readline()  # line 0: rel_path (skip)
                    size_line = f.readline()  # line 1: "<size> <mtime>"
                original_size = int(size_line.split()[0])
                result["st_size"] = original_size
                # fuse.py recalculates: new_blocks = (st_blocks * st_blksize) // PREFERRED_BLOCK_SIZE
                # du interprets final st_blocks as 512-byte units.
                # By setting st_blksize = PREFERRED_BLOCK_SIZE (4 MiB), the division
                # becomes a no-op and st_blocks passes through unchanged.
                result["st_blocks"] = (original_size + 511) // 512
                result["st_blksize"] = 4194304
            except (IOError, OSError, ValueError, IndexError) as e:
                pass
        return result

    def mkdir(self, path: str, mode: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def readdir(self, path: str) -> list:
        result = super().readdir(path)
        if not self.snapshot:
            return result
        readdir_result = []
        x_result = result['readdir']
        getattr_data = result['getattr']
        for x in x_result:
            if x == ".":
                x_mode = 16888
            elif x == "..":
                x_mode = 16888
            else:
                x_path = path + "/" + x
                x_data = getattr_data[x_path]['result']
                x_mode = x_data.get("st_mode", 0)
            if stat.S_ISDIR(x_mode):
                readdir_result.append(x)
                continue
            try:
                x, entry, longname = self.resolve_longname(path, x)
            except Exception as e:
                longname = False
            if not longname:
                if not x.endswith(self.snapshot):
                    continue
                entry = re.sub(f'(.*)-{self.snapshot}$', r'\1', x)
            readdir_result.append(entry)
        result['readdir'] = readdir_result
        for x_path in dict(result['getattr']):
            x_data = result['getattr'].pop(x_path)
            x_mode = x_data['result'].get("st_mode", 0)
            if stat.S_ISDIR(x_mode):
                x_path = x_path.split("/")
                x_path.pop(1)
                x_path.insert(1, self.snapshot)
                x_path = "/".join(x_path)
                result['getattr'][x_path] = x_data
                continue
            if x_path.endswith(".longname"):
                longname = x_path
                x_path = re.sub('(.*).longname$', r'\1', x_path)
            else:
                longname = False
            if not x_path.endswith(self.snapshot):
                continue
            if longname:
                longname = self.load_longname(longname)
                x_path = x_path.split("/")
                x_path[-1] = longname
            else:
                x_path = x_path.split("/")
            x_path.pop(1)
            x_path.insert(1, self.snapshot)
            x_path = "/".join(x_path)
            x_path = re.sub(f'(.*)-{self.snapshot}$', r'\1', x_path)
            result['getattr'][x_path] = x_data
        for x_path in dict(result['getxattr']):
            x_data = result['getxattr'].pop(x_path)
            if not x_path.endswith(self.snapshot):
                continue
            x_path = x_path.split("/")
            x_path.pop(1)
            x_path.insert(1, self.snapshot)
            x_path = "/".join(x_path)
            x_path = re.sub(f'(.*)-{self.snapshot}$', r'\1', x_path)
            result['getxattr'][x_path] = x_data
        return result

    @fix_snapshot_path()
    def readlink(self, path: str) -> str:
        return super().readlink(path)

    def rename(self, old: str, new: str):
        raise PermissionError(errno.EROFS, "Permission denied")

    def rmdir(self, path: str) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def symlink(self, target: str, source: str):
        raise PermissionError(errno.EROFS, "Permission denied")

    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def unlink(self, path: str) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def open(self, path: str, flags) -> int:
        if flags & os.O_WRONLY:
            flag_type = "write"
        elif flags & os.O_RDWR:
            flag_type = "write"
        elif flags & os.O_APPEND:
            flag_type = "write"
        else:
            flag_type = "read"
        if flag_type == "write":
            raise PermissionError(errno.EROFS, "Permission denied")
        return super().open(path, flags)

    @fix_snapshot_path()
    def read(self, path: str, size: int, offset: int) -> bytes:
        return super().read(path, size, offset)

    def write(self, path: str, data, offset: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def release(self, path: str) -> int:
        return super().release(path)

    @fix_snapshot_path()
    def access(self, path: str, amode: int) -> int:
        return super().access(path, amode)

    def link(self, target: str, source: str):
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def exists(self, path: str) -> int:
        return super().exists(path)

    @fix_snapshot_path()
    def get_mtime(self, path: str) -> int:
        return super().get_mtime(path)

    @fix_snapshot_path()
    def get_ctime(self, path: str) -> int:
        return super().get_ctime(path)

    @fix_snapshot_path()
    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs)"""
        return super().getxattr(path, name, position)

    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def listxattr(self, path: str) -> list:
        """List all extended attributes"""
        return super().listxattr(path)

    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes"""
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def statfs(self, path: str) -> dict[str, int]:
        return super().statfs(path)
