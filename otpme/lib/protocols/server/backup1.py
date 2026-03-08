# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
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
from otpme.lib import pidfile
from otpme.lib.fuse import CONF_FILE
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
            if path == "/":
                path = path.split("/")
                path.insert(1, "snapshots")
                path = "/".join(path)
            if path != "/" and not path.startswith("/snapshots"):
                path = path.split("/")
                path_len = len(path)
                path.insert(1, "snapshots")
                if path_len > 1:
                    path.insert(3, "data")
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
        # PID file.
        self.pidfile = None
        # Call parent class init.
        OTPmeFsServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def set_proctitle(self, repository, action):
        """ Set proctitle to contain sharename. """
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
                            "get_salt",
                            "list_snapshots",
                            "create_snapshot",
                            "write_entry",
                            "get_file_entry",
                            "copy_refs",
                            "block_exists",
                            "store_block",
                            "retrieve_block",
                            "add_ref",
                            "set_entry_metadata",
                            "snap_dir",
                            "list_entries",
                            "link_entry",
                            "get_entry_metadata",
                            "set_running",
                            "finalize_snapshot",
                            "apply_retention",
                            "read_restore_file",
                            "read_cryptfs_settings",
                            "get_chunk",
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
            if not write:
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
            if write:
                self.pidfile = os.path.join(self.backup_root, "running")
                pid = pidfile.is_running(self.pidfile)
                if pid:
                    status = status_codes.PERMISSION_DENIED
                    message = _("Backup repository locked.")
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
                self.backup_handler.init_repository()
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
            pidfile.create_pidfile(self.pidfile)
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
            backup_handler = BackupServer(self.root)
            snaps = backup_handler.list_snapshots()
            if not snaps:
                status = False
                message = _("Repository has no snapshots.")
                return self.build_response(status, message)
            snap = snaps[-1]['name']
            data_dir = f"{self.root}/snapshots/{snap}/data"
            data_file = os.path.join(data_dir, CONF_FILE)
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
                binary_data = fd.read()
            except Exception as e:
                log_msg = _("Failed to read cryptfs file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to read cryptfs file.")
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
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            restore_path = path.split("/")
            restore_path.insert(2, "data")
            restore_path = "/".join(restore_path)
            restore_file = f"{self.root}/snapshots/{restore_path}"
            try:
                fd = open(restore_file, "rb")
            except Exception as e:
                log_msg = _("Failed to open restore file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to open restore file.")
                return self.build_response(status, message)
            try:
                binary_data = fd.read()
            except Exception as e:
                log_msg = _("Failed to read restore file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to read restore file.")
                return self.build_response(status, message)
            status = True
            message = _("Restore file data.")
            self.set_proctitle(self.repository, action="read_restore_file")
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
            chunk_dir = h[:2]
            chunk_dir = f"{self.root}/objects/{chunk_dir}"
            chunk_file = f"{chunk_dir}/{h}"
            try:
                fd = open(chunk_file, "rb")
            except Exception as e:
                log_msg = _("Failed to open chunk file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to open chunk file.")
                return self.build_response(status, message)
            try:
                binary_data = fd.read()
            except Exception as e:
                log_msg = _("Failed to read chunk file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                status = False
                message = _("Failed to read chunk file.")
                return self.build_response(status, message)
            status = True
            message = _("Chunk file data.")
            self.set_proctitle(self.repository, action="get_chunk")
            return self.build_response(status, message, binary_data=binary_data)

        elif not self.backup_handler:
            message = _("Please open repository first.")
            status = False
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

        elif command == "get_file_entry":
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
                message = self.backup_handler.get_file_entry(snap_name, path)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "copy_refs":
            try:
                from_snap = command_args['from_snap']
            except KeyError:
                status = False
                message = _("Missing from_snap.")
                return self.build_response(status, message)
            try:
                to_snap = command_args['to_snap']
            except KeyError:
                status = False
                message = _("Missing to_snap.")
                return self.build_response(status, message)
            try:
                chunk_hashes = command_args['chunk_hashes']
            except KeyError:
                status = False
                message = _("Missing chunk_hashes.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.copy_refs(from_snap, to_snap, chunk_hashes)
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

        elif command == "add_ref":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                h = command_args['h']
            except KeyError:
                status = False
                message = _("Missing h.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.add_ref(snap_name, h)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

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

        elif command == "list_entries":
            try:
                snap_name = command_args['snap_name']
            except KeyError:
                status = False
                message = _("Missing snap_name.")
                return self.build_response(status, message)
            try:
                filter_path = command_args['filter_path']
            except KeyError:
                status = False
                message = _("Missing filter_path.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.list_entries(snap_name, filter_path)
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
            try:
                message = self.backup_handler.link_entry(prev_snap, snap_name, rel)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

        elif command == "get_entry_metadata":
            try:
                prev_snap = command_args['prev_snap']
            except KeyError:
                status = False
                message = _("Missing prev_snap.")
                return self.build_response(status, message)
            try:
                rel = command_args['rel']
            except KeyError:
                status = False
                message = _("Missing rel.")
                return self.build_response(status, message)
            try:
                message = self.backup_handler.get_entry_metadata(prev_snap, rel)
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
            try:
                message = self.backup_handler.finalize_snapshot(name)
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            os.remove(self.pidfile)
            return self.build_response(status, message)

        elif command == "apply_retention":
            daily_file = os.path.join(self.backup_root, ".daily")
            weekly_file = os.path.join(self.backup_root, ".weekly")
            monthly_file = os.path.join(self.backup_root, ".monthly")
            status = True
            apply_retention = True
            keep_daily = self.read_keep_file(daily_file)
            if keep_daily is None:
                status = False
                apply_retention = False
                message = _("Failed to read daily keep file.")
            keep_weekly = self.read_keep_file(weekly_file)
            if keep_weekly is None:
                status = False
                apply_retention = False
                message = _("Failed to read weekly keep file.")
            keep_monthly = self.read_keep_file(monthly_file)
            if keep_monthly is None:
                status = False
                apply_retention = False
                message = _("Failed to read monthly keep file.")
            if apply_retention:
                if keep_daily == 0 and keep_weekly == 0 and keep_monthly == 0:
                    apply_retention = False
                    message = _("No retention configured.")
            if apply_retention:
                try:
                    message = self.backup_handler.apply_retention(daily=keep_daily,
                                                                weekly=keep_weekly,
                                                                monthly=keep_monthly)
                except Exception as e:
                    status = False
                    message = f"{command}: {e}"
            return self.build_response(status, message)

    @fix_snapshot_path()
    def chmod(self, path: str, mode: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def chown(self, path: str, uid: int, gid: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def create(self, path: str, mode, fi=None) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def getattr(self, path: str, fh: Optional[int] = None) -> dict[str, Any]:
        result = super().getattr(path, fh)
        mode = result.get("st_mode", 0)
        # Directories are real dirs in data/ — nothing to fix.
        if stat.S_ISDIR(mode):
            return result
        # For regular files the data/ entry is a small text file whose first
        # line contains the original size and mtime: "<size> <mtime>\n".
        # Replace st_size and st_blocks with the real values.
        if stat.S_ISREG(mode):
            try:
                file_path = self.get_full_file_path(path)
                with open(file_path, "r") as f:
                    first_line = f.readline()
                original_size = int(first_line.split()[0])
                result["st_size"] = original_size
                # Approximate block count (512-byte blocks).
                # FIXME: get blocksize of underlying fs?
                result["st_blocks"] = (original_size + 511) // 512
            except (IOError, OSError, ValueError, IndexError) as e:
                pass
        return result

    @fix_snapshot_path()
    def mkdir(self, path: str, mode: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def readdir(self, path: str) -> list:
        result = super().readdir(path)
        if len(path.split("/")) < 4:
            return result
        for x_path in dict(result['getattr']):
            x_data = result['getattr'].pop(x_path)
            x_path = x_path.split("/")
            x_path.pop(1)
            x_path.pop(2)
            x_path = "/".join(x_path)
            result['getattr'][x_path] = x_data
        for x_path in dict(result['getxattr']):
            x_data = result['getxattr'].pop(x_path)
            x_path = x_path.split("/")
            x_path.pop(1)
            x_path.pop(2)
            x_path = "/".join(x_path)
            result['getxattr'][x_path] = x_data
        return result

    @fix_snapshot_path()
    def readlink(self, path: str) -> str:
        return super().readlink(path)

    @fix_snapshot_path()
    def rename(self, old: str, new: str):
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def rmdir(self, path: str) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def symlink(self, target: str, source: str):
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def unlink(self, path: str) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
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

    @fix_snapshot_path()
    def write(self, path: str, data, offset: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def release(self, path: str) -> int:
        return super().release(path)

    @fix_snapshot_path()
    def access(self, path: str, amode: int) -> int:
        return super().access(path, amode)

    @fix_snapshot_path()
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

    @fix_snapshot_path()
    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def listxattr(self, path: str) -> list:
        """List all extended attributes"""
        return super().listxattr(path)

    @fix_snapshot_path()
    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes"""
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def statfs(self, path: str) -> dict[str, int]:
        return super().statfs(path)
