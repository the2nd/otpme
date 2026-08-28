# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import pwd
import grp
import time
import gzip
import stat
import glob
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
except Exception:
    pass

from otpme.lib import jwt
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import posix_acl
from otpme.lib import multiprocessing

from otpme.lib.protocols import status_codes
from otpme.lib.classes.backup import BackupServer
from otpme.lib.multiprocessing import drop_privileges
from otpme.lib.protocols.server.fs import ACL_XATTRS
from otpme.lib.protocols.server.fs import OTPmeFsServer1

from otpme.lib.exceptions import *

filehandlers = {}
getattr_cache = {}
readdir_cache = {}

PASS_FILE = ".password"

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-backup-1.0"

def register():
    config.register_otpme_protocol("backupd", PROTOCOL_VERSION, server=True)

def fix_snapshot_path(amode=os.F_OK):
    """ Map a client path to the repository layout and check permissions.

    amode: the access the wrapped method needs on the entry itself (the parent
    directories always need search permission).
    """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, path, *args, **kwargs):
            try:
                skip = kwargs.pop('skip')
            except KeyError:
                skip = False
            # Will hold the entries path within the snapshot (methods that
            # need the access mode at runtime need it, e.g. access()).
            self.snapshot_rel_path = None
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
                        # A snapshot a backup is still writing has nothing to
                        # show yet: its entries are not in the index and its
                        # directories have not got their metadata.
                        if not self.snapshot_complete(self.snapshot):
                            raise FileNotFoundError(errno.ENOENT,
                                                os.strerror(errno.ENOENT))
                        is_dir = False
                        try:
                            result = self.getattr(path, None, skip=True)
                        except Exception as e:
                            pass
                        else:
                            mode = result.get("st_mode", 0)
                            if stat.S_ISDIR(mode):
                                is_dir = True
                        if is_dir:
                            # The directory exists in the shared tree/ but may
                            # not belong to this snapshot -> report as absent
                            # (covers getattr and the readdir target itself).
                            if not self._dir_in_snapshot(path):
                                raise FileNotFoundError(errno.ENOENT,
                                                    os.strerror(errno.ENOENT))
                        # The entries in tree/ carry the permissions/ACLs of
                        # the last backup, so the kernel cannot decide this
                        # for us -> evaluate the ones of this snapshot.
                        self.check_snapshot_access(path, amode)
                        if not is_dir:
                            # Check for longname.
                            x = f"{path}-{self.snapshot}"
                            basename = os.path.basename(x)
                            tree_name = f"{basename}-{self.snapshot}"
                            path_len = len(tree_name)
                            if path_len <= 255:
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
        # The IDs of the mount user. We need them to evaluate the
        # permissions/ACLs a snapshot recorded for its entries.
        self.mount_uid = None
        self.mount_gid = None
        self.mount_gids = []
        # Cache for the entry metadata of the current snapshot.
        self.snapshot_entry_cache = {}
        # Snapshots we know are finished. A finished one never becomes
        # unfinished, so this only ever holds positives.
        self.complete_snapshots = set()
        # What the repository looked like when we last filled the caches.
        self.repo_stamp = None
        # Path of the entry the current request is about (within the snapshot).
        self.snapshot_rel_path = None
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
        # Set once the repo password has been verified (or a new repo was
        # initialized by this client). Data commands require this.
        self.repo_pass_verified = False
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

    def _resolve_repo_root(self, repository):
        """ Validate the client-supplied repository id and resolve it to
        an absolute path strictly under config.backup_dir.

        The id is expected as "<type>/<site>/<name>" and resolves to
        <backup_dir>/<site>/<type>/<name>. Returns the resolved
        absolute path, or None if the id is malformed or escapes
        backup_dir via ".." or symlinks. Without this check, "mount"
        and "open_repository" would happily realpath() arbitrary
        attacker-chosen paths and (with allow_new_backup_repos) drop a
        .password file outside backup_dir. """
        if not isinstance(repository, str) or "\x00" in repository:
            return None
        parts = repository.split("/")
        if len(parts) != 3:
            return None
        if any(p in ("", ".", "..") for p in parts):
            return None
        repo_type, repo_site, repo_name = parts
        try:
            backup_dir_real = os.path.realpath(config.backup_dir)
            candidate = os.path.realpath(os.path.join(backup_dir_real,
                                                     repo_site,
                                                     repo_type,
                                                     repo_name))
            if os.path.commonpath([backup_dir_real, candidate]) != backup_dir_real:
                return None
        except Exception:
            return None
        return candidate

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

    def _verify_mount_jwt(self, mount_jwt, repository, username,
                          default_group, groups):
        """ Verify a mount JWT signed by the caller's site.

        The caller (fsd) signs a short-lived JWT with its local site's
        private key; we resolve the site via the JWT payload and verify
        the signature against site._cert_public_key, then match every
        claim against the current mount request. Returns the decoded
        payload dict on success, None otherwise. """
        try:
            unverified = jwt.decode(mount_jwt,
                                    secret="",
                                    algorithm='RS256',
                                    options={'verify_signature': False})
        except Exception as e:
            log_msg = _("Mount JWT decode failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        realm = unverified.get('realm')
        site_name = unverified.get('site')
        if not realm or not site_name:
            log_msg = _("Mount JWT missing realm/site claim.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        result = backend.search(object_type="site",
                                attribute="name",
                                value=site_name,
                                realm=realm)
        if not result:
            log_msg = _("Mount JWT for unknown site: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site_name)
            self.logger.warning(log_msg)
            return None
        site = backend.get_object(uuid=result[0])
        if not site or not site._cert_public_key:
            log_msg = _("Mount JWT site public key missing: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site_name)
            self.logger.warning(log_msg)
            return None
        try:
            data = jwt.decode(mount_jwt,
                              key=site._cert_public_key,
                              algorithm='RS256')
        except Exception as e:
            log_msg = _("Mount JWT signature verification failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            return None
        if data.get('reason') != 'BACKUP_MOUNT':
            log_msg = _("Mount JWT wrong reason: {reason}", log=True)[1]
            log_msg = log_msg.format(reason=data.get('reason'))
            self.logger.warning(log_msg)
            return None
        exp = data.get('exp')
        if not isinstance(exp, (int, float)) or exp < time.time():
            log_msg = _("Mount JWT expired.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        if data.get('repository') != repository:
            log_msg = _("Mount JWT repository mismatch.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        if data.get('username') != username:
            log_msg = _("Mount JWT username mismatch.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        if data.get('default_group') != default_group:
            log_msg = _("Mount JWT default_group mismatch.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        if list(data.get('groups') or []) != list(groups or []):
            log_msg = _("Mount JWT groups mismatch.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        if not data.get('password'):
            log_msg = _("Mount JWT missing password claim.", log=True)[1]
            self.logger.warning(log_msg)
            return None
        return data

    def verify_client_pass(self):
        if not self.client_password:
            msg = _("Missing client password.")
            raise PermissionDenied(msg)
        try:
            fd = open(self.pass_file, "r")
        except Exception as e:
            msg = _("Failed to open password file {pass_file}")
            msg = msg.format(pass_file=self.pass_file)
            raise PermissionDenied(msg) from e
        try:
            repo_pass = fd.read()
        except Exception as e:
            msg = _("Failed to read password file {pass_file}")
            raise PermissionDenied(msg) from e
        if self.client_password == repo_pass:
            self.repo_pass_verified = True
            return True
        msg = _("Permission denied.")
        raise PermissionDenied(msg)

    def get_full_file_path(self, path):
        file_path = f"{self.root}/{path}"
        return file_path

    def get_repo_stamp(self):
        """ Get something cheap that changes when the repository does.

        The index database, its write-ahead log and the snapshots directory:
        a backup adds a snapshot and commits index rows, and each of those
        shows up in one of them.
        """
        db_path = self.backup_handler._snap_index_db_path()
        stamp = []
        for x_path in (db_path,
                        f"{db_path}-wal",
                        str(self.backup_handler.snapshots_dir)):
            try:
                x_stat = os.stat(x_path)
            except OSError:
                stamp.append(None)
                continue
            stamp.append((x_stat.st_mtime_ns, x_stat.st_size))
        return tuple(stamp)

    def check_repo_changed(self):
        """ Drop the caches if the repository changed under us.

        A mount is served from caches that never expire, and rightly so: the
        entries of a finished snapshot do not change. But a backup running
        while the mount is open does change the repository -- it adds a
        snapshot and it commits the index rows of the one it is writing. A
        mount that looked in the meantime would else keep serving what it saw
        back then, which is the repository mid-backup: entries that are not
        in the index yet, and a tree/ directory whose permissions have not
        been applied. Until it is unmounted.
        """
        if not self.backup_handler:
            return
        try:
            stamp = self.get_repo_stamp()
        except Exception as e:
            log_msg = _("Failed to check repository state: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return
        if stamp == self.repo_stamp:
            return
        self.repo_stamp = stamp
        getattr_cache.clear()
        readdir_cache.clear()
        self.snapshot_entry_cache.clear()
        self.complete_snapshots.clear()

    def drop_incomplete_snapshots(self, result):
        """ Keep the snapshots a backup is still writing out of the listing.

        Offering one would only lead into an empty or half applied snapshot,
        see snapshot_complete().
        """
        listed = []
        for x_entry in result['readdir']:
            if x_entry in (".", ".."):
                listed.append(x_entry)
                continue
            if not self.snapshot_complete(x_entry):
                continue
            listed.append(x_entry)
        result['readdir'] = listed
        # Keep the cached metadata in step with the listing.
        keep = set(listed)
        for x_map in ('getattr', 'getxattr'):
            for x_path in list(result[x_map]):
                if os.path.basename(x_path) in keep:
                    continue
                result[x_map].pop(x_path)

    def snapshot_complete(self, snap_name):
        """ Check if a backup has finished writing the given snapshot.

        The snapshot directory exists from the moment a backup starts, but
        its entries only reach the index when the backup commits. Serving it
        in between hands out the repository mid-backup.
        """
        if not self.backup_handler:
            return True
        if snap_name in self.complete_snapshots:
            return True
        try:
            complete = self.backup_handler.is_complete(snap_name)
        except Exception:
            return False
        if complete:
            self.complete_snapshots.add(snap_name)
        return complete

    def resolve_mount_ids(self):
        """ Resolve the UID/GIDs of the mount user.

        We have to evaluate the permissions/ACLs of the snapshot ourselves
        (see check_snapshot_access()) and thus need the numeric IDs of the
        user we mount for. They are resolved before we drop privileges, so a
        failure here is the same failure drop_privileges() would run into.
        """
        try:
            self.mount_uid = pwd.getpwnam(self.username).pw_uid
        except KeyError as e:
            msg = _("Unknown user: {username}")
            msg = msg.format(username=self.username)
            raise OTPmeException(msg) from e
        try:
            self.mount_gid = grp.getgrnam(self.default_group).gr_gid
        except KeyError as e:
            msg = _("Unknown group: {group_name}")
            msg = msg.format(group_name=self.default_group)
            raise OTPmeException(msg) from e
        mount_gids = [self.mount_gid]
        for x_group in self.groups:
            try:
                x_gid = grp.getgrnam(x_group).gr_gid
            except KeyError:
                # Not fatal: drop_privileges() will fail on its own if the
                # group is really needed.
                continue
            if x_gid in mount_gids:
                continue
            mount_gids.append(x_gid)
        self.mount_gids = mount_gids

    def _process(self, command, command_args, binary_data):
        """ Handle fuse requests. """
        if self.root:
            # Once per client request, not per entry we touch while serving
            # it: a backup running while this mount is open changes the
            # repository under us.
            self.check_repo_changed()
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
                            "get_key_check",
                            "set_key_check",
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

        # All data commands require a verified repository password. The
        # entry-point commands below either verify it themselves
        # (open_repository / start_restore / mount) or initialize a brand-new
        # repo (start_backup). Everything else must not run until the
        # password has been verified for this connection.
        verify_exempt = ("open_repository", "start_backup",
                        "start_restore", "mount")
        if command not in verify_exempt and not self.repo_pass_verified:
            status = status_codes.PERMISSION_DENIED
            message = _("Open repository first.")
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
            self.repository = repository
            self.backup_root = self._resolve_repo_root(repository)
            if self.backup_root is None:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Invalid repository id: {repository}", log=True)
                message = message.format(repository=repository)
                log_msg = log_msg.format(repository=repository)
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
            if os.path.exists(self.pass_file):
                # An already-initialized repository (password file present)
                # must always pass the password check. allow_new_backup_repos
                # must never bypass it for an existing repo -- it only permits
                # creating a brand-new one.
                try:
                    self.verify_client_pass()
                except Exception:
                    status = status_codes.PERMISSION_DENIED
                    message = _("Permission denied.")
                    return self.build_response(status, message)
            elif not allow_new_repos:
                # Repository not initialized and we may not create a new one.
                status = status_codes.UNKNOWN_OBJECT
                message = _("Unknown repository: {repository}: {root_dir}")
                message = message.format(repository=self.repository, root_dir=self.backup_root)
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
                # The client just set the repo password -> authorized.
                self.repo_pass_verified = True
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
            # backupd runs with dont_drop_privileges=True, so any client
            # allowed here effectively runs as root during file ops
            # (drop_privileges is a no-op when the process is already
            # root and the client picks its own username). Require a
            # short-lived mount JWT signed by the caller's site so only
            # trusted OTPme daemons (fsd) can reach this handler.
            try:
                mount_jwt = command_args['mount_jwt']
            except KeyError:
                status = status_codes.PERMISSION_DENIED
                message = _("Missing mount JWT.")
                return self.build_response(status, message)
            jwt_data = self._verify_mount_jwt(mount_jwt,
                                              repository=repository,
                                              username=self.username,
                                              default_group=self.default_group,
                                              groups=self.groups)
            if not jwt_data:
                status = status_codes.PERMISSION_DENIED
                message = _("Invalid mount JWT.")
                return self.build_response(status, message)
            self.client_password = jwt_data['password']
            self.repository = repository
            self.root = self._resolve_repo_root(repository)
            if self.root is None:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Invalid repository id: {repository}", log=True)
                message = message.format(repository=repository)
                log_msg = log_msg.format(repository=repository)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            if not os.path.exists(self.root):
                status = status_codes.UNKNOWN_OBJECT
                message = _("Unknown repository dir: {repository}: {root_dir}")
                message = message.format(repository=self.repository, root_dir=self.root)
                return self.build_response(status, message)
            # Verify the per-repo password (carried inside the mount JWT)
            # against the persisted .password file before binding the
            # backup_handler so every follow-up file handler operates
            # on an authenticated mount.
            self.pass_file = os.path.join(self.root, PASS_FILE)
            try:
                self.verify_client_pass()
            except Exception:
                self.root = None
                self.pass_file = None
                status = status_codes.PERMISSION_DENIED
                message = _("Permission denied.")
                return self.build_response(status, message)
            self.backup_handler = BackupServer(self.root)
            self.backup_handler.load_pack_index()
            try:
                self.resolve_mount_ids()
            except Exception as e:
                status = status_codes.PERMISSION_DENIED
                message, log_msg = _("Failed to resolve mount user: {error}", log=True)
                message = message.format(error=e)
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            # Read everything that belongs to the repository itself before we
            # drop privileges: it belongs to us, not to the mount user, so
            # afterwards we could open neither the database and the WAL files
            # it needs nor the mode file.
            try:
                self.backup_handler.get_mode()
                self.backup_handler._open_snap_db(readonly=True)
            except Exception as e:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Failed to open snap-index: {error}", log=True)
                message = message.format(error=e)
                log_msg = log_msg.format(error=e)
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

        elif command == "get_key_check":
            try:
                binary_data = self.backup_handler.get_key_check()
                if not binary_data:
                    binary_data = None
                message = "Got key check."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
                binary_data = None
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "set_key_check":
            if not binary_data:
                status = False
                message = _("Missing key check.")
                return self.build_response(status, message)
            try:
                self.backup_handler.set_key_check(binary_data)
                message = "Key check stored."
            except Exception as e:
                status = False
                message = f"{command}: {e}"
            return self.build_response(status, message)

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
            if offset < 0 or chunk_size < 0 or chunk_size > 100 * 1024 * 1024:
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
        return name, entry

    def _resolve_link(self, file_path):
        """ Resolve HARDLINK/SYMLINK entries to the target file path.
            Returns the resolved path or the original path if not a link. """
        try:
            with gzip.open(file_path, 'rt') as f:
                f.readline()  # line 0: rel_path
                header_line = f.readline().strip()
                if header_line == "SYMLINK":
                    return file_path, True
                if header_line == "HARDLINK":
                    dest = f.readline().strip().split()[0]
                    dest_file = f"{self.root}/tree/{dest}-{self.snapshot}"
                    return dest_file, False
        except (IOError, OSError, ValueError, IndexError):
            pass
        return file_path, False

    @fix_snapshot_path(amode=os.R_OK)
    def read_restore_file(self, path):
        restore_file = f"{self.root}/{path}"
        # Enforce the repo boundary before touching the filesystem —
        # fix_snapshot_path lets any /tree/... path pass through
        # unchanged, so ".." traversal from the client is otherwise
        # only limited by backupd's process credentials (root).
        try:
            root_real = os.path.realpath(self.root)
            resolved_check = os.path.realpath(restore_file)
            if os.path.commonpath([root_real, resolved_check]) != root_real:
                raise ValueError("outside repo")
        except (ValueError, OSError) as e:
            log_msg = _("Rejected restore path outside repo: {path}: {e}", log=True)[1]
            log_msg = log_msg.format(path=path, e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg) from e
        resolved = self._resolve_link(restore_file)[0]
        try:
            resolved_real = os.path.realpath(resolved)
            if os.path.commonpath([root_real, resolved_real]) != root_real:
                raise ValueError("link outside repo")
        except (ValueError, OSError) as e:
            log_msg = _("Rejected restore path via link outside repo: {path}: {e}", log=True)[1]
            log_msg = log_msg.format(path=path, e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg) from e
        try:
            fd = open(resolved, "rb")
        except Exception as e:
            log_msg = _("Failed to open restore file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg) from e
        try:
            raw_data = fd.read()
        except Exception as e:
            log_msg = _("Failed to read restore file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg) from e
        try:
            binary_data = gzip.decompress(raw_data)
        except Exception as e:
            log_msg = _("Failed to decrompress restore file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg) from e
        return binary_data

    def chmod(self, path: str, mode: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def chown(self, path: str, uid: int, gid: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def create(self, path: str, mode, fi=None) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    def _dir_in_snapshot(self, tree_path):
        """ Return True if the tree/ directory 'tree_path' belongs to the
        currently selected snapshot (self.snapshot).

        Directories live in the shared tree/ across ALL snapshots, so their
        mere presence on disk does not imply membership. The index answers
        that: it has one entry per snapshot and path. 'tree_path' is the
        internal "/tree/<enc-rel>" path; stripping the "/tree/" prefix yields
        the encrypted rel path. Returns True when there is nothing to check
        against (no snapshot / no handler / unexpected path), so non-snapshot
        browsing is unaffected. A directory we find no entry for is reported
        as absent: we would else fall back to the permissions of the last
        backup (see check_snapshot_access()).
        """
        if not self.snapshot or not self.backup_handler:
            return True
        prefix = "/tree/"
        if not tree_path.startswith(prefix):
            return True
        rel_key = tree_path[len(prefix):]
        if not rel_key:
            return True
        entry = self.get_snapshot_entry(rel_key)
        return entry is not None and entry['is_dir']

    def get_tree_rel_path(self, tree_path):
        """ Get the entries path within the snapshot.

        The internal path is "/tree/<enc-rel>". Stripping the prefix yields
        the encrypted rel path the snapshot uses as key. The tree root itself
        is stored as ".". Returns None for paths outside tree/.
        """
        prefix = "/tree"
        if not tree_path.startswith(prefix):
            return None
        rel_path = tree_path[len(prefix):].strip("/")
        if not rel_path:
            return "."
        return rel_path

    def get_snapshot_entry(self, rel_path):
        """ Get the metadata the current snapshot recorded for an entry.

        This is the metadata the entry had at backup time (mode, uid, gid and
        the ACLs), not the one the entry carries on disk. Returns None if the
        entry is not part of this snapshot.

        It comes from the index, not from the filesystem. A directory in tree/
        is shared by all snapshots and carries the metadata of the last
        backup, and the entries of the others we may not even be allowed to
        read: we run with the privileges of the mount user. The index is open
        read-only since before we dropped privileges, see the mount command.
        """
        cache_key = f"{self.snapshot}:{rel_path}"
        try:
            return self.snapshot_entry_cache[cache_key]
        except KeyError:
            pass
        entry = None
        try:
            index_entry = self.backup_handler.entry_from_index(self.snapshot,
                                                            rel_path)
        except Exception as e:
            log_msg = _("Failed to read snapshot entry: {rel_path}: {error}", log=True)[1]
            log_msg = log_msg.format(rel_path=rel_path, error=e)
            self.logger.warning(log_msg)
            index_entry = None
        if index_entry is not None:
            entry = {
                    'mode'          : index_entry['mode'],
                    'uid'           : index_entry['uid'],
                    'gid'           : index_entry['gid'],
                    'mtime'         : index_entry['mtime'],
                    'acl'           : index_entry.get('acl'),
                    'default_acl'   : index_entry.get('default_acl'),
                    'is_dir'        : index_entry.get('type_line') == "DIR",
                    }
            # Parsed once: the access check runs for every parent directory
            # of every request.
            entry['acl_parsed'] = posix_acl.parse_acl_text(entry['acl'])
            self.snapshot_entry_cache[cache_key] = entry
        # A miss is not cached: it may only mean the backup writing this
        # snapshot has not committed its entries yet, and that answer must
        # not outlive the backup.
        return entry

    def check_entry_access(self, rel_path, amode):
        """ Check the mount users access to a single snapshot entry. """
        entry = self.get_snapshot_entry(rel_path)
        if entry is None:
            # Without the metadata of the snapshot we cannot tell which
            # permissions the entry had at backup time. The permissions on
            # disk are the ones of the last backup, so trusting them would
            # hand out access the user never had.
            return False
        return posix_acl.check_access(mode=entry['mode'],
                                    uid=entry['uid'],
                                    gid=entry['gid'],
                                    acl=entry['acl_parsed'],
                                    user_uid=self.mount_uid,
                                    user_gids=self.mount_gids,
                                    amode=amode,
                                    is_dir=entry['is_dir'])

    def check_snapshot_access(self, tree_path, amode):
        """ Check if the mount user may access a path in the current snapshot.

        The directories below tree/ are shared by all snapshots and therefore
        carry the permissions/ACLs of the *last* backup. A user who got access
        to a directory after a snapshot was taken would else be able to read
        the files that snapshot holds below it. So we read the permissions/ACLs
        the snapshot recorded and evaluate them ourselves: every parent
        directory needs search permission and the entry itself the access the
        caller asked for.

        This check only ever denies. We still drop privileges to the mount
        user, so the kernel keeps enforcing the permissions the directories in
        tree/ carry on top of it. That means the other way round stays closed
        as well: a user who lost his permissions on a directory does not get
        to the data of the older snapshots either. That is on purpose -- we do
        not want to be the only thing standing between a user and the data.

        Raises PermissionError on denied access.
        """
        self.snapshot_rel_path = None
        if not self.snapshot or not self.backup_handler:
            return
        if self.mount_uid is None:
            return
        rel_path = self.get_tree_rel_path(tree_path)
        if rel_path is None:
            return
        self.snapshot_rel_path = rel_path
        for x_parent in self.get_parent_rel_paths(rel_path):
            if self.check_entry_access(x_parent, os.X_OK):
                continue
            log_msg = _("Access denied by snapshot permissions: {snapshot}: {rel_path}", log=True)[1]
            log_msg = log_msg.format(snapshot=self.snapshot, rel_path=x_parent)
            self.logger.debug(log_msg)
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))
        if amode == os.F_OK:
            return
        if self.check_entry_access(rel_path, amode):
            return
        log_msg = _("Access denied by snapshot permissions: {snapshot}: {rel_path}", log=True)[1]
        log_msg = log_msg.format(snapshot=self.snapshot, rel_path=rel_path)
        self.logger.debug(log_msg)
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))

    def get_parent_rel_paths(self, rel_path):
        """ Get all parent directories of the given rel path. """
        if rel_path == ".":
            return []
        parents = ["."]
        path_parts = rel_path.split("/")
        for x in range(1, len(path_parts)):
            parents.append("/".join(path_parts[:x]))
        return parents

    def get_request_entry(self):
        """ Get the snapshot entry the current request is about.

        check_snapshot_access() left us the path within the snapshot, which is
        the unmangled one: for a file the path the handler works on carries
        the snapshot suffix and would not resolve.
        """
        if not self.snapshot or not self.backup_handler:
            return None
        if self.snapshot_rel_path is None:
            return None
        return self.get_snapshot_entry(self.snapshot_rel_path)

    def get_acl_xattr(self, name):
        """ Get an ACL extended attribute of the current request.

        The index holds both ACLs as text, so we let the kernel turn the text
        back into the attribute a client expects, see posix_acl.
        """
        entry = self.get_request_entry()
        if entry is None:
            return None
        default = (name == "system.posix_acl_default")
        if default:
            acl_text = entry['default_acl']
        else:
            acl_text = entry['acl']
        if not acl_text:
            return None
        return posix_acl.acl_text_to_xattr(acl_text, default=default)

    def fix_dir_attrs(self, tree_path, result):
        """ Replace a directories metadata with the one of the snapshot. """
        if not self.snapshot or not self.backup_handler:
            return
        rel_path = self.get_tree_rel_path(tree_path)
        if rel_path is None:
            return
        entry = self.get_snapshot_entry(rel_path)
        if entry is None:
            return
        result['st_mode'] = stat.S_IFDIR | stat.S_IMODE(entry['mode'])
        result['st_uid'] = entry['uid']
        result['st_gid'] = entry['gid']
        # getattr() returns nanoseconds (the '_ns' suffix is stripped from the
        # key), the entry holds seconds.
        result['st_mtime'] = int(entry['mtime'] * 1000000000)

    @fix_snapshot_path()
    def getattr(self, path: str, fh: Optional[int] = None) -> dict[str, Any]:
        global getattr_cache
        # The directories in tree/ are shared by all snapshots but we report
        # the metadata of the snapshot the client is browsing, so the snapshot
        # has to be part of the cache key.
        cache_key = f"{self.snapshot}:{path}"
        try:
            result = getattr_cache[cache_key]
        except KeyError:
            pass
        else:
            return result
        result = super().getattr(path, fh)
        mode = result.get("st_mode", 0)
        # Directories are real dirs in tree/, but they carry the metadata of
        # the last backup -> report the one of this snapshot.
        if stat.S_ISDIR(mode):
            self.fix_dir_attrs(path, result)
            getattr_cache[cache_key] = result
            return result
        # For regular files the data/ entry is a small text file whose first
        # line contains the original size and mtime: "<size> <mtime>\n".
        # Replace st_size and st_blocks with the real values.
        if stat.S_ISREG(mode):
            try:
                file_path = self.get_full_file_path(path)
                # Follow links to get the actual file's size.
                file_path, symlink = self._resolve_link(file_path)
                if symlink:
                    result["st_size"] = 0
                    result["st_blocks"] = 0
                    result["st_blksize"] = 4194304
                else:
                    # A HARDLINK entry's dest is built from attacker-controlled
                    # file content (link_target is not validated on write), so
                    # _resolve_link can hand back an unbounded path. Confine it
                    # to the repo root before opening, mirroring
                    # read_restore_file. On escape we raise ENOENT (caught
                    # below) so the size stays unmodified instead of turning
                    # this into an out-of-repo size/existence oracle.
                    root_real = os.path.realpath(self.root)
                    resolved_real = os.path.realpath(file_path)
                    if os.path.commonpath([root_real, resolved_real]) != root_real:
                        raise OSError(errno.ENOENT,
                                      os.strerror(errno.ENOENT))
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
        # Update cache.
        getattr_cache[cache_key] = result
        return result

    def mkdir(self, path: str, mode: int) -> int:
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path(amode=os.R_OK|os.X_OK)
    def readdir(self, path: str) -> list:
        global readdir_cache
        if self.snapshot:
            cache_key = f"{self.snapshot}:{path}"
            try:
                result = readdir_cache[cache_key]
            except KeyError:
                pass
            else:
                return result
        if self.snapshot:
            # tree/ holds the entries of all snapshots side by side. Let the
            # FS layer skip the files of the other snapshots right away, so it
            # does not stat() them and does not build getattr/getxattr cache
            # entries we would drop below anyway. Directories are not snapshot
            # suffixed and are returned regardless of the glob.
            # The snapshot name comes from the client supplied path, so escape
            # any glob metacharacters in it.
            snapshot = glob.escape(self.snapshot)
            file_glob = [
                        f"*-{snapshot}",
                        f"*-{snapshot}.longname",
                        ]
        else:
            file_glob = None
        result = super().readdir(path, permanent_cache=True, glob=file_glob)
        if not self.snapshot:
            if path.rstrip("/").endswith("/snapshots"):
                self.drop_incomplete_snapshots(result)
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
                # Shared tree/ dirs leak across snapshots -> only list the
                # ones that actually belong to this snapshot.
                if x == "." or x == ".." or self._dir_in_snapshot(path + "/" + x):
                    readdir_result.append(x)
                continue
            # resolve_longname() does check the snapshot: it strips the
            # ".longname" suffix and requires the remainder to end with our
            # snapshot. On mismatch we land in the except below, and since x
            # then still ends with ".longname" (never with our snapshot) the
            # entry is skipped.
            try:
                x, entry = self.resolve_longname(path, x)
                longname = True
            except Exception:
                longname = False
            if not longname:
                # The entry name of a non-longname entry is the tree file name,
                # so we have to strip the snapshot suffix. For a longname entry
                # resolve_longname() took the name from the entry file's first
                # line (the original rel path), which never carries a suffix.
                if not x.endswith(self.snapshot):
                    continue
                entry = re.sub(f'(.*)-{self.snapshot}$', r'\1', x)
            readdir_result.append(entry)
        result['readdir'] = readdir_result
        for x_path in dict(result['getattr']):
            x_data = result['getattr'].pop(x_path)
            x_mode = x_data['result'].get("st_mode", 0)
            if stat.S_ISDIR(x_mode):
                # Drop dirs that are not part of this snapshot (keep the
                # getattr map consistent with the filtered readdir list).
                if not self._dir_in_snapshot(x_path):
                    continue
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
                # load_longname() returns the entries complete rel path. We
                # replace the last component only, so we need the basename.
                # Using the rel path here would add all parent directories a
                # second time.
                longname = self.load_longname(longname)
                x_path = x_path.split("/")
                x_path[-1] = os.path.basename(longname)
            else:
                x_path = x_path.split("/")
            x_path.pop(1)
            x_path.insert(1, self.snapshot)
            x_path = "/".join(x_path)
            if not longname:
                # Only a non-longname name comes from the tree file name and
                # thus carries the snapshot suffix. A longname name was taken
                # from the entry file's first line (the original rel path):
                # stripping there would mangle files that are themselves named
                # like "<something>-<snapshot>".
                x_path = re.sub(f'(.*)-{self.snapshot}$', r'\1', x_path)
            result['getattr'][x_path] = x_data
        for x_path in dict(result['getxattr']):
            x_data = result['getxattr'].pop(x_path)
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
                x_path[-1] = os.path.basename(longname)
            else:
                x_path = x_path.split("/")
            x_path.pop(1)
            x_path.insert(1, self.snapshot)
            x_path = "/".join(x_path)
            if not longname:
                # See the getattr loop above: the snapshot suffix only exists
                # in the tree file name, not in a resolved longname.
                x_path = re.sub(f'(.*)-{self.snapshot}$', r'\1', x_path)
            result['getxattr'][x_path] = x_data
        # Update cache.
        if self.snapshot:
            readdir_cache[cache_key] = result
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

    @fix_snapshot_path(amode=os.R_OK)
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
        # The entries in tree/ carry the permissions/ACLs of the last backup,
        # so os.access() would answer for the wrong snapshot.
        if self.snapshot_rel_path is not None:
            if not self.check_entry_access(self.snapshot_rel_path, amode):
                raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))
            return 0
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
        if name in ACL_XATTRS and self.snapshot_rel_path is not None:
            # The entries on disk carry the ACL of the last backup (shared
            # directories) or none at all -> serve the one of this snapshot.
            acl_xattr = self.get_acl_xattr(name)
            if acl_xattr is None:
                raise OSError(errno.ENODATA, "No such attribute")
            return acl_xattr
        return super().getxattr(path, name, position)

    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def listxattr(self, path: str) -> list:
        """List all extended attributes"""
        result = super().listxattr(path)
        entry = self.get_request_entry()
        if entry is None:
            return result
        # Keep the list consistent with getxattr(): the ACLs are the ones of
        # this snapshot, everything else comes from the entry on disk.
        attrs = []
        for x_attr in result:
            if x_attr in ACL_XATTRS:
                continue
            attrs.append(x_attr)
        if entry['acl']:
            attrs.append("system.posix_acl_access")
        if entry['default_acl']:
            attrs.append("system.posix_acl_default")
        return attrs

    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes"""
        raise PermissionError(errno.EROFS, "Permission denied")

    @fix_snapshot_path()
    def statfs(self, path: str) -> dict[str, int]:
        return super().statfs(path)
