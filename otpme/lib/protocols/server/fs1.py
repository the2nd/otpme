# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import grp
import time
import errno
import xattr
import struct
import orjson
import setproctitle
from typing import Any
from typing import Optional

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import multiprocessing
from otpme.lib.fuse import init_cryptfs
from otpme.lib.fuse import read_cryptfs_settings

from otpme.lib.fscoding import decode_packet
from otpme.lib.protocols import status_codes
from otpme.lib.multiprocessing import drop_privileges
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

filehandlers = {}
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-fs-1.0"

def register():
    config.register_otpme_protocol("fsd", PROTOCOL_VERSION, server=True)

def with_root_path(func):
    def wrapper(self, path, *args, **kwargs):
        path = self.root + path
        # Get absolut path to prevent break out of root dir.
        path = os.path.abspath(path)
        if not path.startswith(self.root):
            raise OSError(errno.ENOENT, "No such file or directory")
        return func(self, path, *args, **kwargs)
    return wrapper

def static_with_root_path(func):
    def wrapper(self, path, *args, **kwargs):
        return func(self.root + path, *args, **kwargs)
    return wrapper

class OTPmeFsP1(OTPmeServer1):
    """ Class that implements OTPme-fs-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "fsd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Authd does not require any authentication on client connect.
        self.require_auth = "user"
        self.require_preauth = True
        # Instructs parent class to require a client certificate.
        self.require_client_cert = True
        # Auth request are allowed to any node.
        self.require_master_node = False
        # We need a clean cluster status.
        self.require_cluster_status = True
        # Allow reuse of SOTPs.
        self.allow_sotp_reuse = True
        # Will hold share name.
        self.share = None
        # Will hold share root.
        self.root = None
        # Share is readonly.
        self.read_only = False
        # Share is encrypted.
        self.encrypted = False
        # Encrypted share blocksize.
        self.block_size = 4096
        # Get logger.(banner=log_banner,
        self.logger = config.logger
        # Dont compress filesystem data.
        self.compresss_response = False
        # Indicates we already dropped privileges.
        self.privileges_dropped = False
        # Create mode for new files.
        self.create_mode = None
        # Create mode for new directories.
        self.directory_mode = None
        # Force group ownership to given group.
        self.force_group_gid = None
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def set_proctitle(self, username, share):
        """ Set proctitle to contain sharename. """
        if config.use_api:
            return
        new_proctitle = ("%s User: %s Share: %s"
                    % (self.proctitle, username, share))
        setproctitle.setproctitle(new_proctitle)

    @with_root_path
    def chmod(self, path: str, mode: int) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if os.path.islink(path):
            path = os.path.realpath(path)
            if not os.path.exists(path):
                return 0
        if self.create_mode:
            if os.path.isfile(path):
                raise PermissionError(errno.EACCES, "Permission denied")
        if self.directory_mode:
            if os.path.isdir(path):
                raise PermissionError(errno.EACCES, "Permission denied")
        return os.chmod(path, mode)

    @with_root_path
    def chown(self, path: str, uid: int, gid: int) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if self.force_group_gid:
            if gid != -1:
                raise PermissionError(errno.EACCES, "Permission denied")
        if os.path.islink(path):
            path = os.path.realpath(path)
            if not os.path.exists(path):
                return 0
        return os.chown(path, uid, gid)

    @with_root_path
    def create(self, path: str, mode, fi=None) -> int:
        global filehandlers
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if self.create_mode:
            mode = self.create_mode
        fh = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            fhs = filehandlers[path]
        except KeyError:
            fhs = {}
            filehandlers[path] = fhs
        fhs['write'] = fh
        if self.force_group_gid:
            os.chown(path, -1, self.force_group_gid)
        return 0

    @with_root_path
    def getattr(self, path: str, fh: Optional[int] = None) -> dict[str, Any]:
        st = os.lstat(path)
        return {
            key.removesuffix('_ns'): getattr(st, key)
            for key in (
                'st_atime_ns',
                'st_ctime_ns',
                'st_gid',
                'st_mode',
                'st_mtime_ns',
                'st_nlink',
                'st_size',
                'st_uid',
                'st_blksize',
                'st_blocks',
                'st_atime_ns',
                'st_ctime_ns',
                'st_mtime_ns',
            )
        }

    @with_root_path
    def mkdir(self, path: str, mode: int) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if self.directory_mode:
            mode = self.directory_mode
        mkdir_result = os.mkdir(path, mode)
        if self.force_group_gid:
            os.chown(path, -1, self.force_group_gid)
        return mkdir_result

    @with_root_path
    def readdir(self, path: str) -> list:
        result = ['.', '..', *os.listdir(path)]
        return result

    @with_root_path
    def readlink(self, path: str) -> str:
        return os.readlink(path)

    @with_root_path
    def rename(self, old: str, new: str):
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.rename(old, self.root + new)

    @with_root_path
    def rmdir(self, path: str) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.rmdir(path)

    @with_root_path
    def symlink(self, target: str, source: str):
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.symlink(source, target)

    @with_root_path
    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        with open(path, 'rb+') as f:
            f.truncate(length)
        return 0

    @with_root_path
    def unlink(self, path: str) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.unlink(path)

    @with_root_path
    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        if os.path.islink(path):
            path = os.path.realpath(path)
            if not os.path.exists(path):
                return 0
        now = time.time_ns()
        os.utime(path, ns=times or (now, now))
        return 0

    @with_root_path
    def open(self, path: str, flags) -> int:
        global filehandlers
        if flags & os.O_WRONLY:
            flag_type = "write"
        elif flags & os.O_RDWR:
            flag_type = "write"
        elif flags & os.O_APPEND:
            flag_type = "write"
        else:
            flag_type = "read"
        try:
            fhs = filehandlers[path]
        except KeyError:
            fhs = {}
            filehandlers[path] = fhs
        try:
            fh = fhs[flag_type]
        except KeyError:
            fh = os.open(path, flags)
            fhs[flag_type] = fh
        return 0

    @with_root_path
    def read(self, path: str, size: int, offset: int) -> bytes:
        global filehandlers
        try:
            fhs = filehandlers[path]
        except KeyError:
            fhs = {}
            filehandlers[path] = fhs
        try:
            fh = fhs['read']
        except KeyError:
            fh = os.open(path, os.O_RDONLY)
            fhs['read'] = fh
        os.lseek(fh, offset, os.SEEK_SET)
        data = os.read(fh, size)
        #os.close(fh)
        return data

    @with_root_path
    def write(self, path: str, data, offset: int) -> int:
        global filehandlers
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        try:
            fhs = filehandlers[path]
        except KeyError:
            fhs = {}
            filehandlers[path] = fhs
        try:
            fh = fhs['write']
        except KeyError:
            fh = os.open(path, os.O_RDWR)
            fhs['write'] = fh
        os.lseek(fh, offset, os.SEEK_SET)
        write_status = os.write(fh, data)
        #os.fsync(fh)
        return write_status

    @with_root_path
    def release(self, path: str) -> int:
        global filehandlers
        try:
            fhs = filehandlers.pop(path)
        except KeyError:
            return 0
        try:
            read_fh = fhs['read']
        except KeyError:
            read_fh = None
        if read_fh:
            os.close(read_fh)
        try:
            write_fh = fhs['write']
        except KeyError:
            write_fh = None
        if write_fh:
            os.close(write_fh)
        return 0

    @with_root_path
    def access(self, path: str, amode: int) -> int:
        if not os.access(path, amode):
            raise PermissionError(errno.EACCES, "Permission denied")
        return 0

    @with_root_path
    def link(self, target: str, source: str):
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.link(self.root + source, target)

    @with_root_path
    def exists(self, path: str) -> int:
        return os.path.exists(path)

    @with_root_path
    def get_mtime(self, path: str) -> int:
        return os.path.getmtime(path)

    @with_root_path
    def get_ctime(self, path: str) -> int:
        return os.path.getctime(path)

    @with_root_path
    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs)"""
        try:
            return xattr.getxattr(path, name)
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise OSError(errno.ENODATA, "No such attribute")
            if e.errno == errno.ENODATA:
                raise OSError(errno.ENODATA, "No such attribute")
            raise

    @with_root_path
    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        try:
            flags = 0
            if options & 0x1:  # XATTR_CREATE
                flags |= xattr.XATTR_CREATE
            if options & 0x2:  # XATTR_REPLACE
                flags |= xattr.XATTR_REPLACE
            xattr.setxattr(path, name, value, flags)
            return 0
        except OSError as e:
            raise

    @with_root_path
    def listxattr(self, path: str) -> list:
        """List all extended attributes"""
        try:
            return list(xattr.listxattr(path))
        except OSError as e:
            if e.errno == errno.ENOTSUP:
                return []
            raise

    @with_root_path
    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes"""
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        try:
            xattr.removexattr(path, name)
            return 0
        except OSError as e:
            if e.errno == errno.ENODATA:
                raise OSError(errno.ENODATA, "No such attribute")
            raise

    @with_root_path
    def statfs(self, path: str) -> dict[str, int]:
        stv = os.statvfs(path)
        return {
            key: getattr(stv, key)
            for key in (
                'f_bavail',
                'f_bfree',
                'f_blocks',
                'f_bsize',
                'f_favail',
                'f_ffree',
                'f_files',
                'f_flag',
                'f_frsize',
                'f_namemax',
            )
        }

    def _process(self, command, command_args, binary_data):
        """ Handle fuse requests. """
        # All valid commands.
        valid_commands = [
                            "mount",
                            "add_share_key",
                            "exists",
                            "get_mtime",
                            "get_ctime",
                            'access',
                            'create',
                            'getattr',
                            'link',
                            'read',
                            'readdir',
                            'readlink',
                            'chmod',
                            'chown',
                            'rename',
                            'statfs',
                            'symlink',
                            'link',
                            'truncate',
                            'utimens',
                            'unlink',
                            'write',
                            'mkdir',
                            'rmdir',
                            'open',
                            'release',
                            'getxattr',
                            'setxattr',
                            'listxattr',
                            'removexattr',
                        ]

        # Check if we got a valid command.
        if not command in valid_commands:
            message = "Unknown command: %s" % command
            status = False
            return self.build_response(status, message)

        if config.use_api:
            if config.auth_token:
                self.username = config.auth_token.owner
                self.authenticated = True

        if not self.authenticated:
            message = "Please authenticate."
            status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        status = True
        if command == "mount":
            if self.root:
                status = False
                message = "Share already mounted: %s" % self.share
                return self.build_response(status, message)
            try:
                self.share = command_args['share']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = "Missing share."
                return self.build_response(status, message)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=self.share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                status = status_codes.UNKNOWN_OBJECT
                message = "Unknown share: %s" % self.share
                return self.build_response(status, message)
            share = result[0]
            if not os.path.exists(share.root_dir):
                status = status_codes.UNKNOWN_OBJECT
                message = ("Unknown share root dir: %s: %s"
                        % (self.share, share.root_dir))
                return self.build_response(status, message)
            if not share.is_assigned_token(token_uuid=config.auth_token.uuid) \
            and not share.is_master_password_token(config.auth_token.rel_path):
                status = status_codes.PERMISSION_DENIED
                message = "No share permissions: %s" % self.share
                self.logger.warning(message)
                return self.build_response(status, message)
            try:
                self.root = os.path.realpath(share.root_dir)
            except Exception as e:
                message = "Failed to mount share: %s" % share
                status = status_codes.UNKNOWN_OBJECT
                msg = "%s: %s" % (message, e)
                self.logger.warning(msg)
                return self.build_response(status, message)
            if share.force_group_uuid is not None:
                group = backend.get_object(uuid=share.force_group_uuid)
                if not group:
                    status = status_codes.UNKNOWN_OBJECT
                    message = "Unknown force group: %s" % share.force_group_uuid
                    return self.build_response(status, message)
                try:
                    self.force_group_gid = grp.getgrnam(group.name).gr_gid
                except:
                    status = status_codes.UNKNOWN_OBJECT
                    message = "Force group does not exists: %s" % group.name
                    return self.build_response(status, message)
            # Get read-only attribute.
            self.read_only = share.read_only
            if share.directory_mode != "0o000":
                os.umask(0)
                self.directory_mode = int(share.directory_mode, 0)
            if share.create_mode != "0o000":
                os.umask(0)
                self.create_mode = int(share.create_mode, 0)
            self.encrypted = share.encrypted
            if self.encrypted:
                self.block_size = share.block_size
                hash_params = share.master_password_hash_params.copy()
                try:
                    init_cryptfs(path=self.root,
                                block_size=self.block_size,
                                hash_params=hash_params)
                except AlreadyInitialized:
                    pass
                except Exception as e:
                    message = "Failed to initialize cryptfs: %s" % share.name
                    status = status_codes.UNKNOWN_OBJECT
                    msg = "%s: %s" % (message, e)
                    self.logger.warning(msg)
                    return self.build_response(status, message)
                try:
                    fs_data = read_cryptfs_settings(path=self.root)
                except NotInitialized:
                    message = "Cryptfs not initialized: %s" % self.root
                    status = status_codes.UNKNOWN_OBJECT
                    self.logger.warning(message)
                    return self.build_response(status, message)
                except Exception as e:
                    message = "Failed to read cryptfs settings: %s" % share.name
                    status = status_codes.UNKNOWN_OBJECT
                    msg = "%s: %s" % (message, e)
                    self.logger.warning(msg)
                    return self.build_response(status, message)
                try:
                    self.block_size = fs_data['block_size']
                except KeyError:
                    message = "Cryptfs misses block size: %s" % share.name
                    status = status_codes.UNKNOWN_OBJECT
                    self.logger.warning(message)
                    return self.build_response(status, message)
                share_key = None
                master_password_hash_params = None
                try:
                    master_password_mount = command_args['master_password_mount']
                except KeyError:
                    master_password_mount = False
                if master_password_mount:
                    if not share.is_master_password_token(config.auth_token.rel_path):
                        status = status_codes.PERMISSION_DENIED
                        message = ("Master password mount not allowed: %s"
                                    % config.auth_token.rel_path)
                        self.logger.warning(message)
                        return self.build_response(status, message)
                    try:
                        master_password_hash_params = fs_data['hash_params']
                    except KeyError:
                        message = "Cryptfs misses master password hash parameters: %s" % share.name
                        status = status_codes.UNKNOWN_OBJECT
                        self.logger.warning(message)
                        return self.build_response(status, message)
                else:
                    share_key = share.get_share_key(username=config.auth_user.name,
                                                    verify_acls=False)
                    if not share_key:
                        status = status_codes.PERMISSION_DENIED
                        message = ("No share key for user: %s"
                                    % config.auth_user.name)
                        self.logger.warning(message)
                        return self.build_response(status, message)

            # Get share node FQDNs to reply.
            share_nodes = share.get_nodes(include_pools=True,
                                        return_type="instance")
            mount_result = {}
            share_node_fqdns = []
            for node in share_nodes:
                share_node_fqdns.append(node.fqdn)
            if not self.privileges_dropped:
                default_group = stuff.get_users_default_group(self.username)
                groups = stuff.get_users_groups(self.username)
                if share.force_group_uuid is not None:
                    if group.name not in groups:
                        status = status_codes.PERMISSION_DENIED
                        message = ("Force group enabled and user not in group: %s"
                                    % group.name)
                        self.logger.warning(message)
                        return self.build_response(status, message)
                try:
                    drop_privileges(user=self.username, group=default_group, groups=groups)
                except Exception as e:
                    status = status_codes.PERMISSION_DENIED
                    message = "Failed to drop privileges: %s" % e
                    self.logger.warning(message)
                    return self.build_response(status, message)
                self.privileges_dropped = True
            self.set_proctitle(self.username, share)
            mount_result = {'nodes':share_node_fqdns}
            if self.encrypted:
                mount_result['share_key'] = share_key
                mount_result['block_size'] = self.block_size
                mount_result['master_password_hash_params'] = master_password_hash_params
            message = mount_result
            return self.build_response(status, message)
        else:
            if not self.root:
                message = "No share mounted."
                status = status_codes.UNKNOWN_OBJECT
                return self.build_response(status, message)

        if command == "add_share_key":
            try:
                share_key = command_args['share_key']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = "Missing share key."
                return self.build_response(status, message)
            if not self.root:
                message = "No share mounted."
                status = status_codes.UNKNOWN_OBJECT
                return self.build_response(status, message)
            if not self.encrypted:
                status = status_codes.UNKNOWN_OBJECT
                message = "Share not encrypted."
                return self.build_response(status, message)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=self.share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                status = status_codes.UNKNOWN_OBJECT
                message = "Unknown share: %s" % self.share
                return self.build_response(status, message)
            share = result[0]
            if not share.is_master_password_token(config.auth_token.rel_path):
                status = status_codes.PERMISSION_DENIED
                message = "No share permissions: %s" % self.share
                self.logger.warning(message)
                return self.build_response(status, message)
            if not share_key:
                status = status_codes.UNKNOWN_OBJECT
                message = ("Got no share key: %s" % config.auth_user.name)
                self.logger.warning(message)
                return self.build_response(status, message)
            share.add_token(token_path=config.auth_token.rel_path,
                            share_key=share_key,
                            callback=default_callback,
                            verify_acls=False)
            default_callback.write_modified_objects()
            message = "Share key added for user: %s" % config.auth_user.name
            status = True

        elif command == "exists":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.exists(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "get_mtime":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.get_mtime(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "get_ctime":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.get_ctime(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "access":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                amode = command_args['amode']
            except KeyError:
                status = False
                message = "Missing amode."
                return self.build_response(status, message)
            try:
                message = self.access(path, amode)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "create":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                status = False
                message = "Missing mode."
                return self.build_response(status, message)
            try:
                message = self.create(path, mode)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "getattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.getattr(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "link":
            try:
                source = command_args['source']
            except KeyError:
                status = False
                message = "Missing source."
                return self.build_response(status, message)
            try:
                target = command_args['target']
            except KeyError:
                status = False
                message = "Missing target."
                return self.build_response(status, message)
            try:
                message = self.link(target, source)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "read":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                size = command_args['size']
            except KeyError:
                status = False
                message = "Missing size."
                return self.build_response(status, message)
            try:
                offset = command_args['offset']
            except KeyError:
                status = False
                message = "Missing offset."
                return self.build_response(status, message)
            try:
                binary_data = self.read(path, size, offset)
            except Exception as e:
                status = e.errno
                message = str(e)
            else:
                message = "File data."
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "readdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.readdir(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "readlink":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.readlink(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "rename":
            try:
                old = command_args['old']
            except KeyError:
                status = False
                message = "Missing old."
                return self.build_response(status, message)
            try:
                new = command_args['new']
            except KeyError:
                status = False
                message = "Missing new."
                return self.build_response(status, message)
            try:
                message = self.rename(old, new)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "statfs":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.statfs(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "symlink":
            try:
                source = command_args['source']
            except KeyError:
                status = False
                message = "Missing source."
                return self.build_response(status, message)
            try:
                target = command_args['target']
            except KeyError:
                status = False
                message = "Missing target."
                return self.build_response(status, message)
            try:
                message = self.symlink(target, source)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "link":
            try:
                source = command_args['source']
            except KeyError:
                status = False
                message = "Missing source."
                return self.build_response(status, message)
            try:
                target = command_args['target']
            except KeyError:
                status = False
                message = "Missing target."
                return self.build_response(status, message)
            try:
                message = self.link(target, source)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "truncate":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                length = command_args['length']
            except KeyError:
                status = False
                message = "Missing length."
                return self.build_response(status, message)
            try:
                message = self.truncate(path, length)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "utimens":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                times = command_args['times']
            except KeyError:
                status = False
                message = "Missing times."
                return self.build_response(status, message)
            try:
                message = self.utimens(path, times)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "unlink":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.unlink(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "mkdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                status = False
                message = "Missing mode."
                return self.build_response(status, message)
            try:
                message = self.mkdir(path, mode)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "rmdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.rmdir(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "chmod":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                status = False
                message = "Missing mode."
                return self.build_response(status, message)
            try:
                message = self.chmod(path, mode)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "chown":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                uid = command_args['uid']
            except KeyError:
                status = False
                message = "Missing uid."
                return self.build_response(status, message)
            try:
                gid = command_args['gid']
            except KeyError:
                status = False
                message = "Missing gid."
                return self.build_response(status, message)
            try:
                message = self.chown(path, uid, gid)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "write":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                offset = command_args['offset']
            except KeyError:
                status = False
                message = "Missing offset."
                return self.build_response(status, message)
            try:
                message = self.write(path, binary_data, offset)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "open":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                flags = command_args['flags']
            except KeyError:
                status = False
                message = "Missing flags."
                return self.build_response(status, message)
            try:
                message = self.open(path, flags)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "release":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.release(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "getxattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = "Missing name."
                return self.build_response(status, message)
            position = command_args.get('position', 0)
            try:
                binary_data = self.getxattr(path, name, position)
                message = "Extended attribute data."
            except Exception as e:
                status = e.errno
                message = str(e)
                binary_data = None
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "setxattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = "Missing name."
                return self.build_response(status, message)
            try:
                value = command_args['value']
            except KeyError:
                status = False
                message = "Missing value."
                return self.build_response(status, message)
            try:
                options = command_args['options']
            except KeyError:
                status = False
                message = "Missing options."
                return self.build_response(status, message)
            position = command_args.get('position', 0)
            try:
                message = self.setxattr(path, name, value, options, position)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "listxattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                message = self.listxattr(path)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        elif command == "removexattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = "Missing path."
                return self.build_response(status, message)
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = "Missing name."
                return self.build_response(status, message)
            try:
                message = self.removexattr(path, name)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        else:
            status = False
            message = "Unknown fs command: %s" % command
            return self.build_response(status, message)

    def build_response(self, status, message, binary_data=None, **kwargs):
        """ Build response using msgpack. """
        # Convert status to integer status code
        if status is True:
            status_code = status_codes.OK
        elif status is None:
            status_code = status_codes.ABORT
        elif status is False:
            status_code = status_codes.ERR
        else:
            status_code = int(status)

        # Create response structure - orjson handles all JSON-compatible types
        response_data = {
            'status_code': status_code,
            'data': message
        }

        # Pack response with orjson (extremely fast JSON serialization)
        packed_data = orjson.dumps(response_data)

        if binary_data is None:
            binary_data = b''

        # Simple binary header (8 bytes total):
        # - packed_data_length: 4 bytes (>I)
        # - binary_length: 4 bytes (>I)
        header_bytes = struct.pack('>II', len(packed_data), len(binary_data))

        response = header_bytes + packed_data + binary_data

        if config.use_api:
            self.last_response = response

        return response

    def decode_request(self, request, **kwargs):
        """ Decode OTPme request using msgpack. """
        # Parse simple binary header (8 bytes total):
        # - packed_data_length: 4 bytes (>I)
        # - binary_length: 4 bytes (>I)
        packed_data_length, binary_length = struct.unpack('>II', request[:8])

        # Extract data sections
        packed_start = 8
        packed_end = packed_start + packed_data_length
        binary_start = packed_end
        binary_end = binary_start + binary_length

        # Extract packed data and binary data
        packed_data = request[packed_start:packed_end]
        binary_data = request[binary_start:binary_end]

        try:
            command, command_args = decode_packet(data=packed_data)
        except (TypeError,ValueError) as e:
            # Unpack request with orjson
            try:
                request_data = orjson.loads(packed_data)
            except Exception as e:
                msg = "Failed to decode orjson request: %s" % e
                raise OTPmeException(msg)
            # Get command and args.
            try:
                command = request_data['command']
            except:
                msg = "Received invalid request: Command is missing"
                raise OTPmeException(msg)
            try:
                command_args = request_data['command_args']
            except:
                msg = "Received invalid request: Command args missing"
                raise OTPmeException(msg)
        return command, command_args, binary_data

    def _close(self):
        pass
