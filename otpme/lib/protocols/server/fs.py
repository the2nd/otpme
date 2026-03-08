# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import errno
import xattr
import struct
import orjson
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

from otpme.lib.fscoding import decode_packet
from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

filehandlers = {}

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-backup-1.0"

def with_root_path(allow_symlinks=False):
    def wrapper(f):
        @wraps(f)
        def wrapped(self, path, *args, **kwargs):
            path = self.root + path
            # Get absolut path to prevent break out of root dir.
            path = os.path.abspath(path)
            if not path.startswith(self.root):
                raise OSError(errno.ENOENT, "No such file or directory")
            if not allow_symlinks:
                path = os.path.realpath(path)
                if not path.startswith(self.root):
                    raise OSError(errno.ENOENT, "No such file or directory")
            return f(self, path, *args, **kwargs)
        return wrapped
    return wrapper

class OTPmeFsServer1(OTPmeServer1):
    """ Class that implements fileserver. """
    def __init__(self, **kwargs):
        # Root dir.
        self.root = None
        # Share is readonly.
        self.read_only = False
        # Get logger.
        self.logger = config.logger
        # Create mode for new files.
        self.create_mode = None
        # Create mode for new directories.
        self.directory_mode = None
        # Force group ownership to given group.
        self.force_group_gid = None
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    @with_root_path()
    def chmod(self, path: str, mode: int) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if self.create_mode:
            if os.path.isfile(path):
                raise PermissionError(errno.EACCES, "Permission denied")
        if self.directory_mode:
            if os.path.isdir(path):
                raise PermissionError(errno.EACCES, "Permission denied")
        return os.chmod(path, mode)

    @with_root_path(allow_symlinks=True)
    def chown(self, path: str, uid: int, gid: int) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if self.force_group_gid:
            if gid != -1:
                raise PermissionError(errno.EACCES, "Permission denied")
        if os.path.islink(path):
            return os.lchown(path, uid, gid)
        return os.chown(path, uid, gid)

    @with_root_path()
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

    @with_root_path(allow_symlinks=True)
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

    @with_root_path()
    def mkdir(self, path: str, mode: int) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        if self.directory_mode:
            mode = self.directory_mode
        mkdir_result = os.mkdir(path, mode)
        if self.force_group_gid:
            os.chown(path, -1, self.force_group_gid)
        return mkdir_result

    @with_root_path()
    def readdir(self, path: str) -> list:
        result = {'getattr':{}, 'getxattr':{}}
        entries = os.listdir(path)
        for entry in entries:
            entry_path = os.path.join(path, entry)
            entry_path = entry_path.replace(self.root, "")
            # getattr cache.
            result['getattr'][entry_path] = {}
            try:
                x_getattr = self.getattr(entry_path)
                result['getattr'][entry_path]['result'] = x_getattr
            except Exception as e:
                result['getattr'][entry_path]['exc'] = e.errno
            result['getattr'][entry_path]['cache_time'] = time.time()
            # getxattr cache.
            result['getxattr'][entry_path] = {}
            result['getxattr'][entry_path]['security.selinux'] = {}
            try:
                x_getxattr = self.getxattr(entry_path, "security.selinux")
                result['getxattr'][entry_path]['security.selinux']['result'] = x_getxattr.hex()
            except Exception as e:
                result['getxattr'][entry_path]['security.selinux']['exc'] = e.errno
            result['getxattr'][entry_path]['security.selinux']['cache_time'] = time.time()
            result['getxattr'][entry_path]['system.posix_acl_access'] = {}
            try:
                x_getxattr = self.getxattr(entry_path, "system.posix_acl_access")
                result['getxattr'][entry_path]['system.posix_acl_access']['result'] = x_getxattr.hex()
            except Exception as e:
                result['getxattr'][entry_path]['system.posix_acl_access']['exc'] = e.errno
            result['getxattr'][entry_path]['system.posix_acl_access']['cache_time'] = time.time()
        readdir = ['.', '..', *entries]
        result['readdir'] = readdir
        return result

    @with_root_path(allow_symlinks=True)
    def readlink(self, path: str) -> str:
        return os.readlink(path)

    @with_root_path(allow_symlinks=True)
    def rename(self, old: str, new: str):
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.rename(old, self.root + new)

    @with_root_path()
    def rmdir(self, path: str) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.rmdir(path)

    @with_root_path(allow_symlinks=True)
    def symlink(self, target: str, source: str):
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        result = os.symlink(source, target)
        if self.force_group_gid:
            os.lchown(target, -1, self.force_group_gid)
        return result

    @with_root_path()
    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        with open(path, 'rb+') as f:
            f.truncate(length)
        return 0

    @with_root_path(allow_symlinks=True)
    def unlink(self, path: str) -> int:
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.unlink(path)

    @with_root_path(allow_symlinks=True)
    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        now = time.time_ns()
        os.utime(path, ns=times or (now, now))
        return 0

    @with_root_path()
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

    @with_root_path()
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

    @with_root_path()
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

    @with_root_path()
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

    @with_root_path(allow_symlinks=True)
    def access(self, path: str, amode: int) -> int:
        if not os.access(path, amode):
            raise PermissionError(errno.EACCES, "Permission denied")
        return 0

    @with_root_path()
    def link(self, target: str, source: str):
        if self.read_only:
            raise PermissionError(errno.EROFS, "Permission denied")
        return os.link(self.root + source, target)

    @with_root_path(allow_symlinks=True)
    def exists(self, path: str) -> int:
        return os.path.exists(path)

    @with_root_path()
    def get_mtime(self, path: str) -> int:
        return os.path.getmtime(path)

    @with_root_path()
    def get_ctime(self, path: str) -> int:
        return os.path.getctime(path)

    @with_root_path(allow_symlinks=True)
    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs)"""
        if os.path.islink(path):
            raise OSError(errno.ENODATA, "No such attribute")
        try:
            return xattr.getxattr(path, name)
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise OSError(errno.ENODATA, "No such attribute")
            if e.errno == errno.ENODATA:
                raise OSError(errno.ENODATA, "No such attribute")
            raise

    @with_root_path()
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

    @with_root_path()
    def listxattr(self, path: str) -> list:
        """List all extended attributes"""
        try:
            return list(xattr.listxattr(path))
        except OSError as e:
            if e.errno == errno.ENOTSUP:
                return []
            raise

    @with_root_path()
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

    @with_root_path()
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

    def process_file_command(self, command, command_args, binary_data=None):
        status = True
        if command == "exists":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
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
                message = _("Missing path.")
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
                message = _("Missing path.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                amode = command_args['amode']
            except KeyError:
                status = False
                message = _("Missing amode.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                status = False
                message = _("Missing mode.")
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
                message = _("Missing path.")
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
                message = _("Missing source.")
                return self.build_response(status, message)
            try:
                target = command_args['target']
            except KeyError:
                status = False
                message = _("Missing target.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                size = command_args['size']
            except KeyError:
                status = False
                message = _("Missing size.")
                return self.build_response(status, message)
            try:
                offset = command_args['offset']
            except KeyError:
                status = False
                message = _("Missing offset.")
                return self.build_response(status, message)
            try:
                binary_data = self.read(path, size, offset)
            except Exception as e:
                status = e.errno
                message = str(e)
            else:
                message = _("File data.")
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "readdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
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
                message = _("Missing path.")
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
                message = _("Missing old.")
                return self.build_response(status, message)
            try:
                new = command_args['new']
            except KeyError:
                status = False
                message = _("Missing new.")
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
                message = _("Missing path.")
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
                message = _("Missing source.")
                return self.build_response(status, message)
            try:
                target = command_args['target']
            except KeyError:
                status = False
                message = _("Missing target.")
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
                message = _("Missing source.")
                return self.build_response(status, message)
            try:
                target = command_args['target']
            except KeyError:
                status = False
                message = _("Missing target.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                length = command_args['length']
            except KeyError:
                status = False
                message = _("Missing length.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                times = command_args['times']
            except KeyError:
                status = False
                message = _("Missing times.")
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
                message = _("Missing path.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                status = False
                message = _("Missing mode.")
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
                message = _("Missing path.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                mode = command_args['mode']
            except KeyError:
                status = False
                message = _("Missing mode.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                uid = command_args['uid']
            except KeyError:
                status = False
                message = _("Missing uid.")
                return self.build_response(status, message)
            try:
                gid = command_args['gid']
            except KeyError:
                status = False
                message = _("Missing gid.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                offset = command_args['offset']
            except KeyError:
                status = False
                message = _("Missing offset.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                flags = command_args['flags']
            except KeyError:
                status = False
                message = _("Missing flags.")
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
                message = _("Missing path.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = _("Missing name.")
                return self.build_response(status, message)
            position = command_args.get('position', 0)
            try:
                binary_data = self.getxattr(path, name, position)
                message = _("Extended attribute data.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = _("Missing name.")
                return self.build_response(status, message)
            try:
                value = command_args['value']
            except KeyError:
                status = False
                message = _("Missing value.")
                return self.build_response(status, message)
            try:
                options = command_args['options']
            except KeyError:
                status = False
                message = _("Missing options.")
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
                message = _("Missing path.")
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
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                name = command_args['name']
            except KeyError:
                status = False
                message = _("Missing name.")
                return self.build_response(status, message)
            try:
                message = self.removexattr(path, name)
            except Exception as e:
                status = e.errno
                message = str(e)
            return self.build_response(status, message)

        else:
            msg = _("Unknown fs command: {command}")
            msg = msg.format(command=command)
            raise UnknownCommand(msg)

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
                msg = _("Failed to decode orjson request: {error}")
                msg = msg.format(error=e)
                raise OTPmeException(msg)
            # Get command and args.
            try:
                command = request_data['command']
            except:
                msg = _("Received invalid request: Command is missing")
                raise OTPmeException(msg)
            try:
                command_args = request_data['command_args']
            except:
                msg = _("Received invalid request: Command args missing")
                raise OTPmeException(msg)
        return command, command_args, binary_data

    def _close(self):
        pass
