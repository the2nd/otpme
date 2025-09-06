# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pwd
import grp
import stat
import time
import fcntl
import pprint
import shutil
from pathlib import Path
from functools import wraps
from collections import OrderedDict

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.incremental_objects import incremental_update

from otpme.lib.exceptions import *

FILE_LOCK_TYPE = "file"

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

def register():
    """ Register stuff. """
    from otpme.lib.locking import register_lock_type
    register_lock_type(FILE_LOCK_TYPE, module=__file__)

def check_user(user):
    """ Check if system user exists """
    from otpme.lib import stuff
    if isinstance(user, str):
        try:
            stuff.user_exists(user)
        except Exception as e:
            raise Exception(str(e))

def check_group(group):
    """ Check if system group exists """
    from otpme.lib import stuff
    if isinstance(group, str):
        try:
            stuff.group_exists(group)
        except Exception as e:
            raise Exception(str(e))

class AtomicFile(object):
    def __init__(self, path, user=None, group=None,
        perms=0o666, mode="r+", auto_open=True,
        create_missing=False, register=None, unregister=None):
        self.path = path
        self.user = user
        self.group = group
        self.mode = mode
        self.perms = perms
        self.register_method = register
        self.unregister_method = unregister
        self.create_missing = create_missing
        if auto_open:
            self.open()

    def open(self):
        """ Open file. """
        if not self.create_missing:
            if self.mode.startswith("r"):
                if not os.path.exists(self.path):
                    msg = "No such file or directory: %s" % self.path
                    raise FileNotFoundError(msg)
        old_umask = os.umask(0o000)
        try:
            if self.register_method:
                self.register_method(self)
            if self.mode.startswith("r"):
                open_flags = os.O_CREAT | os.O_RDONLY
            if self.mode.startswith("w"):
                open_flags = os.O_CREAT | os.O_RDWR
            self._fd = os.open(self.path, open_flags, self.perms)
            self.fd = os.fdopen(self._fd, self.mode)
            if self.user:
                try:
                    set_fs_ownership(path=self.path,
                                    user=self.user,
                                    group=self.group)
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            raise
        except Exception as e:
            msg = "Failed to open file: %s: %s" % (self.path, e)
            raise OTPmeException(msg)
        finally:
            os.umask(old_umask)

    def __getattr__(self, name):
        """ Map to original attributes. """
        return getattr(self.fd, name)

    def close(self, *args, **kwargs):
        close_result = None
        if self.fd:
            close_result = self.fd.close(*args, **kwargs)
        elif self._fd:
            close_result = os.close(self._fd)
        if self.unregister_method:
            self.unregister_method(self)
        return close_result

    def unlink(self):
        """ Remove file. """
        try:
            os.remove(self.path)
        except:
            pass

class AtomicFileLock(object):
    def __init__(self, path, user=None, group=None, perms=0o666,
        mode="r+", read_lock=False, write_lock=False, auto_open=True,
        block=True, register=None, unregister=None):
        from otpme.lib import config
        self.fd = None
        self.path = path
        self.mode = mode
        self.user = user
        self.group = group
        self.perms = perms
        self.register_method = register
        self.unregister_method = unregister
        self._method_flock = None
        if read_lock:
            self.acquire_lock(block=block)
        elif write_lock:
            self.acquire_lock(exclusive=True, block=block)
        elif auto_open:
            self.ensure_fd()
        self.logger = config.logger

    def __getattr__(self, name):
        """ Map to original attributes. """
        return getattr(self.fd, name)

    def get_fd(self):
        fd = AtomicFile(path=self.path,
                        user=self.user,
                        group=self.group,
                        mode=self.mode,
                        create_missing=True,
                        register=self.register_method,
                        unregister=self.unregister_method)
        return fd

    def check_inode(self):
        """ Make sure our FD was not deleted. """
        if not self.fd:
            return False
        try:
            fd_inode = os.fstat(self.fd.fileno())[1]
        except Exception as e:
            if not self.fd.closed:
                msg = "Failed to get inode: %s: %s" % (self.fd, e)
                raise OTPmeException(msg)
            return False
        try:
            x_inode = os.stat(self.path)[1]
        except FileNotFoundError:
            return False
        if x_inode == fd_inode:
            return True
        return False

    def ensure_fd(self):
        """ Make sure FD is not outdated (e.g. deleted). """
        while not self.check_inode():
            if self.fd:
                self.fd.close()
            self.fd = self.get_fd()

    def acquire_lock(self, exclusive=False, block=True, timeout=None,
        callback=None, log_wait_message=False, wait_message=None):
        from otpme.lib import stuff
        from otpme.lib import config
        lock_status = self._acquire_lock_atomic(exclusive=exclusive, block=False)
        if lock_status:
            return lock_status
        if wait_message is not None:
            if log_wait_message:
                if config.debug_level() >= 2:
                    self.logger.debug(wait_message)
            if callback:
                callback.send(wait_message)
        if timeout is None:
            result = self._acquire_lock_atomic(exclusive=exclusive, block=block)
            return result
        def run_method():
            return self._acquire_lock_atomic(exclusive=exclusive, block=block)
        result = stuff.start_with_timeout(run_method, timeout=timeout)
        return result

    def _acquire_lock_atomic(self, exclusive=False, block=True):
        """ Do atomic lock acquiring. """
        if exclusive:
            if block:
                flags = fcntl.LOCK_EX
            else:
                flags = fcntl.LOCK_EX | fcntl.LOCK_NB
        else:
            if block:
                flags = fcntl.LOCK_SH
            else:
                flags = fcntl.LOCK_SH | fcntl.LOCK_NB
        lock_status = False
        while True:
            # Make sure we have a FD.
            self.ensure_fd()
            # Lock the FD.
            try:
                fcntl.flock(self.fd, flags)
                lock_status = True
            except BlockingIOError:
                lock_status = False
            except IOError:
                lock_status = False
            except TimeoutReached:
                msg = "Timeout waiting for lock."
                raise LockWaitTimeout(msg)
            # Make sure the locked FD was not removed.
            if self.check_inode():
                break
            self.release_lock()
        return lock_status

    def release_lock(self):
        """ Release flock. """
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        except ValueError:
            pass
        except IOError:
            pass

    def close(self, *args, **kwargs):
        if not self.fd:
            return
        return self.fd.close(*args, **kwargs)

    def unlink(self, force=False, ignore_inode=False):
        """ Remove file if its not used anymore. """
        if not force:
            # Make sure file is not used when doing unlink.
            try:
                self.acquire_lock(exclusive=True, block=False)
            except:
                return False
        # Make sure we do not deleted a recreated file.
        if not ignore_inode:
            if not self.check_inode():
                if not force:
                    self.release_lock()
                return False
        # Remove file.
        self.fd.unlink()
        return True

def copy_file(src, dst):
    """ Copy file and perserving ownership and permissions. """
    try:
        shutil.copy2(src, dst)
        st = os.stat(src)
        os.chown(dst, st[stat.ST_UID], st[stat.ST_GID])
    except Exception as e:
        msg = ("Failed to copy file: %s > %s: %s"
                % (src, dst, e))
        raise OTPmeException(msg)

def list_dir(directory, sort_by="name"):
    """ List directory index and ignore if directory does not exist. """
    _list = []
    try:
        _list = os.listdir(directory)
    except OSError as e:
        if e.errno != 2:
            raise
    # Sort functions to handle dirs/files removed while listing.
    def sort_by_ctime(x):
        try:
            ctime = os.path.getctime(os.path.join(directory, x))
        except OSError:
            ctime = 0
        return ctime
    def sort_by_mtime(x):
        try:
            mtime = os.path.getmtime(os.path.join(directory, x))
        except FileNotFoundError:
            mtime = 0
        return mtime
    if sort_by == "name":
        _list.sort()
    elif sort_by == "ctime":
        _list.sort(key=sort_by_ctime)
    elif sort_by == "mtime":
        _list.sort(key=sort_by_mtime)
    else:
        msg = "Unknown sort_by: %s" % sort_by
        raise OTPmeException(msg)
    return _list

def create_dir(path, user=None, group=True,
    mode=0o770, user_acls=[], group_acls=[]):
    """ Create a directory with sub directories if it not exists """
    if not user or not group:
        from otpme.lib import config
        user = config.user
        group = config.group

    # Make sure user/goup exists.
    check_user(user)
    check_group(group)

    if os.path.exists(path):
        return

    count = 1
    for i in path.split("/"):
        directory = "/%s" % "/".join(path.split("/")[1:count])
        if not os.path.exists(directory):
            os.mkdir(directory)
            # Set ownership.
            set_fs_ownership(path=directory,
                            user=user,
                            group=group)
            # Set permissions.
            set_fs_permissions(path=directory,
                            mode=mode,
                            user_acls=user_acls,
                            group_acls=group_acls)
        count += 1

def remove_dir(path, recursive=False,
    remove_non_empty=False, fail_on_non_empty=False):
    """ Remove given directory. """
    if recursive and remove_non_empty:
        shutil.rmtree(path)
        return
    if not recursive:
        os.rmdir(path)
        return
    x = path
    while True:
        if len(os.listdir(x)) > 0:
            if fail_on_non_empty:
                raise Exception(_("Directory not empty: %s") % x)
            break
        os.rmdir(x)
        x = "/".join(x.split("/")[:-1])

def read_file(path, read_mode="r", compression=None):
    """ Atomic file read.. """
    from otpme.lib import stuff
    # Get file real path to ensure working locking (e.g. on symlink).
    file_real_path = os.path.realpath(path)
    if not os.path.exists(file_real_path):
        msg = "No such file or directory: %s" % path
        raise FileNotFoundError(msg)
    try:
        _compression = stuff.get_compression_type(file_real_path)
    except OTPmeException:
        _compression = None
    if _compression:
        read_mode = "rb"
    # Get flock.
    fd = AtomicFileLock(path=file_real_path, mode=read_mode, read_lock=True)
    # Read file content.
    try:
        file_content = fd.read()
    finally:
        fd.release_lock()
        fd.close()
    if _compression:
        file_content = stuff.decompress(file_content, compression=_compression)
    return file_content

def create_file(path, content=None, user=None, group=True, mode=0o660,
    user_acls=[], group_acls=[], write_mode="w", compression=None, lock=True):
    """ Create file with content and sane permissions. """
    from otpme.lib import stuff
    if not user or not group:
        from otpme.lib import config
        user = config.user
        group = config.group

    if content is None:
        content = ""

    # Make sure user/goup exists.
    check_user(user)
    check_group(group)

    if compression:
        write_mode = "wb"
        content = stuff.compress(content, compression=compression)

    # Get file real path to ensure working locking (e.g. on symlink).
    file_real_path = os.path.realpath(path)

    # Open temp file.
    fd = AtomicFileLock(path=file_real_path,
                        mode=write_mode,
                        write_lock=True,
                        perms=mode)
    # Truncate file.
    fd.truncate()
    # Write data to file.
    fd.write(content)
    fd.close()
    # Set ownership.
    set_fs_ownership(path=file_real_path,
                    user=user,
                    group=group,
                    recursive=False)
    # Set permissions.
    set_fs_permissions(path=file_real_path,
                        mode=mode,
                        user_acls=user_acls,
                        group_acls=group_acls,
                        recursive=False)
    # Release flock.
    fd.release_lock()

def create_temp_file(content, tmp_dir="/tmp", user=False,
    group=True, mode=0o660, user_acls=[], group_acls=[]):
    """ Create temp file with content 'content' and sane permissions. """
    from otpme.lib import stuff
    tmp_file = "%s.tmp" % (stuff.gen_secret(len=32))
    temp_file = os.path.join(tmp_dir, tmp_file)

    create_file(path=temp_file,
                content=content,
                user=user,
                group=group,
                mode=mode,
                user_acls=user_acls,
                group_acls=group_acls)
    return temp_file

def symlink(src, dst):
    """ Create symlink. """
    try:
        os.symlink(src, dst)
    except Exception as e:
        msg = ("Failed to create symlink: %s > %s: %s"
                % (src, dst, e))
        raise OTPmeException(msg)

def touch(path, user=None, group=True, mode=0o660,
    user_acls=[], group_acls=[]):
    """ Create empty file """
    if not user or not group:
        from otpme.lib import config
        user = config.user
        group = config.group
    set_permissions = False
    if not os.path.exists(path):
        set_permissions = True
    Path(path).touch()
    if not set_permissions:
        return
    # Set ownership.
    set_fs_ownership(path=path,
                    user=user,
                    group=group,
                    recursive=False)
    # Set permissions.
    set_fs_permissions(path=path,
                    mode=mode,
                    user_acls=user_acls,
                    group_acls=group_acls,
                    recursive=False)

def delete(path):
    """ Atomic deletion. """
    if os.path.islink(path):
        try:
            os.remove(path)
        except Exception as e:
            msg = "Failed to remove symlink: %s: %s" % (path, e)
            raise OTPmeException(msg)
        return True
    # Lock file.
    fd = AtomicFileLock(path=path, mode="w", write_lock=True)
    try:
        fd.unlink()
    except Exception as e:
        msg = "Failed to delete file: %s: %s" % (path, e)
        raise OTPmeException(msg)
    return True

def set_fs_ownership(path, user, group=None, recursive=False):
    """
    Sets owner and group:
        if group is True we set gid to the primary group of user (default)
        if group is False we do not touch group ownership
        if group is set we set gid to the gid of the given group
    """
    from otpme.lib import stuff
    def get_gid(group):
        """ Get GID from group. """
        # If group is True we set gid to the primary group of user.
        # If group is False we do not touch group ownership.
        # If group is set we set gid to the gid of the given group.
        if group is True:
            gid = pwd.getpwnam(user).pw_gid
        elif not group:
            gid = -1
        else:
            gid = grp.getgrnam(group).gr_gid
        return gid

    # Make sure user/goup exists.
    check_user(user)
    check_group(group)

    # Get GID.
    gid = get_gid(group)

    # Only root can change owner.
    system_user = stuff.get_pid_user(os.getpid())
    if system_user == "root":
        change_owner = True
    else:
        file_owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
        # If the given file is not owned by the current system user we cannot
        # change ownership.
        if file_owner != system_user:
            return
        # If the current user is not member of the destination group we cannot
        # change ownership.
        if not gid in os.getgroups():
            return
        change_owner = False

    # Get UID.
    if change_owner:
        uid = pwd.getpwnam(user).pw_uid
    else:
        uid = -1

    # Just change permissions of path if not called with recursive=True.
    if not recursive:
        os.chown(path, uid, gid)
        return

    # Check if path is a directory.
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            # There is no need to differentiate between dirs and files so we
            # call it objects.
            objects = files
            # We want to catch all files and dirs recursive. So we just need to
            # add every directory root because every dir is also listed as root
            # on the next run.
            objects.insert(0, root)

            for object in objects:
                object_path = os.path.join(root, object)
                os.chown(object_path, uid, gid)
    else:
        # Set ownership of file.
        os.chown(path, uid, gid)

def set_fs_permissions(path, mode, user_acls=[], group_acls=[], recursive=False):
    """ Sets filesystem permissions """
    apply_acls = False

    if user_acls or group_acls:
        import posix1e
        apply_acls = True
        mode_map = {
                    0 : "---",
                    1 : "--x",
                    2 : "-w-",
                    3 : "-wx",
                    4 : "r--",
                    5 : "r-x",
                    6 : "rw-",
                    7 : "rwx",
                }
        owner_perms ="u::%s" % mode_map[int(str(oct(mode))[-3])]
        group_perms = "g::%s" % mode_map[int(str(oct(mode))[-2])]
        others_perms = "o::%s" % mode_map[int(str(oct(mode))[-1])]
        mask_perms = "m::rwx"

        acl_structure = [
                owner_perms,
                ",".join(user_acls),
                group_perms,
                ",".join(group_acls),
                mask_perms,
                others_perms,
                ]

        acl_text = ""
        for i in acl_structure:
            if not i:
                continue
            if not acl_text:
                acl_text = "%s%s" % (acl_text, i)
            else:
                acl_text = "%s,%s" % (acl_text, i)

        new_acl = posix1e.ACL(text=acl_text)

    # Just change permissions of path if not called with recursive=True.
    if not recursive:
        os.chmod(path, mode)
        if apply_acls:
            new_acl.applyto(path)
        return

    for root, dirs, files in os.walk(path):
        # There is no need to differentiate between dirs and files so we call it
        # objects.
        objects = files
        # We want to catch all files and dirs recursive. So we just need to add
        # every directory root because every dir is also listed as root on the
        # next run.
        objects.insert(0,root)
        for object in objects:
            object_path = os.path.join(root, object)
            os.chmod(object_path, mode)
            if apply_acls:
                new_acl.applyto(object_path)

def ensure_fs_permissions(directories=None, files=None,
    files_create=None, user=None, group=None):
    """
    Make sure needed directories and files exists with the correct permissions
    """
    if not user or not group:
        from otpme.lib import config
        user = config.user
        group = config.group

    # Make sure user/goup exists.
    check_user(user)
    check_group(group)

    if directories:
        for d in directories:
            if not os.path.exists(d):
                create_dir(d, user=user, group=group)
            set_fs_ownership(path=d, user=user, group=group, recursive=False)
            set_fs_permissions(path=d, mode=directories[d], recursive=False)

    if files:
        for f in files:
            if os.path.exists(f):
                set_fs_ownership(path=f, user=user, group=group)
                set_fs_permissions(path=f, mode=files[f])

    if files_create:
        for f in files_create:
            parent_dir = os.path.dirname(f)
            if not os.path.exists(parent_dir):
                msg = (_("Cannot create file '%s'. Directory does not exist: "
                        "%s") % (f, parent_dir))
                raise OTPmeException(msg)
            # Create empty file if it does not exists.
            if not os.path.exists(f):
                touch(f, user=user, group=group)
            # Set ownership and permissions.
            set_fs_ownership(path=f, user=user, group=group)
            set_fs_permissions(path=f, mode=files_create[f])

def read_data_file(filename, *args, **kwargs):
    _file = JsonFile(filename)
    return _file.read(*args, **kwargs)

def write_data_file(filename, *args, **kwargs):
    _file = JsonFile(filename)
    return _file.write(*args, **kwargs)

#def read_data_file(object_id, object_uuid, *args, **kwargs):
#    _file = SQLiteFile(object_id, object_uuid)
#    return _file.read(*args, **kwargs)
#
#def write_data_file(object_id, object_uuid, *args, **kwargs):
#    _file = SQLiteFile(object_id, object_uuid)
#    return _file.write(*args, **kwargs)
#
#def delete_data_file(object_uuid):
#    from otpme.lib.db_dict import SQLiteDict
#    _dict = SQLiteDict(uuid=object_uuid)
#    _dict.drop()

def write_lock(write=True):
    """ Decorator to handle write lock. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            from otpme.lib import locking
            lock_id = self.file_path.replace("/", ":")
            try:
                _lock = locking.acquire_lock(lock_type=FILE_LOCK_TYPE,
                                            lock_id=lock_id, write=write)
            except OTPmeException as e:
                msg = "Failed to acquire file lock: %s: %s" % (self.file_path, e)
                raise ObjectLocked(msg)
            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                _lock.release_lock()
            return result
        return wrapped
    return wrapper

class JsonFile(object):
    def __init__(self, file_path):
        from otpme.lib import config
        # Get file real path to ensure working locking (e.g. on symlink).
        file_real_path = os.path.realpath(file_path)
        self.file_path = file_real_path
        self.logger = config.logger

    def read_file(self):
        try:
            file_content = read_file(self.file_path, compression="auto")
        except Exception as e:
            msg = "Failed to read file: %s: %s" % (self.file_path, e)
            self.logger.critical(msg)
            raise
        try:
            object_config = json.loads(file_content)
        except Exception as e:
            msg = "Failed to load file: %s: %s" % (self.file_path, e)
            self.logger.critical(msg)
            raise
        return object_config

    def write_file(self, object_config, user=None,
        group=None, mode=0o660, user_acls=[], group_acls=[]):
        from otpme.lib import config
        compression = None
        if config.object_json_compression:
            compression = config.object_json_compression
        if config.prettify_object_json:
            file_content = json.dumps(object_config, sort_keys=True, indent=4)
        else:
            file_content = json.dumps(object_config)
        try:
            create_file(path=self.file_path,
                        content=file_content,
                        compression=compression,
                        user=user,
                        group=group,
                        mode=mode,
                        user_acls=user_acls,
                        group_acls=group_acls)
        except Exception as e:
            msg = "Failed to write file: %s: %s" % (self.file_path, e)
            self.logger.critical(msg)

    def read(self, parameters=None):
        """ Import bash style config file into dictionary. """
        try:
            if os.environ['OTPME_DEBUG_FILE_READ'] == "True":
                print("READ: %s" % self.file_path)
        except:
            pass

        if not os.path.exists(self.file_path):
            msg = "No such file or directory: %s" % self.file_path
            raise OTPmeException(msg)

        object_config = self.read_file()
        if parameters:
            for attr in dict(object_config):
                if attr in parameters:
                    continue
                object_config.pop(attr)

        return object_config

    @write_lock(write=True)
    def write(self, object_config, full_data_update=None,
        user=None, group=True, mode=0o660, user_acls=[], group_acls=[]):
        """ Write dictionary to JSON config file. """
        from otpme.lib import stuff
        from otpme.lib import config

        if user is None:
            user = config.user

        try:
            if os.environ['OTPME_DEBUG_FILE_WRITE'] == "True":
                print("WRITE: %s" % self.file_path)
        except:
            pass

        if not isinstance(object_config, dict):
            msg = "<object_config> must be dict not %s" % type(object_config)
            raise OTPmeException(msg)

        object_config = stuff.copy_object(object_config)

        # Get (and remove) modified attributes information from object config.
        try:
            modified_attributes = object_config.pop('MODIFIED_ATTRIBUTES')
        except KeyError:
            modified_attributes = []
        try:
            deleted_attributes = object_config.pop('DELETED_ATTRIBUTES')
        except KeyError:
            deleted_attributes = []
        try:
            list_attributes = object_config['LIST_ATTRIBUTES']
        except KeyError:
            list_attributes = []
        try:
            dict_attributes = object_config['DICT_ATTRIBUTES']
        except KeyError:
            dict_attributes = []
        try:
            incremental_updates = object_config.pop('INCREMENTAL_UPDATES')
        except KeyError:
            incremental_updates = []
        try:
            modified_attributes.remove("INCREMENTAL_UPDATES")
        except ValueError:
            pass

        new_db = False
        if not os.path.exists(self.file_path):
            new_db = True

        if not new_db:
            current_oc = self.read_file()
            new_incr_id = None
            if incremental_updates:
                # Generate increment ID.
                new_incr_id = json.dumps(incremental_updates)
                new_incr_id = stuff.gen_md5(new_incr_id)
                # Skip already written increment.
                try:
                    increment_ids = current_oc["INCREMENT_IDS"]
                except KeyError:
                    increment_ids = []
                increment_ids = sorted(increment_ids)
                for x in increment_ids:
                    incr_id = x[1]
                    if new_incr_id == incr_id:
                        return

            if full_data_update is True:
                self.write_file(object_config,
                                user=user,
                                group=group,
                                mode=mode)
                return object_config

            _modified_attributes = modified_attributes.copy()
            for x in incremental_updates:
                attr = x[1]
                action = x[2]
                value_type = x[3]
                dict_path = x[4]
                if attr in list_attributes:
                    value = x[5]
                    try:
                        current_list = current_oc[attr]
                    except KeyError:
                        current_oc[attr] = []
                        current_list = current_oc[attr]
                    if action == "add":
                        try:
                            index = x[6]
                        except IndexError:
                            index = -1
                        if index == -1:
                            current_list.append(value)
                        else:
                            current_list.insert(index, value)
                    elif action == "del":
                        try:
                            current_list.remove(value)
                        except ValueError:
                            pass
                    else:
                        msg = "Unknown action: %s" % action
                        raise OTPmeException(msg)
                    current_oc[attr] = current_list
                if attr in dict_attributes:
                    if value_type == "list":
                        value = x[5]
                        try:
                            index = x[6]
                        except IndexError:
                            index = -1
                        key = dict_path[-1]
                    if value_type == "dict":
                        if action == "move_to_begin":
                            key = x[5]
                            value = None
                            index = None
                        elif action == "move_to_end":
                            key = x[5]
                            value = None
                            index = None
                        else:
                            key = x[5]
                            value = x[6]
                            index = -1
                    try:
                        current_dict = current_oc[attr]
                    except KeyError:
                        current_oc[attr] = {}
                        current_dict = current_oc[attr]
                    if dict_path:
                        value = incremental_update(current_dict,
                                                    action,
                                                    key,
                                                    dict_path,
                                                    value_type,
                                                    value=value,
                                                    index=index)
                        action = "add"
                        key = dict_path[0]
                    if action == "add":
                        current_dict[key] = value
                    elif action == "del":
                        try:
                            current_dict.pop(key)
                        except KeyError:
                            pass
                    elif action == "move_to_begin":
                        current_dict = OrderedDict(current_dict)
                        current_dict.move_to_end(key, last=False)
                        current_dict = dict(current_dict)
                    elif action == "move_to_end":
                        current_dict = OrderedDict(current_dict)
                        current_dict.move_to_end(key)
                        current_dict = dict(current_dict)
                    else:
                        msg = "Unknown action: %s" % action
                        raise OTPmeException(msg)
                    current_oc[attr] = current_dict
                try:
                    _modified_attributes.remove(attr)
                except ValueError:
                    pass
            if modified_attributes:
                for attr in _modified_attributes:
                    try:
                        value = object_config[attr]
                    except:
                        msg = "Missing modified attribute: %s" % attr
                        raise OTPmeException(msg)
                    current_oc[attr] = value
            for attr in deleted_attributes:
                current_oc.pop(attr)
        else:
            new_incr_id = None
            increment_ids = []
            # Set new increment ID.
            current_oc = object_config

        # Save increment ID.
        if new_incr_id:
            try:
                _increment_ids = current_oc['INCREMENT_IDS']
            except KeyError:
                _increment_ids = []
            for x in _increment_ids:
                if x in increment_ids:
                    continue
                increment_ids.append(x)
            increment_ids.append([time.time(), new_incr_id])
            increment_ids = sorted(increment_ids)[-500:]
            current_oc['INCREMENT_IDS'] = increment_ids
        # Make sure data is written.
        self.write_file(current_oc,
                        user=user,
                        group=group,
                        mode=mode,
                        user_acls=user_acls,
                        group_acls=group_acls)
        return current_oc

class SQLiteFile(object):
    def __init__(self, object_id, object_uuid):
        from otpme.lib import config
        self.object_id = object_id
        self.object_uuid = object_uuid
        self.logger = config.logger

    def read(self, parameters=None):
        """ Import bash style config file into dictionary. """
        from otpme.lib.db_dict import SQLiteDict
        object_config = SQLiteDict(uuid=self.object_uuid)
        object_config = object_config.copy()
        if parameters:
            for attr in dict(object_config):
                if attr in parameters:
                    continue
                object_config.pop(attr)
        return object_config

    def write(self, object_config, full_data_update=None,
        user=None, group=True, mode=0o660, user_acls=[], group_acls=[]):
        """ Write dictionary to JSON config file. """
        from otpme.lib import stuff
        from otpme.lib import config
        from otpme.lib.db_dict import SQLiteDict

        if user is None:
            user = config.user

        try:
            if os.environ['OTPME_DEBUG_FILE_WRITE'] == "True":
                print("WRITE: %s" % self.file_path)
        except:
            pass

        if not isinstance(object_config, dict):
            msg = "<object_config> must be dict not %s" % type(object_config)
            raise OTPmeException(msg)

        object_config = stuff.copy_object(object_config)

        # Get (and remove) modified attributes information from object config.
        try:
            modified_attributes = object_config.pop('MODIFIED_ATTRIBUTES')
        except KeyError:
            modified_attributes = []
        try:
            deleted_attributes = object_config.pop('DELETED_ATTRIBUTES')
        except KeyError:
            deleted_attributes = []
        try:
            list_attributes = object_config['LIST_ATTRIBUTES']
        except KeyError:
            list_attributes = []
        try:
            dict_attributes = object_config['DICT_ATTRIBUTES']
        except KeyError:
            dict_attributes = []
        try:
            incremental_updates = object_config.pop('INCREMENTAL_UPDATES')
        except KeyError:
            incremental_updates = []
        try:
            modified_attributes.remove("INCREMENTAL_UPDATES")
        except ValueError:
            pass

        new_db = False
        current_oc = SQLiteDict(uuid=self.object_uuid)
        try:
            current_oc['UUID']
        except KeyError:
            new_db = True

        if not new_db:
            new_incr_id = None
            if incremental_updates:
                # Generate increment ID.
                new_incr_id = json.dumps(incremental_updates)
                new_incr_id = stuff.gen_md5(new_incr_id)
                # Skip already written increment.
                try:
                    increment_ids = current_oc["INCREMENT_IDS"]
                except KeyError:
                    current_oc["INCREMENT_IDS"] = []
                    increment_ids = current_oc["INCREMENT_IDS"]
                #increment_ids = sorted(increment_ids)
                for x in increment_ids:
                    incr_id = x[1]
                    if new_incr_id == incr_id:
                        return

            if full_data_update is True:
                current_oc.clear()
                current_oc.bulk_insert(object_config)
                return

            _modified_attributes = modified_attributes.copy()
            for x in incremental_updates:
                attr = x[1]
                action = x[2]
                value_type = x[3]
                dict_path = x[4]
                if attr in list_attributes:
                    value = x[5]
                    try:
                        current_list = current_oc[attr]
                    except KeyError:
                        current_oc[attr] = []
                        current_list = current_oc[attr]
                    if action == "add":
                        #print("AAA", attr, value)
                        current_list.append(value)
                    elif action == "del":
                        try:
                            current_list.remove(value)
                        except ValueError:
                            pass
                    else:
                        msg = "Unknown action: %s" % action
                        raise OTPmeException(msg)
                if attr in dict_attributes:
                    if value_type == "list":
                        value = x[5]
                        key = dict_path[-1]
                    if value_type == "dict":
                        key = x[5]
                        value = x[6]
                    try:
                        current_dict = current_oc[attr]
                    except KeyError:
                        current_oc[attr] = {}
                        current_dict = current_oc[attr]
                    if dict_path:
                        value = incremental_update(current_dict,
                                                    action,
                                                    key,
                                                    dict_path,
                                                    value_type,
                                                    value)
                        action = "add"
                        key = dict_path[0]
                    if action == "add":
                        current_dict[key] = value
                    elif action == "del":
                        try:
                            current_dict.pop(key)
                        except KeyError:
                            pass
                    else:
                        msg = "Unknown action: %s" % action
                        raise OTPmeException(msg)
                    current_oc[attr] = current_dict
                try:
                    _modified_attributes.remove(attr)
                except ValueError:
                    pass
            if modified_attributes:
                for attr in _modified_attributes:
                    try:
                        value = object_config[attr]
                    except:
                        msg = "Missing modified attribute: %s" % attr
                        raise OTPmeException(msg)
                    current_oc[attr] = value
            for attr in deleted_attributes:
                current_oc.pop(attr)
        else:
            new_incr_id = None
            # Set new increment ID.
            current_oc.bulk_insert(object_config)
            try:
                increment_ids = current_oc["INCREMENT_IDS"]
            except KeyError:
                current_oc["INCREMENT_IDS"] = []
                increment_ids = current_oc["INCREMENT_IDS"]

        # Save increment ID.
        if new_incr_id:
            #try:
            #    _increment_ids = current_oc['INCREMENT_IDS']
            #except KeyError:
            #    current_oc['INCREMENT_IDS'] = []
            #    _increment_ids = current_oc['INCREMENT_IDS']
            #for x in _increment_ids:
            #    if x in increment_ids:
            #        continue
            #    increment_ids.append(x)
            increment_ids.append([time.time(), new_incr_id])
            #increment_ids = sorted(increment_ids)[-5:]
            #current_oc['INCREMENT_IDS'] = increment_ids
        current_oc.commit()
        current_oc.close()
