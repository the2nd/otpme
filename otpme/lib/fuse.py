# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
import time
import stat
import hmac
import errno
import random
import base64
import struct
import hashlib
import setproctitle
from typing import List
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import connections
from otpme.lib.protocols import status_codes
from otpme.lib.register import register_module
from otpme.lib.encryption import hash_password
from otpme.lib.fscoding import encode_method_call

from otpme.lib.exceptions import *

os.environ['FUSE_NAME'] = "fuse3"

#import mfusepy as fuse
from otpme.lib.third_party import mfusepy as fuse

diriv_cache = {}
filesize_cache = {}
path_hash_cache = {}
no_such_file_cache = {}
no_such_data_cache = {}
last_create_cache = None
last_create_cache_time = 0.0

UTIME_NOW = 1073741823
CONF_FILE = "otpmecryptfs.conf"
DIRIV_NAME = "otpmecryptfs.diriv"
LONGNAME_PREFIX = "otpmecryptfs.longname."

# We use cephfs blocksize which results in good read/write performance.
PREFERRED_BLOCK_SIZE = 4194304

register_module("otpme.lib.encryption")

def gen_diriv():
    iv = os.urandom(16)
    return iv

def read_cryptfs_settings(path):
    conf_file = os.path.join(path, CONF_FILE)
    if not os.path.exists(conf_file):
        msg = "Cryptfs not initialized."
        raise NotInitialized(msg)
    try:
        fd = open(conf_file, "r")
        fs_data = fd.read()
        fd.close()
    except Exception as e:
        msg = "Failed to read cryptfs settings: %s" % e
        raise OTPmeException(msg)
    try:
        fs_data = json.loads(fs_data)
    except Exception as e:
        msg = "Failed to load cryptfs settings: %s" % e
        raise OTPmeException(msg)
    return fs_data

def init_cryptfs(path, block_size, hash_params):
    conf_file = os.path.join(path, CONF_FILE)
    if os.path.exists(conf_file):
        msg = "Cryptfs already initialized."
        raise AlreadyInitialized(msg)
    init_data = {
                'block_size'    : block_size,
                'hash_params'   : hash_params,
                }
    init_data = json.dumps(init_data)
    try:
        fd = open(conf_file, "w")
        fd.write(init_data)
        fd.close()
    except Exception as e:
        msg = "Failed to init cryptfs: %s" % e
        raise OTPmeException(msg)
    try:
        os.chmod(conf_file, 0o600)
    except Exception as e:
        msg = ("Failed to set config file permissions: %s: %s"
                % (conf_file, e))
        raise OTPmeException(msg)
    diriv_file = os.path.join(path, DIRIV_NAME)
    if os.path.exists(diriv_file):
        return
    diriv = gen_diriv()
    try:
        fd = open(diriv_file, "wb")
        fd.write(diriv)
        fd.close()
    except Exception as e:
        msg = "Failed to init cryptfs: %s" % e
        raise OTPmeException(msg)
    try:
        os.chmod(diriv_file, 0o644)
    except Exception as e:
        msg = ("Failed to set diriv file permissions: %s: %s"
                % (diriv_file, e))
        raise OTPmeException(msg)

class OTPmeFS(fuse.Operations):
    '''
    OTPmeFS.
    '''

    def __init__(
        self,
        share,
        share_site,
        logger,
        nodes,
        ):
        self.use_ns = True
        self.share = share
        self.share_site = share_site
        self.nodes = nodes
        self.fsd_conn = None
        self.max_name = 255
        self.username = None
        self.encrypted = False
        self.logger = logger
        self.add_share_key = False
        self.master_password = None
        config.daemon_mode = True

    def get_user(self):
        agent_conn = connections.get(daemon="agent")
        try:
            username = agent_conn.get_user()
        finally:
            agent_conn.close()
        return username

    def get_fsd_connection(self, node):
        # Get SOTP from agent
        agent_conn = connections.get(daemon="agent")
        try:
            sotp = agent_conn.get_sotp(site=self.share_site)[1]
        except Exception as e:
            msg = "Unable to get SOTP from agent: %s" % e
            raise OTPmeException(msg)
        finally:
            agent_conn.close()
        try:
            fsd_conn = connections.get(daemon="fsd",
                                    node=node,
                                    allow_untrusted=True,
                                    username=self.username,
                                    password=sotp,
                                    use_ssh_agent=False,
                                    use_smartcard=False,
                                    timeout=300)
        except Exception as e:
            msg = "Failed to get daemon connection: %s" % e
            raise OTPmeException(msg)
        return fsd_conn

    def send(self, command, command_args, binary_data=None):
        while True:
            if not self.fsd_conn:
                tried_nodes = []
                nodes = self.nodes
                while True:
                    remaining_nodes = list(set(nodes) - set(tried_nodes))
                    if not remaining_nodes:
                        if command != "fsop_write":
                            raise OSError(errno.EHOSTUNREACH, "Server unreachable")
                        break
                    if self.username is None:
                        try:
                            self.username = self.get_user()
                        except Exception as e:
                            msg = "Unable to get username from agent: %s" % e
                            raise OSError(errno.EINVAL, msg)
                    node = random.choice(remaining_nodes)
                    msg = "Trying connection to node: %s" % node
                    self.logger.info(msg)
                    try:
                        self.fsd_conn = self.get_fsd_connection(node)
                    except Exception as e:
                        tried_nodes.append(node)
                        self.fsd_conn = None
                        msg = "Failed to get fsd connection: %s" % e
                        self.logger.warning(msg)
                        #config.raise_exception()
                        if len(tried_nodes) == len(nodes):
                            msg = "Nodes failed: %s" % tried_nodes
                            self.logger.warning(msg)
                            if command != "fsop_write":
                                raise OSError(errno.EHOSTUNREACH, "Server unreachable")
                        continue
                    tried_nodes.append(node)
                    mount_args = {'share':self.share}
                    master_password_mount = False
                    if self.master_password:
                        master_password_mount = True
                        mount_args['master_password_mount'] = master_password_mount
                    mount_status, \
                    mount_response_code, \
                    mount_response, \
                    mount_binary_data = self.fsd_conn.send(command="mount",
                                                    command_args=mount_args,
                                                    handle_response=False,
                                                    encrypt_request=False,
                                                    encode_request=False,
                                                    compress_request=False)
                    if not mount_status:
                        msg = "Failed to mount share: %s: %s" % (self.share, mount_response)
                        self.logger.warning(msg)
                        if len(tried_nodes) == len(nodes):
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            if command != "fsop_write":
                                if mount_response_code == status_codes.UNKNOWN_OBJECT:
                                    raise OSError(errno.ENOENT, mount_response)
                                elif mount_response_code == status_codes.PERMISSION_DENIED:
                                    raise OSError(errno.EACCES, mount_response)
                                else:
                                    raise OSError(errno.EINVAL, mount_response)
                        time.sleep(1)
                        continue
                    try:
                        self.nodes = mount_response['nodes']
                    except KeyError:
                        msg = "Mount response misses nodes: %s: %s" % (self.share, node)
                        self.logger.info(msg)
                    if self.encrypted:
                        try:
                            block_size= mount_response['block_size']
                        except KeyError:
                            msg = ("Mount response misses block size: %s: %s"
                                    % (self.share, node))
                            self.logger.warning(msg)
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            raise OSError(errno.ENOENT, "Missing block size")
                        # Set block size for encrypted fs.
                        self.set_block_size(block_size)
                        if not self.key:
                            if master_password_mount:
                                try:
                                    master_password_hash_params= mount_response['master_password_hash_params']
                                except KeyError:
                                    msg = ("Mount response misses master password hash parameters: %s: %s"
                                            % (self.share, node))
                                    self.logger.warning(msg)
                                    self.fsd_conn.close()
                                    self.fsd_conn = None
                                    raise OSError(errno.EACCES, "No share key received")
                                try:
                                    hash_data = hash_password(self.master_password,
                                                            encoding=None,
                                                            **master_password_hash_params)
                                    share_key = hash_data.pop("hash")
                                except Exception as e:
                                    msg = ("Failed to derive share key from master password: %s: %s"
                                            % (self.share, e))
                                    self.logger.warning(msg)
                                    self.fsd_conn.close()
                                    self.fsd_conn = None
                                    raise OSError(errno.EACCES, "No share key received")
                            else:
                                try:
                                    share_key= mount_response['share_key']
                                except KeyError:
                                    msg = "Mount response misses share key: %s: %s" % (self.share, node)
                                    self.logger.warning(msg)
                                    self.fsd_conn.close()
                                    self.fsd_conn = None
                                    raise OSError(errno.EACCES, "No share key received")
                                # Decrypt share key with key script.
                                try:
                                    share_key = stuff.decrypt_share_key(self.username,
                                                                        share_key,
                                                                        key_mode=None,
                                                                        encode=False)
                                except Exception as e:
                                    msg = "Failed to decrypt share key: %s: %s" % (self.share, e)
                                    self.logger.warning(msg)
                                    self.fsd_conn.close()
                                    self.fsd_conn = None
                                    raise OSError(errno.EACCES, "Failed to decrypt share key")
                            try:
                                self.setup_encryption(share_key)
                            except Exception as e:
                                msg = "Failed to setup encryption: %s: %s" % (self.share, e)
                                self.logger.warning(msg)
                                self.fsd_conn.close()
                                self.fsd_conn = None
                                raise OSError(errno.EINVAL, msg)
                        # Get max filename length for encrypted shares.
                        statfs = self.statfs(path="/")
                        try:
                            self.max_name = statfs['f_namemax']
                        except:
                            pass
                    msg = "Share mounted: %s (%s)" % (self.share, node)
                    self.logger.info(msg)
                    print(msg)
                    # Add share key.
                    if self.add_share_key:
                        # Encrypt share key with key script.
                        try:
                            enc_share_key = stuff.encrypt_share_key(username=self.username,
                                                                    share_user=self.username,
                                                                    share_key=share_key,
                                                                    key_mode=None)
                        except Exception as e:
                            msg = "Failed to encrypt share key: %s: %s" % (self.share, e)
                            self.logger.warning(msg)
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            raise OSError(errno.EACCES, "Failed to decrypt share key")
                        # Add token and share key to share
                        add_args = {'share_key':enc_share_key}
                        add_status, \
                        add_response_code, \
                        add_response, \
                        add_binary_data = self.fsd_conn.send(command="add_share_key",
                                                        command_args=add_args,
                                                        handle_response=False,
                                                        encrypt_request=False,
                                                        encode_request=False,
                                                        compress_request=False)
                        if not add_status:
                            raise OSError(errno.EACCES, "Failed to add share key.")
                        self.add_share_key = False
                    break

            if not self.fsd_conn:
                continue

            try:
                status, \
                response_code, \
                response, \
                binary_data = self.fsd_conn.send(command=command,
                                                command_args=command_args,
                                                binary_data=binary_data,
                                                handle_response=False,
                                                encrypt_request=False,
                                                encode_request=False,
                                                compress_request=False)
            except Exception as e:
                self.fsd_conn.close()
                self.fsd_conn = None
                msg = "Failed to send data: %s: %s" % (command, e)
                self.logger.warning(msg)
                if command != "fsop_write":
                    raise OSError(errno.EHOSTUNREACH, "Server unreachable")
                time.sleep(1)
                continue
            break
        return status, response_code, response, binary_data

    def check_no_such_file_cache(self, path):
        global no_such_file_cache
        try:
            cache_time = no_such_file_cache[path]
        except KeyError:
            pass
        else:
            cache_age = time.time() - cache_time
            if cache_age < 2:
                raise OSError(errno.ENOENT, "No such file or directory")
        no_such_file_cache[path] = time.time()

    def check_no_such_data_cache(self, path):
        global no_such_data_cache
        try:
            cache_time = no_such_data_cache[path]
        except KeyError:
            pass
        else:
            cache_age = time.time() - cache_time
            if cache_age < 2:
                raise OSError(errno.ENODATA, "No such attribute")
        no_such_data_cache[path] = time.time()

    @fuse.overrides(fuse.Operations)
    def chmod(self, path: str, mode: int) -> int:
        self.logger.debug(f"chmod method called for path: {path}")
        method_data = encode_method_call(method_name="chmod",
                                        path=path,
                                        mode=mode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_chmod", command_args=command_args)
        if status is not True:
            self.logger.debug(f"chmod failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"chmod successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def chown(self, path: str, uid: int, gid: int) -> int:
        self.logger.debug(f"chown method called for path: {path}")
        method_data = encode_method_call(method_name="chown",
                                        path=path,
                                        uid=uid,
                                        gid=gid)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_chown", command_args=command_args)
        if status is not True:
            self.logger.debug(f"chown failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"chown successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def create(self, path: str, mode, fi=None) -> int:
        self.logger.debug(f"create method called for path: {path}")
        method_data = encode_method_call(method_name="create",
                                        path=path,
                                        mode=mode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_create", command_args=command_args)
        if status is not True:
            self.logger.debug(f"create failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"create successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def destroy(self, path: str) -> None:
        self.logger.debug(f"destroy method called for path: {path}")
        if self.fsd_conn:
            self.fsd_conn.close()
        self.logger.debug(f"destroy completed for path: {path}")

    @fuse.overrides(fuse.Operations)
    def getattr(self, path: str, fh: Optional[int] = None):
        self.logger.debug(f"getattr method called for path: {path}")
        method_data = encode_method_call(method_name="getattr", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_getattr", command_args=command_args)
        if status is not True:
            self.logger.debug(f"getattr failed for path: {path}")
            if response_code == errno.ENOENT:
                self.check_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        block_size = response['st_blksize']
        blocks = response['st_blocks']
        file_size = blocks * block_size
        new_blocks = file_size // PREFERRED_BLOCK_SIZE
        response['st_blocks'] = new_blocks
        response['st_blksize'] = PREFERRED_BLOCK_SIZE
        self.logger.debug(f"getattr successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def statfs(self, path: str):
        self.logger.debug(f"statfs method called for path: {path}")
        method_data = encode_method_call(method_name="statfs", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_statfs", command_args=command_args)
        if status is not True:
            self.logger.debug(f"statfs failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        response['f_bsize'] = PREFERRED_BLOCK_SIZE
        response['f_frsize'] = PREFERRED_BLOCK_SIZE
        self.logger.debug(f"statfs successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def mkdir(self, path: str, mode: int) -> int:
        self.logger.debug(f"mkdir method called for path: {path}")
        method_data = encode_method_call(method_name="mkdir",
                                        path=path,
                                        mode=mode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_mkdir", command_args=command_args)
        if status is not True:
            self.logger.debug(f"mkdir failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"mkdir successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        self.logger.debug(f"read method called for path: {path}")
        method_data = encode_method_call(method_name="read",
                                        path=path,
                                        size=size,
                                        offset=offset)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_read", command_args=command_args)
        if status is not True:
            self.logger.debug(f"read failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"read successful for path: {path}")
        return binary_data

    @fuse.overrides(fuse.Operations)
    def open(self, path: str, flags) -> int:
        self.logger.debug(f"open method called for path: {path}")
        method_data = encode_method_call(method_name="open",
                                        path=path,
                                        flags=flags)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_open", command_args=command_args)
        if status is not True:
            self.logger.debug(f"open failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"open successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def release(self, path: str, fh: int=None) -> int:
        self.logger.debug(f"release method called for path: {path}")
        method_data = encode_method_call(method_name="release", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_release", command_args=command_args)
        if status is not True:
            self.logger.debug(f"release failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"release successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def access(self, path: str, amode: int) -> int:
        self.logger.debug(f"access method called for path: {path}")
        method_data = encode_method_call(method_name="access",
                                        path=path,
                                        amode=amode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_access", command_args=command_args)
        if status is not True:
            self.logger.debug(f"access failed for path: {path}")
            if response_code == errno.ENOENT:
                self.check_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"access successful for path: {path}")
        return 0

    @fuse.overrides(fuse.Operations)
    def readdir(self, path: str, fh: int) -> fuse.ReadDirResult:
        self.logger.debug(f"readdir method called for path: {path}")
        method_data = encode_method_call(method_name="readdir", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_readdir", command_args=command_args)
        if status is not True:
            self.logger.debug(f"readdir failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"readdir successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def readlink(self, path: str) -> str:
        self.logger.debug(f"readlink method called for path: {path}")
        method_data = encode_method_call(method_name="readlink", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_readlink", command_args=command_args)
        if status is not True:
            self.logger.debug(f"readlink failed for path: {path}")
            if response_code == errno.ENOENT:
                self.check_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"readlink successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def rename(self, old: str, new: str) -> int:
        self.logger.debug(f"rename method called for old: {old}, new: {new}")
        method_data = encode_method_call(method_name="rename",
                                        old=old,
                                        new=new)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_rename", command_args=command_args)
        if status is not True:
            self.logger.debug(f"rename failed for old: {old}, new: {new}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"rename successful for old: {old}, new: {new}")
        return response

    @fuse.overrides(fuse.Operations)
    def rmdir(self, path: str) -> int:
        self.logger.debug(f"rmdir method called for path: {path}")
        method_data = encode_method_call(method_name="rmdir", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_rmdir", command_args=command_args)
        if status is not True:
            self.logger.debug(f"rmdir failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"rmdir successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def link(self, target: str, source: str):
        self.logger.debug(f"link method called for target: {target}, source: {source}")
        method_data = encode_method_call(method_name="link",
                                        target=target,
                                        source=source)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_link", command_args=command_args)
        if status is not True:
            self.logger.debug(f"link failed for target: {target}, source: {source}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"link successful for target: {target}, source: {source}")
        return response

    @fuse.overrides(fuse.Operations)
    def symlink(self, target: str, source: str) -> int:
        self.logger.debug(f"symlink method called for target: {target}, source: {source}")
        method_data = encode_method_call(method_name="symlink",
                                        target=target,
                                        source=source)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_symlink", command_args=command_args)
        if status is not True:
            self.logger.debug(f"symlink failed for target: {target}, source: {source}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"symlink successful for target: {target}, source: {source}")
        return response

    @fuse.overrides(fuse.Operations)
    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        self.logger.debug(f"truncate method called for path: {path}")
        method_data = encode_method_call(method_name="truncate",
                                        path=path,
                                        length=length)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_truncate", command_args=command_args)
        if status is not True:
            self.logger.debug(f"truncate failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"truncate successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def unlink(self, path: str) -> int:
        self.logger.debug(f"unlink method called for path: {path}")
        method_data = encode_method_call(method_name="unlink", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_unlink", command_args=command_args)
        if status is not True:
            self.logger.debug(f"unlink failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"unlink successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        self.logger.debug(f"utimens method called for path: {path}")
        if times is None:
            now = time.time_ns()
            times = (now, now)
        else:
            atime_ns = times[0]
            mtime_ns = times[1]
            if atime_ns == UTIME_NOW or mtime_ns == UTIME_NOW:
                now = time.time_ns()
                if atime_ns == UTIME_NOW:
                    atime_ns = now
                if mtime_ns == UTIME_NOW:
                    mtime_ns = now
                times = (atime_ns, mtime_ns)
        method_data = encode_method_call(method_name="utimens",
                                        path=path,
                                        times=times)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_utimens", command_args=command_args)
        if status is not True:
            self.logger.debug(f"utimens failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"utimens successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        self.logger.debug(f"write method called for path: {path}")
        method_data = encode_method_call(method_name="write", path=path, offset=offset)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_write", command_args=command_args, binary_data=data)
        if status is not True:
            self.logger.debug(f"write failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"write successful for path: {path}")
        return response

    def exists(self, path: str):
        self.logger.debug(f"exists method called for path: {path}")
        method_data = encode_method_call(method_name="exists", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_exists", command_args=command_args)
        if status is not True:
            self.logger.debug(f"exists failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"exists successful for path: {path}")
        return response

    def get_mtime(self, path: str):
        self.logger.debug(f"get_mtime method called for path: {path}")
        method_data = encode_method_call(method_name="get_mtime", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_get_mtime", command_args=command_args)
        if status is not True:
            self.logger.debug(f"get_mtime failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"get_mtime successful for path: {path}")
        return response

    def get_ctime(self, path: str):
        self.logger.debug(f"get_ctime method called for path: {path}")
        method_data = encode_method_call(method_name="get_ctime", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_get_ctime", command_args=command_args)
        if status is not True:
            self.logger.debug(f"get_ctime failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"get_ctime successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs)"""
        self.logger.debug(f"getxattr method called for path: {path}")
        method_data = encode_method_call(method_name="getxattr",
                                        path=path,
                                        name=name,
                                        position=position)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_getxattr", command_args=command_args)
        if status is not True:
            self.logger.debug(f"getxattr failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"getxattr successful for path: {path}")
        return binary_data if binary_data else response

    @fuse.overrides(fuse.Operations)
    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        self.logger.debug(f"setxattr method called for path: {path}")
        method_data = encode_method_call(method_name="setxattr",
                                        path=path,
                                        name=name,
                                        value=value,
                                        options=options,
                                        position=position)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_setxattr", command_args=command_args)
        if status is not True:
            self.logger.debug(f"setxattr failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        self.logger.debug(f"setxattr successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def listxattr(self, path: str) -> List[str]:
        """List all extended attributes"""
        method_data = encode_method_call(method_name="listxattr", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_listxattr", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes"""
        method_data = encode_method_call(method_name="removexattr",
                                        path=path,
                                        name=name)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_removexattr", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response


class EncryptedFS(OTPmeFS):
    def __init__(
        self,
        share,
        share_site,
        logger,
        nodes,
        master_password,
        add_share_key=False,
        *args,
        **kwargs,
        ):
        super().__init__(share, share_site, logger, nodes, *args, **kwargs)
        self.key = None
        self.encrypted = True
        self.name_key = None
        self.content_key = None
        self.add_share_key = add_share_key
        self.master_password = master_password
        self.block_size = 4096
        self.nonce_size = 12
        self.tag_size = 16
        self.metadata_size = 4 + 4 + self.nonce_size + self.tag_size
        self.block_with_metadata_size = self.block_size + self.metadata_size
        self.max_name = 255
        self.null_block = b'\x00' * self.block_size

    def set_block_size(self, block_size):
        self.block_size = block_size
        self.block_with_metadata_size = self.block_size + self.metadata_size
        self.null_block = b'\x00' * self.block_size

    def setup_encryption(self, key):
        key_len = len(key)
        if key_len not in (16, 24, 32):
            raise ValueError("Key must be 16, 24 or 32 bytes.")
        self.key = key
        hkdf_len = key_len * 2
        hkdf = HKDF(algorithm=hashes.SHA256(), length=hkdf_len, salt=None, info=b"otpmefs-keys")
        okm = hkdf.derive(self.key)
        self.content_key = okm[:key_len]
        self.name_key = okm[key_len:key_len * 2]
        self.aesgcm = AESGCM(self.content_key)
        self.aesgcm_names = AESGCM(self.name_key)

    def _b64e(self, b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

    def _b64d(self, s: str) -> bytes:
        pad = '=' * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s + pad)

    def _diriv_path(self, enc_dir_path: str) -> str:
        return os.path.join(enc_dir_path, DIRIV_NAME)

    def _create_diriv(self, enc_dir_path: str) -> bytes:
        diriv_file = self._diriv_path(enc_dir_path)
        if super().exists(diriv_file):
            return
        try:
            super().create(diriv_file, 0o664, None)
        except Exception:
            pass
        iv = gen_diriv()
        super().truncate(diriv_file, 0, None)
        super().write(diriv_file, iv, 0, None)
        return iv

    def _load_diriv(self, enc_dir_path: str, use_cache=False) -> bytes:
        #if not use_cache:
        #    print("UUUU", enc_dir_path, use_cache)
        #    from otpme.lib import debug
        #    debug.trace()
        if use_cache:
            try:
                diriv = diriv_cache[enc_dir_path]
            except KeyError:
                pass
            else:
                return diriv
        try:
            diriv_cache.pop(enc_dir_path)
        except KeyError:
            pass
        diriv_file = self._diriv_path(enc_dir_path)
        diriv = super().read(diriv_file, 16, 0, None)
        # Make sure diriv file is closed and not re-read old diriv from still open fh.
        super().release(diriv_file)
        if not diriv or len(diriv) != 16:
            raise fuse.FuseOSError(errno.EIO)
        diriv_cache[enc_dir_path] = diriv
        return diriv

    def _name_nonce(self, diriv: bytes, name: str) -> bytes:
        mac = hmac.new(self.name_key, diriv + name.encode('utf-8'), hashlib.sha256).digest()
        return mac[:self.nonce_size]

    def _encrypt_name_blob(self, diriv: bytes, name: str) -> str:
        nonce = self._name_nonce(diriv, name)
        ct = self.aesgcm_names.encrypt(nonce, name.encode('utf-8'), None)
        return self._b64e(nonce + ct)

    def _try_decrypt_name_blob(self, blob: str) -> Optional[str]:
        try:
            raw = self._b64d(blob)
            nonce, ct = raw[:self.nonce_size], raw[self.nonce_size:]
            pt = self.aesgcm_names.decrypt(nonce, ct, None)
            return pt.decode('utf-8')
        except Exception:
            return None

    def _long_helper_path(self, enc_dir_path: str, tag: str) -> str:
        return enc_dir_path.rstrip('/') + '/' + tag + ".name" if enc_dir_path != '/' else '/' + tag + ".name"

    def _to_fs_name(self, enc_dir_path: str, clear_name: str, diriv: bytes=None,
        use_diriv_cache: bool=False, create_longname: bool=False) -> str:
        if not diriv:
            diriv = self._load_diriv(enc_dir_path, use_cache=use_diriv_cache)
        ciph = self._encrypt_name_blob(diriv, clear_name)
        if len(ciph) <= self.max_name:
            return ciph
        # Handle long names.
        h = hashlib.sha256(ciph.encode('ascii')).hexdigest()[:32]
        tag = LONGNAME_PREFIX + h
        if not create_longname:
            return tag
        helper = self._long_helper_path(enc_dir_path, tag)
        try:
            super().create(helper, 0o600, None)
        except Exception:
            pass
        super().truncate(helper, 0, None)
        super().write(helper, ciph.encode('ascii'), 0, None)
        return tag

    def _from_fs_name(self, enc_dir_path: str, fs_name: str) -> Optional[str]:
        if fs_name in ('.', '..'):
            return fs_name
        if fs_name == DIRIV_NAME:
            return None
        if fs_name.startswith(LONGNAME_PREFIX):
            helper = self._long_helper_path(enc_dir_path, fs_name)
            try:
                data = super().read(helper, 8192, 0, None)
                blob = data.decode('ascii')
                return self._try_decrypt_name_blob(blob)
            except Exception:
                return None
        return self._try_decrypt_name_blob(fs_name)

    def _split_components(self, path: str) -> List[str]:
        if path == '/':
            return []
        return [c for c in path.split('/') if c]

    def _join_enc(self, parts: List[str]) -> str:
        return '/' + '/'.join(parts) if parts else '/'

    def _map_plain_to_enc(self, plain_path: str, use_diriv_cache=False) -> str:
        comps = self._split_components(plain_path)
        enc_parts = []
        enc_dir = '/'
        for name in comps:
            enc_name = self._to_fs_name(enc_dir, name, use_diriv_cache=use_diriv_cache)
            enc_parts.append(enc_name)
            enc_dir = self._join_enc(enc_parts)
        enc_path = self._join_enc(enc_parts)
        return enc_path

    def _encrypt_block(self, block, unencrypted_block_len, nonce):
        self.logger.debug(f"Encrypting block of size {len(block)} with nonce {nonce.hex()}")
        #if len(block) != self.block_size:
        #    self.logger.error(f"Invalid block size: {len(block)}, expected {self.block_size}")
        #    raise fuse.FuseOSError(errno.EIO)
        #if len(nonce) != self.nonce_size:
        #    self.logger.error(f"Invalid nonce size: {len(nonce)}, expected {self.nonce_size}")
        #    raise fuse.FuseOSError(errno.EIO)
        try:
            ciphertext = self.aesgcm.encrypt(nonce, block, None)
            tag = ciphertext[-self.tag_size:]
            encrypted_block = ciphertext[:-self.tag_size]
            block_len = len(encrypted_block)
            if block_len != self.block_size:
                self.logger.error(f"Encrypted block size invalid: {block_len}, expected {self.block_size}")
                raise fuse.FuseOSError(errno.EIO)
            if tag == b'\x00' * self.tag_size:
                self.logger.error("Generated zero tag, which is invalid")
                raise fuse.FuseOSError(errno.EIO)
            self.logger.debug(f"Encrypted block size: {block_len}, tag: {tag.hex()}")
            serialized_block = (
                struct.pack('!I', block_len) +
                struct.pack('!I', unencrypted_block_len) +
                encrypted_block +
                nonce +
                tag
            )
            #if len(serialized_block) != self.block_with_metadata_size:
            #    self.logger.error(f"Serialized block size invalid: {len(serialized_block)}, expected {self.block_with_metadata_size}")
            #    raise fuse.FuseOSError(errno.EIO)
            return serialized_block
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e

    def open(self, path: str, flags):
        accmode = flags & os.O_ACCMODE
        if accmode == os.O_RDONLY:
            use_diriv_cache = True
        else:
            use_diriv_cache = False
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        # Dont open file in append mode. This is required because even if
        # only append is requested we have to seek/write existing blocks
        # (e.g. the last block that is written partial).
        if flags & os.O_APPEND:
            flags = flags & ~os.O_APPEND
            # Ensure write flags are present when append mode was requested.
            if not (flags & (os.O_WRONLY | os.O_RDWR)):
                flags |= os.O_WRONLY
        try:
            return super().open(enc, flags)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            enc = self._map_plain_to_enc(path)
            return super().open(enc, flags)

    def release(self, path: str, fh: int=None):
        enc = self._map_plain_to_enc(path, use_diriv_cache=True)
        try:
            return super().release(enc, 0)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            enc = self._map_plain_to_enc(path)
            return super().release(enc, 0)

    def create(self, path: str, mode, fi=None):
        global last_create_cache
        global last_create_cache_time
        parent = os.path.dirname(path) if path != '/' else '/'
        use_diriv_cache = False
        if last_create_cache == parent:
            last_create_cache_age = time.time() - last_create_cache_time
            if last_create_cache_age < 0.5:
                use_diriv_cache = True
        name = os.path.basename(path)
        enc_parent = self._map_plain_to_enc(parent, use_diriv_cache=use_diriv_cache)
        enc_name = self._to_fs_name(enc_parent,
                                    name,
                                    use_diriv_cache=use_diriv_cache,
                                    create_longname=True)
        enc_path = enc_parent.rstrip('/') + '/' + enc_name if enc_parent != '/' else '/' + enc_name
        try:
            result = super().create(enc_path, mode, fi)
        except:
            last_create_cache = None
            last_create_cache_time = 0.0
            raise
        last_create_cache = parent
        last_create_cache_time = time.time()
        return result

    def mkdir(self, path: str, mode: int, use_diriv_cache: bool=True) -> int:
        parent = os.path.dirname(path) if path != '/' else '/'
        name = os.path.basename(path)
        enc_parent = self._map_plain_to_enc(parent, use_diriv_cache=use_diriv_cache)
        enc_name = self._to_fs_name(enc_parent, name,
                                    use_diriv_cache=use_diriv_cache,
                                    create_longname=True)
        enc_path = enc_parent.rstrip('/') + '/' + enc_name if enc_parent != '/' else '/' + enc_name
        try:
            result = super().mkdir(enc_path, mode)
        except:
            if not use_diriv_cache:
                raise
            return self.mkdir(path, mode, use_diriv_cache=False)
        # Create diriv for new directory.
        self._create_diriv(enc_path)
        return result

    def rmdir(self, path: str, use_diriv_cache: bool=True) -> int:
        global diriv_cache
        global last_create_cache
        global last_create_cache_time
        empty_dir_entries = [".", "..", DIRIV_NAME]
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        enc_dir_path = os.path.dirname(enc)
        try:
            dir_entries = super().readdir(enc, 0)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.rmdir(path, use_diriv_cache=False)
        # Remove diriv file on rmdir on empty dir.
        if sorted(empty_dir_entries) == sorted(dir_entries):
            enc_parent = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
            diriv_path = os.path.join(enc_parent, DIRIV_NAME)
            super().unlink(diriv_path)
            try:
                diriv_cache.pop(enc_dir_path)
            except KeyError:
                pass
        last_create_cache = None
        last_create_cache_time = 0.0
        try:
            result = super().rmdir(enc)
        except:
            if not use_diriv_cache:
                raise
            return self.rmdir(path, use_diriv_cache=False)
        # Make sure we remove longname file.
        enc_dir_name = os.path.basename(enc)
        if enc_dir_name.startswith(LONGNAME_PREFIX):
            longname_file = enc + ".name"
            super().unlink(longname_file)
        return result

    def unlink(self, path: str, use_diriv_cache=True) -> int:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        # Handle longname symlinks.
        st_info = super().getattr(enc)
        if stat.S_ISLNK(st_info['st_mode']):
            link_target = super().readlink(enc)
            if link_target.startswith(LONGNAME_PREFIX):
                target_longname_file = "%s.name" % link_target
                enc_old_parent = os.path.dirname(enc)
                enc_old_path = os.path.join(enc_old_parent, target_longname_file)
                super().unlink(enc_old_path)
        # Make sure we remove longname file.
        enc_file = os.path.basename(enc)
        if enc_file.startswith(LONGNAME_PREFIX):
            longname_file = enc + ".name"
            super().unlink(longname_file)
        try:
            return super().unlink(enc)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.unlink(path, use_diriv_cache=False)

    def rename(self, old: str, new: str) -> int:
        enc_old = self._map_plain_to_enc(old)
        new_parent = os.path.dirname(new) if new != '/' else '/'
        new_name = os.path.basename(new)
        enc_new_parent = self._map_plain_to_enc(new_parent)
        # Handle longname symlinks.
        st_info = super().getattr(enc_old)
        if stat.S_ISLNK(st_info['st_mode']):
            link_target = super().readlink(enc_old)
            if link_target.startswith(LONGNAME_PREFIX):
                target_longname_file = "%s.name" % link_target
                enc_old_parent = os.path.dirname(enc_old)
                enc_old_path = os.path.join(enc_old_parent, target_longname_file)
                enc_new_path = os.path.join(enc_new_parent, target_longname_file)
                super().rename(enc_old_path, enc_new_path)
        enc_new_name = self._to_fs_name(enc_new_parent,
                                        new_name,
                                        create_longname=True)
        enc_new = enc_new_parent.rstrip('/') + '/' + enc_new_name if enc_new_parent != '/' else '/' + enc_new_name
        try:
            result = super().rename(enc_old, enc_new)
        except:
            enc_new_file = os.path.basename(enc_new)
            if enc_new_file.startswith(LONGNAME_PREFIX):
                longname_file = enc_new + ".name"
                super().unlink(longname_file)
            raise
        enc_old_file = os.path.basename(enc_old)
        if enc_old_file.startswith(LONGNAME_PREFIX):
            longname_file = enc_old + ".name"
            super().unlink(longname_file)
        return result

    def link(self, target: str, source: str, use_diriv_cache: bool=True):
        enc_source = self._map_plain_to_enc(source, use_diriv_cache=use_diriv_cache)
        enc_target_parent = self._map_plain_to_enc(os.path.dirname(target) or '/',
                                                use_diriv_cache=use_diriv_cache)
        enc_target_name = self._to_fs_name(enc_target_parent,
                                        os.path.basename(target),
                                        use_diriv_cache=use_diriv_cache,
                                        create_longname=True)
        enc_target = enc_target_parent.rstrip('/') + '/' + enc_target_name if enc_target_parent != '/' else '/' + enc_target_name
        try:
            return super().link(enc_target, enc_source)
        except Exception as e:
            # Remove target longname-name file on error.
            if enc_target_name.startswith(LONGNAME_PREFIX):
                enc_source_longname_file = "%s.name" % enc_source
                super().unlink(enc_source_longname_file)
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            # On ENOENT error retry withouth diriv cache.
            return self.link(target, source, use_diriv_cache=False)

    def symlink(self, target: str, source: str, use_diriv_cache: bool=True) -> int:
        enc_target_parent = self._map_plain_to_enc(os.path.dirname(target) or '/',
                                                use_diriv_cache=use_diriv_cache)
        enc_target_name = self._to_fs_name(enc_target_parent,
                                        os.path.basename(target),
                                        use_diriv_cache=use_diriv_cache,
                                        create_longname=True)
        enc_target = enc_target_parent.rstrip('/') + '/' + enc_target_name if enc_target_parent != '/' else '/' + enc_target_name
        diriv = self._load_diriv(enc_target_parent, use_cache=use_diriv_cache)
        enc_source = self._to_fs_name(enc_target_parent,
                                    source or '/',
                                    diriv=diriv,
                                    create_longname=True)
        try:
            return super().symlink(enc_target, enc_source)
        except Exception as e:
            # Remove longname-name files on error.
            if enc_target.startswith(LONGNAME_PREFIX):
                enc_target_longname_file = "%s.name" % enc_target
                super().unlink(enc_target_longname_file)
            if enc_source.startswith(LONGNAME_PREFIX):
                enc_source_longname_file = "%s.name" % enc_source
                super().unlink(enc_source_longname_file)
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            # On ENOENT error retry withouth diriv cache.
            return self.symlink(target, source, use_diriv_cache=False)

    def readlink(self, path: str, use_diriv_cache: bool=True) -> str:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            result = super().readlink(enc)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            self.check_no_such_file_cache(enc)
            return self.readlink(path, use_diriv_cache=False)
        enc_dir_path = os.path.dirname(enc) if path != '/' else '/'
        link_clear = self._from_fs_name(enc_dir_path, result)
        return link_clear

    def access(self, path: str, amode: int, use_diriv_cache: bool=True) -> int:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().access(enc, amode)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            self.check_no_such_file_cache(enc)
            return self.access(path, amode, use_diriv_cache=False)

    def getattr(self, path: str, fh: Optional[int] = None, use_diriv_cache: bool=True):
        global filesize_cache
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            result = super().getattr(enc, fh)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            self.check_no_such_file_cache(enc)
            return self.getattr(path, fh, use_diriv_cache=False)

        if stat.S_ISDIR(result['st_mode']) or stat.S_ISLNK(result['st_mode']):
            self.logger.debug(f"Path {path} is a {'directory' if stat.S_ISDIR(result['st_mode']) else 'symlink'}, returning original st_size: {result['st_size']}")
            return result

        encrypted_size = result['st_size']
        if encrypted_size == 0:
            self.logger.debug(f"No data for {path}, assuming empty file")
            return result

        file_mtime = result['st_mtime']
        file_ctime = result['st_ctime']
        unencrypted_size = None
        try:
            cache_data = filesize_cache[path]
        except KeyError:
            pass
        else:
            cache_ctime = cache_data['ctime']
            if file_ctime == cache_ctime:
                result = cache_data['result']
                return result
            cache_mtime = cache_data['mtime']
            if file_mtime == cache_mtime:
                unencrypted_size = cache_data['size']
        if unencrypted_size is None:
            unencrypted_size = self._calc_unencrypted_size(path, encrypted_size, enc)
        unencrypted_blocks = (unencrypted_size + 511) // 512
        self.logger.debug(f"Unencrypted file size for {path}: {unencrypted_size}")
        result['st_size'] = unencrypted_size
        result['st_blocks'] = unencrypted_blocks
        filesize_cache[path] = {
                                'ctime'     : file_ctime,
                                'mtime'     : file_mtime,
                                'size'      : unencrypted_size,
                                'result'    : result,
                                }
        return result

    def readdir(self, path: str, fh: int) -> fuse.ReadDirResult:
        enc_dir = self._map_plain_to_enc(path)
        try:
            diriv_cache.pop(enc_dir)
        except KeyError:
            pass
        enc_entries = super().readdir(enc_dir, fh)
        plain = []
        for e in enc_entries:
            pt = self._from_fs_name(enc_dir, e)
            if pt is None:
                continue
            plain.append(pt)
        return plain

    def read(self, path, size, offset, fh):
        enc = self._map_plain_to_enc(path, use_diriv_cache=True)
        self.logger.debug(f"Reading {size} bytes at offset {offset} from {path}")
        start_block = offset // self.block_size
        end_block = (offset + size - 1) // self.block_size
        block_count = end_block - start_block + 1
        self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
        read_offset = start_block * self.block_with_metadata_size
        read_size = block_count * self.block_with_metadata_size
        self.logger.debug(f"Read offset: {read_offset}, read size: {read_size}")
        encrypted_size = self._get_file_size(enc)
        if encrypted_size == 0:
            self.logger.debug("File is empty")
            return b''
        read_size = min(read_size, encrypted_size - read_offset)
        if read_size <= 0:
            self.logger.debug("No data to read at offset")
            return b''
        try:
            encrypted_data = super().read(enc, read_size, read_offset, fh)
            self.logger.debug(f"Read {len(encrypted_data)} bytes from server")
            #if len(encrypted_data) != read_size:
            #    self.logger.error(f"Expected {read_size} bytes, but read {len(encrypted_data)}")
            #    raise fuse.FuseOSError(errno.EIO)
        except Exception as e:
            self.logger.error(f"Read failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        decrypted_data = self._decrypt_blocks(encrypted_data, block_count)
        del encrypted_data
        data_offset = offset % self.block_size
        result = decrypted_data[data_offset:data_offset + size]
        del decrypted_data
        return result

    def write(self, path, data, offset, fh):
        global path_hash_cache
        enc = self._map_plain_to_enc(path, use_diriv_cache=True)
        self.logger.debug(f"Writing {len(data)} bytes at offset {offset} to {path}")
        start_block = offset // self.block_size
        end_block = (offset + len(data) - 1) // self.block_size
        block_count = end_block - start_block + 1
        self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
        write_offset = start_block * self.block_with_metadata_size
        self.logger.debug(f"Write offset: {write_offset}")
        is_first_block_partial = offset % self.block_size != 0
        is_last_block_partial = (offset + len(data)) % self.block_size != 0
        self.logger.debug(f"First block partial: {is_first_block_partial}, Last block partial: {is_last_block_partial}")
        current_size = self._get_file_size(enc)
        decrypted_data = {}
        if current_size > 0 and (is_first_block_partial or is_last_block_partial):
            blocks_to_read = []
            if is_first_block_partial:
                blocks_to_read.append(start_block)
            if is_last_block_partial and end_block != start_block:
                blocks_to_read.append(end_block)
            for block in blocks_to_read:
                read_offset = block * self.block_with_metadata_size
                read_size = self.block_with_metadata_size
                max_available_size = self._get_file_size(enc)
                read_size = min(read_size, max_available_size - read_offset)
                if read_size > 0:
                    self.logger.debug(f"Reading block {block} at offset {read_offset}, size {read_size}")
                    try:
                        encrypted_data = super().read(enc, read_size, read_offset, fh)
                        decrypted_data[block] = self._decrypt_blocks(encrypted_data, 1)[:self.block_size]
                    except Exception as e:
                        self.logger.error(f"Failed to read block {block}: {e}")
                        raise fuse.FuseOSError(errno.EIO) from e
        # Create a unique identifier from the file path using SHA-256.
        try:
            path_hash = path_hash_cache[path]
        except KeyError:
            path_hash = hashlib.sha256(path.encode('utf-8')).digest()
            path_hash_cache[path] = path_hash
        data_offset = 0
        block_counter = 0
        serialized_data = bytearray()
        for i in range(start_block, end_block + 1):
            block = bytearray()
            if i == start_block and is_first_block_partial:
                existing_block = decrypted_data.get(i, b'\x00' * self.block_size)
                block_offset = offset % self.block_size
                block.extend(existing_block[:block_offset])
                data_start = data_offset
                data_end = min(len(data), data_start + self.block_size - block_offset)
                block.extend(data[data_start:data_end])
                block_length = len(block)
                data_offset = data_end
                if len(block) % self.block_size != 0:
                    block.extend(b'\x00' * (self.block_size - (len(block) % self.block_size)))
            elif i == end_block and is_last_block_partial:
                existing_block = decrypted_data.get(i, b'\x00' * self.block_size)
                remaining_data = data[data_offset:]
                block.extend(remaining_data)
                block_length = len(remaining_data)
                remaining_length = self.block_size - len(remaining_data)
                if remaining_length > 0:
                    block.extend(existing_block[:remaining_length])
            else:
                data_start = data_offset
                data_end = min(len(data), data_start + self.block_size)
                block.extend(data[data_start:data_end])
                block_length = len(data[data_start:data_end])
                data_offset = data_end
                if len(block) % self.block_size != 0:
                    block.extend(b'\x00' * (self.block_size - (len(block) % self.block_size)))
            # Get block number for nonce.
            block_number = write_offset + block_counter
            # Generate nonce: 8 bytes block_number, 2 bytes path_id, 2 bytes random.
            nonce = struct.pack('!Q', block_number) + path_hash[:2] + os.urandom(2)
            serialized_block = self._encrypt_block(block, block_length, nonce)
            serialized_data.extend(serialized_block)
            block_counter += 1
        try:
            self.logger.debug(f"Writing {len(serialized_data)} bytes at offset {write_offset}")
            #if len(serialized_data) != block_count * self.block_with_metadata_size:
            #    self.logger.error(f"Invalid serialized data size: {len(serialized_data)}, expected {block_count * self.block_with_metadata_size}")
            #    raise fuse.FuseOSError(errno.EIO)
            super().write(enc, bytes(serialized_data), write_offset, fh)
        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        del serialized_data
        return len(data)

    #def write(self, path, data, offset, fh):
    #    enc = self._map_plain_to_enc(path, use_diriv_cache=True)
    #    self.logger.debug(f"Writing {len(data)} bytes at offset {offset} to {path}")
    #    start_block = offset // self.block_size
    #    end_block = (offset + len(data) - 1) // self.block_size
    #    block_count = end_block - start_block + 1
    #    self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
    #    write_offset = start_block * self.block_with_metadata_size
    #    self.logger.debug(f"Write offset: {write_offset}")
    #    is_first_block_partial = offset % self.block_size != 0
    #    is_last_block_partial = (offset + len(data)) % self.block_size != 0
    #    self.logger.debug(f"First block partial: {is_first_block_partial}, Last block partial: {is_last_block_partial}")
    #    current_size = self._get_file_size(enc)
    #    decrypted_data = {}
    #    if current_size > 0 and (is_first_block_partial or is_last_block_partial):
    #        blocks_to_read = []
    #        if is_first_block_partial:
    #            blocks_to_read.append(start_block)
    #        if is_last_block_partial and end_block != start_block:
    #            blocks_to_read.append(end_block)
    #        for block in blocks_to_read:
    #            read_offset = block * self.block_with_metadata_size
    #            read_size = self.block_with_metadata_size
    #            max_available_size = self._get_file_size(enc)
    #            read_size = min(read_size, max_available_size - read_offset)
    #            if read_size > 0:
    #                self.logger.debug(f"Reading block {block} at offset {read_offset}, size {read_size}")
    #                try:
    #                    encrypted_data = super().read(enc, read_size, read_offset, fh)
    #                    decrypted_data[block] = self._decrypt_blocks(encrypted_data, 1)[:self.block_size]
    #                except Exception as e:
    #                    self.logger.error(f"Failed to read block {block}: {e}")
    #                    raise fuse.FuseOSError(errno.EIO) from e
    #    new_data = bytearray()
    #    data_offset = 0
    #    block_lengths = []
    #    for i in range(start_block, end_block + 1):
    #        if i == start_block and is_first_block_partial:
    #            existing_block = decrypted_data.get(i, b'\x00' * self.block_size)
    #            block_offset = offset % self.block_size
    #            new_data.extend(existing_block[:block_offset])
    #            data_start = data_offset
    #            data_end = min(len(data), data_start + self.block_size - block_offset)
    #            new_data.extend(data[data_start:data_end])
    #            block_lengths.append(len(new_data) - sum(block_lengths))
    #            data_offset = data_end
    #            if len(new_data) % self.block_size != 0:
    #                new_data.extend(b'\x00' * (self.block_size - (len(new_data) % self.block_size)))
    #        elif i == end_block and is_last_block_partial:
    #            existing_block = decrypted_data.get(i, b'\x00' * self.block_size)
    #            remaining_data = data[data_offset:]
    #            new_data.extend(remaining_data)
    #            block_lengths.append(len(remaining_data))
    #            remaining_length = self.block_size - len(remaining_data)
    #            if remaining_length > 0:
    #                new_data.extend(existing_block[:remaining_length])
    #        else:
    #            data_start = data_offset
    #            data_end = min(len(data), data_start + self.block_size)
    #            new_data.extend(data[data_start:data_end])
    #            block_lengths.append(len(data[data_start:data_end]))
    #            data_offset = data_end
    #            if len(new_data) % self.block_size != 0:
    #                new_data.extend(b'\x00' * (self.block_size - (len(new_data) % self.block_size)))
    #    # Create a unique identifier from the file path using SHA-256.
    #    path_hash = hashlib.sha256(path.encode('utf-8')).digest()
    #    serialized_data = bytearray()
    #    for i in range(block_count):
    #        block = new_data[i * self.block_size:(i + 1) * self.block_size]
    #        #if len(block) != self.block_size:
    #        #    self.logger.error(f"Invalid block size for block {i}: {len(block)} bytes, expected {self.block_size}")
    #        #    raise fuse.FuseOSError(errno.EIO)
    #        # Get block number for nonce.
    #        block_number = write_offset + i
    #        ## Create a unique identifier from the file path using SHA-256.
    #        #path_hash = hashlib.sha256(path.encode('utf-8')).digest()
    #        # Generate nonce: 8 bytes block_number, 2 bytes path_id, 2 bytes random.
    #        nonce = struct.pack('!Q', block_number) + path_hash[:2] + os.urandom(2)
    #        #if len(nonce) != self.nonce_size:
    #        #    self.logger.error("Generated nonce with wrong size.")
    #        #    raise fuse.FuseOSError(errno.EIO)
    #        #if nonce == b'\x00' * self.nonce_size:
    #        #    self.logger.error("Generated zero nonce, which is invalid")
    #        #    raise fuse.FuseOSError(errno.EIO)
    #        block_length = block_lengths[i]
    #        serialized_block = self._encrypt_block(block, block_length, nonce)
    #        serialized_data.extend(serialized_block)
    #    del new_data
    #    try:
    #        self.logger.debug(f"Writing {len(serialized_data)} bytes at offset {write_offset}")
    #        #if len(serialized_data) != block_count * self.block_with_metadata_size:
    #        #    self.logger.error(f"Invalid serialized data size: {len(serialized_data)}, expected {block_count * self.block_with_metadata_size}")
    #        #    raise fuse.FuseOSError(errno.EIO)
    #        super().write(enc, bytes(serialized_data), write_offset, fh)
    #    except Exception as e:
    #        self.logger.error(f"Write failed: {e}")
    #        raise fuse.FuseOSError(errno.EIO) from e
    #    del serialized_data
    #    return len(data)

    def _decrypt_blocks(self, encrypted_data, block_count):
        decrypted_data = bytearray()
        offset = 0
        blocks_processed = 0
        while offset < len(encrypted_data) and blocks_processed < block_count:
            #if offset + 4 > len(encrypted_data):
            #    self.logger.error(f"Invalid block structure at offset {offset}, not enough data for block length")
            #    raise fuse.FuseOSError(errno.EIO)
            block_len = struct.unpack('!I', encrypted_data[offset:offset + 4])[0]
            if block_len == 0:
                block = encrypted_data[offset + 8:offset + 8 + self.block_size]
                block_len = len(block)
                if block == self.null_block:
                    decrypted_data.extend(block)
                    offset += 8
                    offset += block_len
                    offset += self.nonce_size
                    offset += self.tag_size
                    blocks_processed += 1
                    continue
                msg = "Found invalid block without block len that is not a null block."
                self.logger.error(msg)
                raise fuse.FuseOSError(errno.EIO)

            # Set block_len and unencrypted_block_len to offset.
            offset += 8
            self.logger.debug(f"Reading block {blocks_processed} at offset {offset - 4}, block_len: {block_len}")
            if block_len != self.block_size:
                self.logger.error(f"Invalid block length: {block_len}, expected {self.block_size}")
                raise fuse.FuseOSError(errno.EIO)
            if offset + block_len + self.nonce_size + self.tag_size > len(encrypted_data):
                self.logger.error(f"Invalid block structure at offset {offset}, not enough data for block")
                raise fuse.FuseOSError(errno.EIO)
            block = encrypted_data[offset:offset + block_len]
            offset += block_len
            nonce = encrypted_data[offset:offset + self.nonce_size]
            offset += self.nonce_size
            tag = encrypted_data[offset:offset + self.tag_size]
            offset += self.tag_size
            self.logger.debug(f"Decrypting block_len: {block_len}, nonce: {nonce.hex()}, tag: {tag.hex()}")
            try:
                decrypted_block = self.aesgcm.decrypt(nonce, block + tag, None)
                decrypted_data.extend(decrypted_block)
            except Exception as e:
                self.logger.error(f"Decryption failed for block {blocks_processed}: {e}")
                raise fuse.FuseOSError(errno.EIO) from e
            blocks_processed += 1
        if blocks_processed < block_count:
            self.logger.error(f"Expected {block_count} blocks, but processed {blocks_processed}")
            raise fuse.FuseOSError(errno.EIO)
        if len(decrypted_data) < block_count * self.block_size:
            decrypted_data.extend(b'\x00' * (block_count * self.block_size - len(decrypted_data)))
        return bytes(decrypted_data)

    def _get_file_size(self, enc_path):
        try:
            attrs = super().getattr(enc_path)
            self.logger.debug(f"File size for {enc_path}: {attrs['st_size']}")
            return attrs['st_size']
        except fuse.FuseOSError as e:
            if e.errno == errno.ENOENT:
                return 0
            raise

    def _calc_unencrypted_size(self, path, encrypted_size, enc=None):
        """ Calculate unencrypted file size. """
        if enc is None:
            enc = self._map_plain_to_enc(path, use_diriv_cache=True)
        num_blocks = encrypted_size // self.block_with_metadata_size
        if encrypted_size % self.block_with_metadata_size != 0:
            self.logger.error(f"Invalid encrypted file size for {path}: {encrypted_size}, not a multiple of {self.block_with_metadata_size}")
            raise fuse.FuseOSError(errno.EIO)
        unencrypted_size = (num_blocks - 1) * self.block_size if num_blocks > 0 else 0
        try:
            offset = (num_blocks - 1) * self.block_with_metadata_size + 4
            len_data = super().read(enc, 4, offset, None)
            super().release(enc, None)
            unencrypted_block_len = struct.unpack('!I', len_data)[0]
            self.logger.debug(f"Last block unencrypted length: {unencrypted_block_len}")
            if unencrypted_block_len > self.block_size:
                self.logger.error(f"Invalid unencrypted block length for last block: {unencrypted_block_len}, exceeds {self.block_size}")
                raise fuse.FuseOSError(errno.EIO)
            unencrypted_size += unencrypted_block_len
        except Exception as e:
            self.logger.error(f"Failed to read unencrypted block length for last block of {path}: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        return unencrypted_size

    def truncate(self, path, length, fh=None):
        enc = self._map_plain_to_enc(path)
        self.logger.debug(f"Truncating {path} to {length} bytes")

        current_encrypted_size = self._get_file_size(enc)

        # Truncate file to 0.
        if length == 0:
            self.logger.debug("Truncating file to 0 bytes")
            return super().truncate(enc, 0, fh)

        # Pad empty file with zeros.
        if current_encrypted_size == 0:
            self.logger.debug("File is empty, creating zero-filled content")
            zero_data = b'\x00' * length
            self.write(path, zero_data, 0, fh)
            return 0

        # Calculate blocks needed after truncate.
        needed_blocks = (length + self.block_size - 1) // self.block_size
        current_blocks = current_encrypted_size // self.block_with_metadata_size

        self.logger.debug(f"Current blocks: {current_blocks}, needed blocks: {needed_blocks}")

        # File gets bigger, expand with zeros.
        current_unencrypted_size = self._calc_unencrypted_size(path, current_encrypted_size, enc)
        if length > current_unencrypted_size:
            self.logger.debug("Expanding file with zeros")
            zero_data = b'\x00' * (length - current_unencrypted_size)
            self.write(path, zero_data, current_unencrypted_size, fh)
            return 0

        # If needed blocks is 0 truncate file to 0.
        if needed_blocks == 0:
            return super().truncate(enc, 0, fh)

        if needed_blocks < current_blocks:
            # If file should shrink, truncate to full block size.
            self.logger.debug(f"Removing blocks: from {current_blocks} to {needed_blocks}")
            new_encrypted_size = needed_blocks * self.block_with_metadata_size
            super().truncate(enc, new_encrypted_size, fh)

        # Handle partial last block.
        last_block_remainder = length % self.block_size
        if last_block_remainder != 0 and needed_blocks > 0:
            self.logger.debug(f"Adjusting last block to {last_block_remainder} bytes")
            # Read current block data.
            last_block_start_offset = (needed_blocks - 1) * self.block_size
            current_block_data = self.read(path, self.block_size, last_block_start_offset, fh)
            # Truncate current block.
            truncated_data = current_block_data[:last_block_remainder]
            # Write truncated block.
            self.write(path, truncated_data, last_block_start_offset, fh)

        return 0

    def chmod(self, path: str, mode: int, use_diriv_cache: bool=True) -> int:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().chmod(enc, mode)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.chmod(path, mode, use_diriv_cache=False)

    def chown(self, path: str, uid: int, gid: int, use_diriv_cache: bool=True) -> int:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().chown(enc, uid, gid)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.chown(path, uid, gid, use_diriv_cache=False)

    def utimens(self, path: str, times: Optional[tuple[int, int]] = None, use_diriv_cache: bool=True) -> int:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().utimens(enc, times)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.utimens(path, times, use_diriv_cache=False)

    def getxattr(self, path: str, name: str, position: int = 0, use_diriv_cache: bool=True) -> bytes:
        """Get extended attributes (including POSIX ACLs) from encrypted filesystem"""
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().getxattr(enc, name, position)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if e.errno == errno.ENODATA:
                self.check_no_such_data_cache(enc)
            if not use_diriv_cache:
                raise
            self.check_no_such_file_cache(enc)
            return self.getxattr(path, name, position, use_diriv_cache=False)

    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0, use_diriv_cache: bool=True) -> int:
        """Set extended attributes (including POSIX ACLs) on encrypted filesystem"""
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().setxattr(enc, name, value, options, position)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.setxattr(path, name, value, options, position, use_diriv_cache=False)

    def listxattr(self, path: str, use_diriv_cache: bool=True) -> List[str]:
        """List all extended attributes from encrypted filesystem"""
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().listxattr(enc)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.listxattr(path, use_diriv_cache=False)

    def removexattr(self, path: str, name: str, use_diriv_cache: bool=True) -> int:
        """Remove extended attributes from encrypted filesystem"""
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().removexattr(enc, name)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.removexattr(path, name, use_diriv_cache=False)

def get_mount_point(username, share_site, share_name):
    mount_point = os.path.join(config.mount_root_dir,
                                username,
                                share_site,
                                share_name)
    return mount_point

def prepare_mount_point(username, share_site, share):
    mount_point = get_mount_point(username, share_site, share)
    if os.path.ismount(mount_point):
        msg = "Already mounted: %s" % mount_point
        raise OTPmeException(msg)
    if os.path.exists(mount_point):
        return mount_point
    old_usmask = os.umask(0o077)
    try:
        os.makedirs(mount_point, mode=0o700, exist_ok=True)
    except FileExistsError:
        pass
    finally:
        os.umask(old_usmask)
    return mount_point

def mount_share_proc(share, share_site, mount, nodes, encrypted, **kwargs):
    new_proctitle = "otpme-mount %s %s" % (share, mount)
    setproctitle.setproctitle(new_proctitle)
    mount_share(share, share_site, mount, nodes, encrypted, **kwargs)

def mount_share(share, share_site, mount, nodes, encrypted=False,
    master_password=None, add_share_key=False, foreground=True,
    logger=None):
    if add_share_key and not master_password:
        msg = "Need <master_password> with <add_share_key>"
        raise OTPmeException(msg)
    #if config.debug_enabled:
    #    logging.basicConfig(level=logging.DEBUG)
    fsname = "OTPmeFS:/%s" % share
    if logger is None:
        logger = config.logger
    msg = "Got nodes: %s: %s" % (share, nodes)
    print(msg)
    logger.info(msg)
    if encrypted:
        fuse.FUSE(EncryptedFS(share, share_site, logger, nodes, master_password, add_share_key),
                        mount,
                        foreground=foreground,
                        nothreads=True,
                        fsname=fsname,
                        )
    else:
        fuse.FUSE(OTPmeFS(share, share_site, logger, nodes=nodes),
                        mount,
                        foreground=foreground,
                        nothreads=True,
                        fsname=fsname,
                        )
