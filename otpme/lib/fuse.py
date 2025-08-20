# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import stat
import hmac
import errno
import base64
import hashlib
import random
import struct
import logging
import argparse
import setproctitle
import mfusepy as fuse
from typing import List
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from otpme.lib import config
from otpme.lib import connections
from otpme.lib.protocols import status_codes

from otpme.lib.exceptions import *

path_cache = {}
files_cache = {}
filesize_cache = {}

BLOCK_SIZE = 4096  # 4 KB
NONCE_SIZE = 12
TAG_SIZE = 16
METADATA_SIZE = 4 + 4 + NONCE_SIZE + TAG_SIZE
BLOCK_WITH_METADATA_SIZE = BLOCK_SIZE + METADATA_SIZE  # 4132
# We use cephfs blocksize which results in good read/write performance.
PREFERRED_BLOCK_SIZE = 4194304

DIRIV_NAME = "otpmecryptfs.diriv"
LONGNAME_PREFIX = "otpmecryptfs.longname."
MAX_NAME = 255

class OTPmeFS(fuse.Operations):
    '''
    OTPmeFS.
    '''

    def __init__(self, share, logger, nodes):
        self.share = share
        self.nodes = nodes
        self.fsd_conn = None
        self.logger = logger
        config.daemon_mode = True

    def get_fsd_connection(self, node=None):
        agent_conn = connections.get(daemon="agent")
        status, \
        status_code, \
        reply = agent_conn.send("get_sotp")
        if not status:
            msg = "Unable to get SOTP from agent: %s" % reply
            raise OTPmeException(msg)
        try:
            try:
                username = reply['username']
            except KeyError:
                msg = "Failed to get username from agent."
                self.logger.warning(msg)
                return
            try:
                sotp = reply['sotp']
            except KeyError:
                msg = "Failed to get SOTP from agent."
                self.logger.warning(msg)
                return
        finally:
            agent_conn.close()
        fsd_conn = connections.get(daemon="fsd",
                                node=node,
                                realm=config.realm,
                                site=config.site,
                                username=username,
                                password=sotp,
                                timeout=300)
        return fsd_conn

    def send(self, command, command_args, binary_data=None):
        while True:
            if not self.fsd_conn:
                nodes = self.nodes
                tried_nodes = []
                while True:
                    remaining_nodes = list(set(nodes) - set(tried_nodes))
                    if not remaining_nodes:
                        if command != "write":
                            raise OSError(errno.EHOSTUNREACH, "Server unreachable")
                        break
                    node = random.choice(remaining_nodes)
                    msg = "Trying connection to node: %s" % node
                    self.logger.info(msg)
                    try:
                        self.fsd_conn = self.get_fsd_connection(node=node)
                    except Exception as e:
                        tried_nodes.append(node)
                        self.fsd_conn = None
                        msg = "Failed to get fsd connection: %s" % e
                        self.logger.warning(msg)
                        if len(tried_nodes) == len(nodes):
                            msg = "Nodes failed: %s" % tried_nodes
                            self.logger.warning(msg)
                            if command != "write":
                                raise OSError(errno.EHOSTUNREACH, "Server unreachable")
                        time.sleep(1)
                        continue
                    tried_nodes.append(node)
                    mount_args = {'share':self.share}
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
                            if command != "write":
                                if mount_response_code == status_codes.UNKNOWN_OBJECT:
                                    raise OSError(errno.ENOENT, mount_response)
                                elif mount_response_code == status_codes.PERMISSION_DENIED:
                                    raise OSError(errno.EACCES, mount_response)
                                else:
                                    raise OSError(errno.EINVAL, mount_response)
                        time.sleep(1)
                        continue
                    msg = "Share mounted: %s (%s)" % (self.share, node)
                    print(msg)
                    self.nodes = mount_response
                    self.logger.info(msg)
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
                self.fsd_conn = None
                msg = "Failed to send data: %s" % e
                self.logger.warning(msg)
                if command != "write":
                    raise OSError(errno.EHOSTUNREACH, "Server unreachable")
                time.sleep(1)
                continue
            break
        return status, response_code, response, binary_data

    @fuse.overrides(fuse.Operations)
    def chmod(self, path: str, mode: int) -> int:
        command_args = {'path':path, 'mode':mode}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="chmod", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def chown(self, path: str, uid: int, gid: int) -> int:
        command_args = {'path':path, 'uid':uid, 'gid':gid}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="chown", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def create(self, path: str, mode, fi=None) -> int:
        command_args = {'path':path, 'mode':mode}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="create", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def destroy(self, path: str) -> None:
        if self.fsd_conn:
            self.fsd_conn.close()

    @fuse.overrides(fuse.Operations)
    def getattr(self, path: str, fh: Optional[int] = None):
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="getattr", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        block_size = response['st_blksize']
        blocks = response['st_blocks']
        file_size = blocks * block_size
        new_blocks = file_size // PREFERRED_BLOCK_SIZE
        response['st_blocks'] = new_blocks
        response['st_blksize'] = PREFERRED_BLOCK_SIZE
        return response

    @fuse.overrides(fuse.Operations)
    def statfs(self, path: str):
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="statfs", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        response['f_bsize'] = PREFERRED_BLOCK_SIZE
        response['f_frsize'] = PREFERRED_BLOCK_SIZE
        return response

    @fuse.overrides(fuse.Operations)
    def mkdir(self, path: str, mode: int) -> int:
        command_args = {'path':path, 'mode':mode}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="mkdir", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        command_args = {'path':path, 'offset':offset, 'size':size}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="read", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return binary_data

    @fuse.overrides(fuse.Operations)
    def open(self, path: str, flags) -> int:
        command_args = {'path':path, 'flags':flags}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="open", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def release(self, path: str, fh: int) -> int:
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="release", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def access(self, path: str, amode: int) -> int:
        command_args = {'path':path, 'amode':amode}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="access", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return 0

    @fuse.overrides(fuse.Operations)
    def readdir(self, path: str, fh: int) -> fuse.ReadDirResult:
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="readdir", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def readlink(self, path: str) -> str:
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="readlink", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def rename(self, old: str, new: str) -> int:
        command_args = {'old':old, 'new':new}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="rename", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def rmdir(self, path: str) -> int:
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="rmdir", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def link(self, target: str, source: str):
        command_args = {'target':target, 'source':source}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="link", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def symlink(self, target: str, source: str) -> int:
        command_args = {'target':target, 'source':source}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="symlink", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        command_args = {'path':path, 'length':length}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="truncate", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def unlink(self, path: str) -> int:
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="unlink", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        # FIXME: a simple touch <file> always gives touch_now timestamp. Why?
        if times is not None:
            touch_now = 1.073741823
            if times[0] == touch_now and times[1] == touch_now:
                now = time.time()
                times = (now, now)
        command_args = {'path':path, 'times':times}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="utimens", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        command_args = {'path':path, 'offset':offset}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="write",
                                command_args=command_args,
                                binary_data=data)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    def exists(self, path: str):
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="exists", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    def get_mtime(self, path: str):
        command_args = {'path':path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="get_mtime", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs)"""
        command_args = {'path': path, 'name': name, 'position': position}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="getxattr", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return binary_data if binary_data else response

    @fuse.overrides(fuse.Operations)
    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        command_args = {'path': path, 'name': name, 'options': options, 'position': position}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="setxattr", command_args=command_args, binary_data=value)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def listxattr(self, path: str) -> List[str]:
        """List all extended attributes"""
        command_args = {'path': path}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="listxattr", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response

    @fuse.overrides(fuse.Operations)
    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes"""
        command_args = {'path': path, 'name': name}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="removexattr", command_args=command_args)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response


class EncryptedFS(OTPmeFS):
    def __init__(self, master_key: bytes, share, logger, *args, **kwargs):
        super().__init__(share, logger, *args, **kwargs)
        if len(master_key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24 or 32 bytes.")
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"mfusepy-keys")
        okm = hkdf.derive(master_key)
        self.content_key = okm[:32]
        self.name_key = okm[32:64]
        self.aesgcm = AESGCM(self.content_key)
        self.aesgcm_names = AESGCM(self.name_key)

    def _b64e(self, b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

    def _b64d(self, s: str) -> bytes:
        pad = '=' * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s + pad)

    def _diriv_path(self, enc_dir_path: str) -> str:
        return os.path.join(enc_dir_path, DIRIV_NAME)

    def _load_or_create_diriv(self, enc_dir_path: str) -> bytes:
        diriv_file = self._diriv_path(enc_dir_path)
        try:
            data = super().read(diriv_file, 16, 0, None)
            if data and len(data) == 16:
                return data
        except fuse.FuseOSError as e:
            if e.errno != errno.ENOENT:
                raise
        iv = os.urandom(16)
        try:
            super().create(diriv_file, 0o664, None)
        except Exception:
            pass
        super().truncate(diriv_file, 0, None)
        super().write(diriv_file, iv, 0, None)
        return iv

    def _load_diriv(self, enc_dir_path: str) -> bytes:
        diriv_file = self._diriv_path(enc_dir_path)
        data = super().read(diriv_file, 16, 0, None)
        if not data or len(data) != 16:
            raise fuse.FuseOSError(errno.EIO)
        return data

    def _name_nonce(self, diriv: bytes, name: str) -> bytes:
        mac = hmac.new(self.name_key, diriv + name.encode('utf-8'), hashlib.sha256).digest()
        return mac[:NONCE_SIZE]

    def _encrypt_name_blob(self, diriv: bytes, name: str) -> str:
        nonce = self._name_nonce(diriv, name)
        ct = self.aesgcm_names.encrypt(nonce, name.encode('utf-8'), None)
        return self._b64e(nonce + ct)

    def _try_decrypt_name_blob(self, blob: str) -> Optional[str]:
        try:
            raw = self._b64d(blob)
            nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
            pt = self.aesgcm_names.decrypt(nonce, ct, None)
            return pt.decode('utf-8')
        except Exception:
            return None

    def _long_helper_path(self, enc_dir_path: str, tag: str) -> str:
        return enc_dir_path.rstrip('/') + '/' + tag + ".name" if enc_dir_path != '/' else '/' + tag + ".name"

    def _to_fs_name(self, enc_dir_path: str, clear_name: str, diriv: bytes=None) -> str:
        if not diriv:
            diriv = self._load_diriv(enc_dir_path)
        ciph = self._encrypt_name_blob(diriv, clear_name)
        if len(ciph) <= MAX_NAME:
            return ciph
        # Handle long names.
        h = hashlib.sha256(ciph.encode('ascii')).hexdigest()[:32]
        tag = LONGNAME_PREFIX + h
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

    def _map_plain_to_enc(self, plain_path: str) -> str:
        global path_cache
        try:
            enc_path = path_cache[plain_path]
        except KeyError:
            pass
        else:
            if super().exists(enc_path):
                return enc_path
        comps = self._split_components(plain_path)
        enc_parts = []
        enc_dir = '/'
        for name in comps:
            enc_name = self._to_fs_name(enc_dir, name)
            enc_parts.append(enc_name)
            enc_dir = self._join_enc(enc_parts)
        enc_path = self._join_enc(enc_parts)
        path_cache[plain_path] = enc_path
        return enc_path

    def _encrypt_block(self, block, unencrypted_block_len, nonce):
        self.logger.debug(f"Encrypting block of size {len(block)} with nonce {nonce.hex()}")
        if len(block) != BLOCK_SIZE:
            self.logger.error(f"Invalid block size: {len(block)}, expected {BLOCK_SIZE}")
            raise fuse.FuseOSError(errno.EIO)
        if len(nonce) != NONCE_SIZE:
            self.logger.error(f"Invalid nonce size: {len(nonce)}, expected {NONCE_SIZE}")
            raise fuse.FuseOSError(errno.EIO)
        try:
            ciphertext = self.aesgcm.encrypt(nonce, block, None)
            tag = ciphertext[-TAG_SIZE:]
            encrypted_block = ciphertext[:-TAG_SIZE]
            block_len = len(encrypted_block)
            if block_len != BLOCK_SIZE:
                self.logger.error(f"Encrypted block size invalid: {block_len}, expected {BLOCK_SIZE}")
                raise fuse.FuseOSError(errno.EIO)
            if tag == b'\x00' * TAG_SIZE:
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
            if len(serialized_block) != BLOCK_WITH_METADATA_SIZE:
                self.logger.error(f"Serialized block size invalid: {len(serialized_block)}, expected {BLOCK_WITH_METADATA_SIZE}")
                raise fuse.FuseOSError(errno.EIO)
            return serialized_block
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e

    def open(self, path: str, flags):
        global files_cache
        try:
            enc = files_cache[path]
        except KeyError:
            enc = self._map_plain_to_enc(path)
            files_cache[path] = enc
        # Dont open file in append mode.
        if flags & os.O_APPEND:
            flags = flags & ~os.O_APPEND
        return super().open(enc, flags)

    def release(self, path: str, fh: int):
        global files_cache
        try:
            enc = files_cache[path]
        except KeyError:
            enc = self._map_plain_to_enc(path)
        try:
            files_cache.pop(path)
        except KeyError:
            pass
        return super().release(enc, 0)

    def create(self, path: str, mode, fi=None):
        parent = os.path.dirname(path) if path != '/' else '/'
        name = os.path.basename(path)
        enc_parent = self._map_plain_to_enc(parent)
        enc_name = self._to_fs_name(enc_parent, name)
        enc_path = enc_parent.rstrip('/') + '/' + enc_name if enc_parent != '/' else '/' + enc_name
        #self._load_or_create_diriv(enc_parent)
        return super().create(enc_path, mode, fi)

    def mkdir(self, path: str, mode: int) -> int:
        parent = os.path.dirname(path) if path != '/' else '/'
        name = os.path.basename(path)
        enc_parent = self._map_plain_to_enc(parent)
        enc_name = self._to_fs_name(enc_parent, name)
        enc_path = enc_parent.rstrip('/') + '/' + enc_name if enc_parent != '/' else '/' + enc_name
        r = super().mkdir(enc_path, mode)
        # Create diriv for new directory.
        self._load_or_create_diriv(enc_path)
        return r

    def rmdir(self, path: str) -> int:
        empty_dir_entries = [".", "..", DIRIV_NAME]
        enc = self._map_plain_to_enc(path)
        dir_entries = super().readdir(enc, 0)
        # Remove diriv file on rmdir on empty dir.
        if sorted(empty_dir_entries) == sorted(dir_entries):
            enc_parent = self._map_plain_to_enc(path)
            diriv_path = os.path.join(enc_parent, DIRIV_NAME)
            super().unlink(diriv_path)
        return super().rmdir(enc)

    def unlink(self, path: str) -> int:
        enc = self._map_plain_to_enc(path)
        # Make sure we remove longname file.
        enc_file = os.path.basename(enc)
        if enc_file.startswith(LONGNAME_PREFIX):
            longname_file = enc + ".name"
            super().unlink(longname_file)
        return super().unlink(enc)

    def rename(self, old: str, new: str) -> int:
        # FIXME: We should handle symlinks here.
        #st_info = self.getattr(old)
        #if stat.S_ISLNK(st_info['st_mode']):
        #    print("symlink:", old)
        enc_old = self._map_plain_to_enc(old)
        new_parent = os.path.dirname(new) if new != '/' else '/'
        new_name = os.path.basename(new)
        enc_new_parent = self._map_plain_to_enc(new_parent)
        enc_new_name = self._to_fs_name(enc_new_parent, new_name)
        enc_new = enc_new_parent.rstrip('/') + '/' + enc_new_name if enc_new_parent != '/' else '/' + enc_new_name
        result = super().rename(enc_old, enc_new)
        enc_file = os.path.basename(enc_old)
        if enc_file.startswith(LONGNAME_PREFIX):
            longname_file = enc_old + ".name"
            super().unlink(longname_file)
        return result

    def link(self, target: str, source: str):
        enc_target = self._map_plain_to_enc(target)
        enc_source_parent = self._map_plain_to_enc(os.path.dirname(source) or '/')
        enc_source_name = self._to_fs_name(enc_source_parent, os.path.basename(source))
        enc_source = enc_source_parent.rstrip('/') + '/' + enc_source_name if enc_source_parent != '/' else '/' + enc_source_name
        return super().link(enc_target, enc_source)

    def symlink(self, target: str, source: str) -> int:
        enc_target_parent = self._map_plain_to_enc(os.path.dirname(target) or '/')
        enc_target_name = self._to_fs_name(enc_target_parent, os.path.basename(target))
        enc_target = enc_target_parent.rstrip('/') + '/' + enc_target_name if enc_target_parent != '/' else '/' + enc_target_name
        diriv = self._load_diriv(enc_target_parent)
        enc_source = self._to_fs_name(enc_target_parent, source or '/', diriv=diriv)
        return super().symlink(enc_target, enc_source)

    def readlink(self, path: str) -> str:
        enc = self._map_plain_to_enc(path)
        result = super().readlink(enc)
        enc_dir_path = os.path.dirname(path) if path != '/' else '/'
        link_clear = self._from_fs_name(enc_dir_path, result)
        return link_clear

    def access(self, path: str, amode: int) -> int:
        enc = self._map_plain_to_enc(path)
        return super().access(enc, amode)

    def getattr(self, path: str, fh: Optional[int] = None):
        global filesize_cache
        enc = self._map_plain_to_enc(path)
        result = super().getattr(enc, fh)
        if stat.S_ISDIR(result['st_mode']) or stat.S_ISLNK(result['st_mode']):
            self.logger.debug(f"Path {path} is a {'directory' if stat.S_ISDIR(result['st_mode']) else 'symlink'}, returning original st_size: {result['st_size']}")
            return result

        encrypted_size = result['st_size']
        if encrypted_size == 0:
            self.logger.debug(f"No data for {path}, assuming empty file")
            return result

        file_mtime = result['st_mtime']
        unencrypted_size = None
        try:
            cache_data = filesize_cache[path]
        except KeyError:
            pass
        else:
            cache_mtime = cache_data['mtime']
            if file_mtime == cache_mtime:
                unencrypted_size = cache_data['size']
        if unencrypted_size is None:
            unencrypted_size = self._calc_unencrypted_size(path, encrypted_size, enc)
        filesize_cache[path] = {'mtime':file_mtime, 'size':unencrypted_size}
        unencrypted_blocks = (unencrypted_size + 511) // 512
        self.logger.debug(f"Unencrypted file size for {path}: {unencrypted_size}")
        result['st_size'] = unencrypted_size
        result['st_blocks'] = unencrypted_blocks
        return result

    def readdir(self, path: str, fh: int) -> fuse.ReadDirResult:
        enc_dir = self._map_plain_to_enc(path)
        enc_entries = super().readdir(enc_dir, fh)
        plain = []
        for e in enc_entries:
            pt = self._from_fs_name(enc_dir, e)
            if pt is None:
                continue
            plain.append(pt)
        return plain

    def read(self, path, size, offset, fh):
        enc = self._map_plain_to_enc(path)
        self.logger.debug(f"Reading {size} bytes at offset {offset} from {path}")
        start_block = offset // BLOCK_SIZE
        end_block = (offset + size - 1) // BLOCK_SIZE
        block_count = end_block - start_block + 1
        self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
        read_offset = start_block * BLOCK_WITH_METADATA_SIZE
        read_size = block_count * BLOCK_WITH_METADATA_SIZE
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
            if len(encrypted_data) != read_size:
                self.logger.error(f"Expected {read_size} bytes, but read {len(encrypted_data)}")
                raise fuse.FuseOSError(errno.EIO)
        except Exception as e:
            self.logger.error(f"Read failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        decrypted_data = self._decrypt_blocks(encrypted_data, block_count, remove_padding=True)
        del encrypted_data
        data_offset = offset % BLOCK_SIZE
        result = decrypted_data[data_offset:data_offset + size]
        del decrypted_data
        return result

    def write(self, path, data, offset, fh):
        global files_cache
        try:
            enc = files_cache[path]
        except KeyError:
            enc = self._map_plain_to_enc(path)
            files_cache[path] = enc
        self.logger.debug(f"Writing {len(data)} bytes at offset {offset} to {path}")
        start_block = offset // BLOCK_SIZE
        end_block = (offset + len(data) - 1) // BLOCK_SIZE
        block_count = end_block - start_block + 1
        self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
        write_offset = start_block * BLOCK_WITH_METADATA_SIZE
        self.logger.debug(f"Write offset: {write_offset}")
        is_first_block_partial = offset % BLOCK_SIZE != 0
        is_last_block_partial = (offset + len(data)) % BLOCK_SIZE != 0
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
                read_offset = block * BLOCK_WITH_METADATA_SIZE
                read_size = BLOCK_WITH_METADATA_SIZE
                max_available_size = self._get_file_size(enc)
                read_size = min(read_size, max_available_size - read_offset)
                if read_size > 0:
                    self.logger.debug(f"Reading block {block} at offset {read_offset}, size {read_size}")
                    try:
                        encrypted_data = super().read(enc, read_size, read_offset, fh)
                        decrypted_data[block] = self._decrypt_blocks(encrypted_data, 1)[:BLOCK_SIZE]
                    except Exception as e:
                        self.logger.error(f"Failed to read block {block}: {e}")
                        raise fuse.FuseOSError(errno.EIO) from e
        new_data = bytearray()
        data_offset = 0
        block_lengths = []
        for i in range(start_block, end_block + 1):
            if i == start_block and is_first_block_partial:
                existing_block = decrypted_data.get(i, b'\x00' * BLOCK_SIZE)
                block_offset = offset % BLOCK_SIZE
                new_data.extend(existing_block[:block_offset])
                data_start = data_offset
                data_end = min(len(data), data_start + BLOCK_SIZE - block_offset)
                new_data.extend(data[data_start:data_end])
                block_lengths.append(len(new_data) - sum(block_lengths))
                data_offset = data_end
                if len(new_data) % BLOCK_SIZE != 0:
                    new_data.extend(b'\x00' * (BLOCK_SIZE - (len(new_data) % BLOCK_SIZE)))
            elif i == end_block and is_last_block_partial:
                existing_block = decrypted_data.get(i, b'\x00' * BLOCK_SIZE)
                remaining_data = data[data_offset:]
                new_data.extend(remaining_data)
                block_lengths.append(len(remaining_data))
                remaining_length = BLOCK_SIZE - len(remaining_data)
                if remaining_length > 0:
                    new_data.extend(existing_block[:remaining_length])
            else:
                data_start = data_offset
                data_end = min(len(data), data_start + BLOCK_SIZE)
                new_data.extend(data[data_start:data_end])
                block_lengths.append(len(data[data_start:data_end]))
                data_offset = data_end
                if len(new_data) % BLOCK_SIZE != 0:
                    new_data.extend(b'\x00' * (BLOCK_SIZE - (len(new_data) % BLOCK_SIZE)))
        serialized_data = bytearray()
        for i in range(block_count):
            block = new_data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
            if len(block) != BLOCK_SIZE:
                self.logger.error(f"Invalid block size for block {i}: {len(block)} bytes, expected {BLOCK_SIZE}")
                raise fuse.FuseOSError(errno.EIO)
            # Get block number for nonce.
            block_number = write_offset + i
            # Create a unique identifier from the file path using SHA-256.
            path_hash = hashlib.sha256(path.encode('utf-8')).digest()
            # Generate nonce: 8 bytes block_number, 2 bytes path_id, 2 bytes random.
            nonce = struct.pack('!Q', block_number) + path_hash[:2] + os.urandom(2)
            if nonce == b'\x00' * NONCE_SIZE:
                self.logger.error("Generated zero nonce, which is invalid")
                raise fuse.FuseOSError(errno.EIO)
            block_length = block_lengths[i]
            serialized_block = self._encrypt_block(block, block_length, nonce)
            serialized_data.extend(serialized_block)
        del new_data
        try:
            self.logger.debug(f"Writing {len(serialized_data)} bytes at offset {write_offset}")
            if len(serialized_data) != block_count * BLOCK_WITH_METADATA_SIZE:
                self.logger.error(f"Invalid serialized data size: {len(serialized_data)}, expected {block_count * BLOCK_WITH_METADATA_SIZE}")
                raise fuse.FuseOSError(errno.EIO)
            super().write(enc, bytes(serialized_data), write_offset, fh)
        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        del serialized_data
        return len(data)

    def _decrypt_blocks(self, encrypted_data, block_count, remove_padding=False):
        decrypted_data = bytearray()
        offset = 0
        blocks_processed = 0
        while offset < len(encrypted_data) and blocks_processed < block_count:
            if offset + 4 > len(encrypted_data):
                self.logger.error(f"Invalid block structure at offset {offset}, not enough data for block length")
                raise fuse.FuseOSError(errno.EIO)
            block_len = struct.unpack('!I', encrypted_data[offset:offset + 4])[0]
            unencrypted_block_len = struct.unpack('!I', encrypted_data[offset + 4:offset + 8])[0]
            offset += 8
            self.logger.debug(f"Reading block {blocks_processed} at offset {offset - 4}, block_len: {block_len}")
            if block_len != BLOCK_SIZE:
                self.logger.error(f"Invalid block length: {block_len}, expected {BLOCK_SIZE}")
                raise fuse.FuseOSError(errno.EIO)
            if offset + block_len + NONCE_SIZE + TAG_SIZE > len(encrypted_data):
                self.logger.error(f"Invalid block structure at offset {offset}, not enough data for block")
                raise fuse.FuseOSError(errno.EIO)
            block = encrypted_data[offset:offset + block_len]
            offset += block_len
            nonce = encrypted_data[offset:offset + NONCE_SIZE]
            offset += NONCE_SIZE
            tag = encrypted_data[offset:offset + TAG_SIZE]
            offset += TAG_SIZE
            self.logger.debug(f"Decrypting block_len: {block_len}, nonce: {nonce.hex()}, tag: {tag.hex()}")
            try:
                decrypted_block = self.aesgcm.decrypt(nonce, block + tag, None)
                if remove_padding:
                    decrypted_block = decrypted_block[:unencrypted_block_len]
                decrypted_data.extend(decrypted_block)
            except Exception as e:
                self.logger.error(f"Decryption failed for block {blocks_processed}: {e}")
                raise fuse.FuseOSError(errno.EIO) from e
            blocks_processed += 1
        if blocks_processed < block_count:
            self.logger.error(f"Expected {block_count} blocks, but processed {blocks_processed}")
            raise fuse.FuseOSError(errno.EIO)
        if not remove_padding:
            if len(decrypted_data) < block_count * BLOCK_SIZE:
                decrypted_data.extend(b'\x00' * (block_count * BLOCK_SIZE - len(decrypted_data)))
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
            enc = self._map_plain_to_enc(path)
        num_blocks = encrypted_size // BLOCK_WITH_METADATA_SIZE
        if encrypted_size % BLOCK_WITH_METADATA_SIZE != 0:
            self.logger.error(f"Invalid encrypted file size for {path}: {encrypted_size}, not a multiple of {BLOCK_WITH_METADATA_SIZE}")
            raise fuse.FuseOSError(errno.EIO)
        unencrypted_size = (num_blocks - 1) * BLOCK_SIZE if num_blocks > 0 else 0
        try:
            offset = (num_blocks - 1) * BLOCK_WITH_METADATA_SIZE + 4
            len_data = super().read(enc, 4, offset, None)
            unencrypted_block_len = struct.unpack('!I', len_data)[0]
            self.logger.debug(f"Last block unencrypted length: {unencrypted_block_len}")
            if unencrypted_block_len > BLOCK_SIZE:
                self.logger.error(f"Invalid unencrypted block length for last block: {unencrypted_block_len}, exceeds {BLOCK_SIZE}")
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
        needed_blocks = (length + BLOCK_SIZE - 1) // BLOCK_SIZE
        current_blocks = current_encrypted_size // BLOCK_WITH_METADATA_SIZE

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
            new_encrypted_size = needed_blocks * BLOCK_WITH_METADATA_SIZE
            super().truncate(enc, new_encrypted_size, fh)

        # Handle partial last block.
        last_block_remainder = length % BLOCK_SIZE
        if last_block_remainder != 0 and needed_blocks > 0:
            self.logger.debug(f"Adjusting last block to {last_block_remainder} bytes")
            # Read current block data.
            last_block_start_offset = (needed_blocks - 1) * BLOCK_SIZE
            current_block_data = self.read(path, BLOCK_SIZE, last_block_start_offset, fh)
            # Truncate current block.
            truncated_data = current_block_data[:last_block_remainder]
            # Write truncated block.
            self.write(path, truncated_data, last_block_start_offset, fh)

        return 0

    def chmod(self, path: str, mode: int) -> int:
        enc = self._map_plain_to_enc(path)
        return super().chmod(enc, mode)

    def chown(self, path: str, uid: int, gid: int) -> int:
        enc = self._map_plain_to_enc(path)
        return super().chown(enc, uid, gid)

    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        enc = self._map_plain_to_enc(path)
        return super().utimens(enc, times)

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs) from encrypted filesystem"""
        enc = self._map_plain_to_enc(path)
        return super().getxattr(enc, name, position)

    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs) on encrypted filesystem"""
        enc = self._map_plain_to_enc(path)
        return super().setxattr(enc, name, value, options, position)

    def listxattr(self, path: str) -> List[str]:
        """List all extended attributes from encrypted filesystem"""
        enc = self._map_plain_to_enc(path)
        return super().listxattr(enc)

    def removexattr(self, path: str, name: str) -> int:
        """Remove extended attributes from encrypted filesystem"""
        enc = self._map_plain_to_enc(path)
        return super().removexattr(enc, name)

def get_mount_point(share_site, share_name):
    mount_point = "/otpme/%s/%s" % (share_site, share_name)
    return mount_point

def prepare_mount_point(share_site, share):
    mount_point = get_mount_point(share_site, share)
    if os.path.ismount(mount_point):
        msg = "Already mounted: %s" % mount_point
        raise OTPmeException(msg)
    if not os.path.exists(mount_point):
        old_usmask = os.umask(0)
        try:
            os.makedirs(mount_point, mode=0o777, exist_ok=True)
        except FileExistsError:
            pass
        finally:
            os.umask(old_usmask)
    return mount_point

def mount_share_proc(share, mount, nodes, **kwargs):
    new_proctitle = "otpme-mount %s %s" % (share, mount)
    setproctitle.setproctitle(new_proctitle)
    msg = "Got nodes: %s" % nodes
    print(msg)
    mount_share(share, mount, nodes, **kwargs)

def mount_share(share, mount, nodes, foreground=True):
    #if config.debug_enabled:
    #    logging.basicConfig(level=logging.DEBUG)
    fsname = "OTPmeFS:/%s" % share
    logger = config.logger
    msg = "Got nodes: %s" % nodes
    print(msg)
    if share == "cryptfs":
        key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        key += b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        fuse.FUSE(EncryptedFS(key, share, logger, nodes),
                        mount,
                        foreground=foreground,
                        nothreads=True,
                        fsname=fsname,
                        )
    else:
        fuse.FUSE(OTPmeFS(share, logger, nodes=nodes),
                        mount,
                        foreground=foreground,
                        nothreads=True,
                        fsname=fsname,
                        )


def cli(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('share')
    parser.add_argument('mount')
    parser.add_argument('--nodes', dest='nodes')
    args = parser.parse_args(args)

    nodes = args.nodes.split(",")

    logging.basicConfig(level=logging.DEBUG)

    logger = config.logger
    fsname = "OTPmeFS:/%s" % args.share
    fuse.FUSE(OTPmeFS(args.share, logger, nodes=nodes),
                    args.mount,
                    foreground=True,
                    nothreads=True,
                    fsname=fsname,
                    #big_writes=True,
                    #max_read=0,
                    #max_readahead=1024000,
                    #max_write=1024000,
                    )

if __name__ == '__main__':
    cli()
