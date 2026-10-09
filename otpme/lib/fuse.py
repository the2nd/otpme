# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
import time
import stat
import threading
import hmac
import errno
import secrets
import base64
import struct
import hashlib
import subprocess
import setproctitle
from typing import List
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.register import register_module
from otpme.lib.encryption import hash_password
from otpme.lib.fscoding import encode_method_call
from otpme.lib.pinentry.pynentry import get_new_password

from otpme.lib.exceptions import *

os.environ['FUSE_LIBRARY_NAME'] = "fuse3"

import mfusepy as fuse
#from otpme.lib.third_party import mfusepy as fuse

diriv_cache = {}
filesize_cache = {}
getattr_cache = {}
getxattr_cache = {}
no_such_file_cache = {}
no_such_data_cache = {}
last_create_cache = None
last_create_cache_time = 0.0

UTIME_NOW = 1073741823
CONF_FILE = "otpmecryptfs.conf"
DIRIV_NAME = "otpmecryptfs.diriv"
LONGNAME_PREFIX = "otpmecryptfs.longname."
# A blob encrypted with the key of the share, so a mount can tell that it
# holds the key the share was written with. See EncryptedFS.verify_key().
KEY_CHECK_NAME = "otpmecryptfs.keycheck"
KEY_CHECK_MAGIC = b"OTPME-CRYPTFS-KEY-CHECK"
# The characters an encrypted name is made of (_b64e, urlsafe base64
# without the padding). Anything else was not written by this
# filesystem, see EncryptedFS.looks_like_an_encrypted_name().
ENC_NAME_CHARS = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

# We use cephfs blocksize which results in good read/write performance.
PREFERRED_BLOCK_SIZE = 4194304

register_module("otpme.lib.encryption")

def gen_diriv():
    iv = os.urandom(16)
    return iv

def read_cryptfs_settings(path):
    conf_file = os.path.join(path, CONF_FILE)
    if not os.path.exists(conf_file):
        msg = _("Cryptfs not initialized.")
        raise NotInitialized(msg)
    try:
        fd = open(conf_file, "r")
        fs_data = fd.read()
        fd.close()
    except Exception as e:
        msg = _("Failed to read cryptfs settings: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    return load_cryptfs_settings(fs_data)

def load_cryptfs_settings(fs_data):
    try:
        fs_data = json.loads(fs_data)
    except Exception as e:
        msg = _("Failed to load cryptfs settings: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    return fs_data

def write_diriv_file(path):
    """ Write the diriv of a directory on the backing store.

    The names in a directory are encrypted with a nonce worked out from
    this, so it is the one file a directory cannot be without.
    """
    diriv_file = os.path.join(path, DIRIV_NAME)
    diriv = gen_diriv()
    try:
        fd = open(diriv_file, "wb")
        fd.write(diriv)
        fd.close()
    except Exception as e:
        msg = _("Failed to write diriv file: {diriv_file}: {e}")
        msg = msg.format(diriv_file=diriv_file, e=e)
        raise OTPmeException(msg) from e
    try:
        os.chmod(diriv_file, 0o644)
    except Exception as e:
        msg = _("Failed to set diriv file permissions: {diriv_file}: {e}")
        msg = msg.format(diriv_file=diriv_file, e=e)
        raise OTPmeException(msg) from e
    return diriv

def share_holds_data(path):
    """ Whether a share holds anything but the files that describe it.

    Asked before writing one of those files, because none of them can
    be made up again for a share that already holds data. The path is
    the backing store of the share, on the node this runs on
    (share.root_dir), so this is a local directory.

    scandir and not listdir, which reads the whole directory into a
    list: the first entry that is not one of ours answers the question,
    and the root of a share can hold a great many.
    """
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.name in (CONF_FILE, DIRIV_NAME, KEY_CHECK_NAME):
                continue
            return True
    return False

def init_cryptfs(path, block_size, hash_params):
    conf_file = os.path.join(path, CONF_FILE)
    already_initialized = os.path.exists(conf_file)
    # The diriv of the root directory, on its own and before the config
    # decides anything.
    #
    # Without it the share cannot answer a single request: _load_diriv()
    # fails with EIO for every path in it. It used to be written only
    # together with the config, and the config being there was enough to
    # leave this function right away -- so once the diriv was gone
    # (on the backing store it is just a file, and a cleanup there takes
    # it along) nothing ever put it back and the share stayed dead.
    diriv_file = os.path.join(path, DIRIV_NAME)
    if not os.path.exists(diriv_file):
        # Into an empty share only. A new diriv for a share that still
        # holds files would make every name in it unfindable: readdir
        # still shows them, because a name decrypts without the diriv,
        # but a lookup builds the name from the diriv and would build a
        # different one. So that case is said out loud and left to
        # somebody who can look at it.
        if share_holds_data(path):
            msg = _("Missing diriv file: {diriv_file}")
            msg = msg.format(diriv_file=diriv_file)
            raise OTPmeException(msg)
        write_diriv_file(path)
    if already_initialized:
        msg = _("Cryptfs already initialized.")
        raise AlreadyInitialized(msg)
    # The same decision for the config file, which is what this function
    # is really about. It used to be written whenever it was missing, so
    # a share that lost it got a new one on the next mount and nobody
    # ever heard of it. The data stays readable -- block_size is not a
    # choice and the same value goes back in -- but the hash_params are
    # replaced, and those are what a master password mount makes its key
    # from. The share is then readable with the share keys of its users
    # and with nothing else, and the one thing that could have said so
    # was the file that went missing.
    if share_holds_data(path):
        msg = _("Missing cryptfs config file: {conf_file}")
        msg = msg.format(conf_file=conf_file)
        raise OTPmeException(msg)
    if not hash_params:
        # The parameters a key is made from the master password with. An
        # empty set is not "the defaults": hash_password() makes a salt
        # of its own when it gets none, so every mount with the master
        # password would arrive at a different key and whatever was
        # written under one of them is lost with it. A share without them
        # is one that was created with --no-key-gen and never took over
        # an existing directory, see data_loss_review, finding 14d.
        msg = _("Refusing to initialize cryptfs without master password parameters.")
        raise OTPmeException(msg)
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
        msg = _("Failed to init cryptfs: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    try:
        os.chmod(conf_file, 0o644)
    except Exception as e:
        msg = _("Failed to set config file permissions: {conf_file}: {e}")
        msg = msg.format(conf_file=conf_file, e=e)
        raise OTPmeException(msg) from e

# Errno a filesystem request gets while the connection to the share is
# still being established. Anything but "hang until we are connected".
NOT_CONNECTED_ERRNO = errno.ENOENT

# Connect to the share in a thread and let the filesystem requests that
# arrive meanwhile fail with NOT_CONNECTED_ERRNO instead of waiting for
# it. Set to False to connect in the calling thread again, which is what
# we did before and what the cases below still do.
BACKGROUND_CONNECT = True

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
        share_realm=None,
        hard=False,
        sotp_signing=False,
        connection_timeout=None,
        ):
        self.use_ns = True
        self.share = share
        self.share_site = share_site
        # A caller that does not name the realm means ours.
        self.share_realm = share_realm or config.realm
        self.nodes = nodes
        self.hard = hard
        self.fsd_conn = None
        # Connecting runs in its own thread, see start_connect().
        self.connect_lock = threading.Lock()
        self.connect_done = threading.Event()
        self.connect_thread = None
        self.connect_error = None
        self.connection_use_time = None
        self.connection_timeout = connection_timeout
        # Set when we dropped the connection because it was unused for
        # too long, see send().
        self.timeout_reconnect = False
        self.max_name = 255
        self.username = None
        self.key = None
        self.encrypted = False
        self.logger = logger
        self.add_share_key = False
        self.master_password = None
        self.restore_share = False
        self.sotp_signing = sotp_signing
        self.share_id = stuff.get_share_id(self.share_realm,
                                        self.share_site, self.share)
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
            # No site: the share ID carries the realm and the site.
            sotp = agent_conn.get_sotp(share=self.share_id)[1]
        except Exception as e:
            msg = _("Unable to get SOTP from agent: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg) from e
        finally:
            agent_conn.close()
        sotp_sign_method = None
        if self.sotp_signing:
            def sotp_sign_method(sotp):
                sotp_sign = stuff.sign_sotp(self.username,
                                            sotp,
                                            key_mode=None,
                                            encode=False,
                                            share=self.share_id)
                return sotp_sign
        try:
            fsd_conn = connections.get(daemon="fsd",
                                    node=node,
                                    allow_untrusted=True,
                                    username=self.username,
                                    password=sotp,
                                    sotp_sign_method=sotp_sign_method,
                                    share=self.share_id,
                                    use_ssh_agent=False,
                                    use_smartcard=False,
                                    request_token=False,
                                    encrypt_session=False,
                                    connect_timeout=3,
                                    timeout=None)
        except SOTPSigningRequired as e:
            self.sotp_signing = True
            msg = _("Error getting daemon connection: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg) from e
        except Exception as e:
            msg = _("Failed to get daemon connection: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg) from e
        return fsd_conn

    def mount_share(self, mount_args):
        mount_status, \
        mount_response_code, \
        mount_response, \
        mount_binary_data = self.fsd_conn.send(command="mount",
                                        command_args=mount_args,
                                        handle_response=False,
                                        encrypt_request=False,
                                        encode_request=False,
                                        compress_request=False)
        if mount_status:
            return True, mount_response_code, mount_response, None
        try:
            mount_message = mount_response['message']
            try_other_node = mount_response['try_other_node']
        except Exception:
            try_other_node = False
            mount_message = mount_response
        log_msg = _("Failed to mount share: {share}: {mount_message}", log=True)[1]
        log_msg = log_msg.format(share=self.share, mount_message=mount_message)
        self.logger.warning(log_msg)
        if not try_other_node:
            return False, mount_response_code, mount_response, mount_message
        return None, mount_response_code, mount_response, mount_message

    def connected(self):
        """ Whether we have a connection that is ready to use.

        connect() publishes self.fsd_conn before it mounts the share, so
        a request must not use it while the connect thread still runs.
        """
        if self.fsd_conn is None:
            return False
        with self.connect_lock:
            if self.connect_thread is None:
                return True
            if self.connect_thread.is_alive():
                return False
        return True

    def reset_key(self):
        """ Forget the share key, connect() gets it again.

        The counterpart of setup_encryption(): the encrypted filesystem
        derives more key material from the share key, and send() must be
        able to drop all of it without knowing about it.
        """
        self.key = None

    def start_connect(self, command):
        """ Start connecting to a node in the background.

        Connecting takes seconds (connect timeout per node, the mount
        that follows, retries on other nodes), and a filesystem request
        that waits for it blocks the command that triggered it. So do it
        in a thread and let the request fail fast (see send()).
        """
        with self.connect_lock:
            if self.connect_thread is not None:
                if self.connect_thread.is_alive():
                    return
            self.connect_done.clear()
            self.connect_thread = threading.Thread(target=self.connect_worker,
                                                args=(command,),
                                                daemon=True)
            self.connect_thread.start()

    def connect_worker(self, command):
        """ Run connect() and remember why it failed. """
        try:
            self.connect(command)
        except Exception as e:
            self.fsd_conn = None
            with self.connect_lock:
                self.connect_error = e
            log_msg = _("Failed to connect share: {share}: {e}", log=True)[1]
            log_msg = log_msg.format(share=self.share, e=e)
            self.logger.warning(log_msg)
        finally:
            self.connect_done.set()

    def raise_connect_error(self):
        """ Raise the error of the last connect attempt, if there was one.

        This way the request that runs into it gets the real reason (e.g.
        permission denied) instead of the generic "not connected yet".
        """
        with self.connect_lock:
            connect_error = self.connect_error
            self.connect_error = None
        if connect_error is None:
            return
        raise connect_error

    def wait_for_connection(self, command):
        """ Make sure a connection is being established.

        Returns True when we are connected. Two cases have to wait for
        it instead of failing fast:

        Encrypted shares, because connecting may run the key script,
        which asks for the password via pinentry, and pinentry needs a
        command to wait for it. On a terminal, because the shell would
        read from the tty again as soon as the request returns. And with
        a DISPLAY too, because a second pinentry started meanwhile
        cannot grab the pointer and fails.

        A write on a hard mount, because it must not fail. It waits and
        retries like it did before.

        And a reconnect after the connection timeout, because the share
        is mounted and in use: failing a request on a mount that works
        would make files that are there look gone.
        """
        block = False
        if self.encrypted:
            block = True
        if self.sotp_signing:
            block = True
        if self.hard and command == "fsop_write":
            block = True
        if self.timeout_reconnect:
            block = True
        if not BACKGROUND_CONNECT:
            block = True
        if not block:
            self.start_connect(command)
            return self.connected()
        # Connect in the calling thread, exactly like we did before the
        # connect thread was added: this is the path that may run the
        # key script, and it must behave the same as it always did.
        while True:
            if self.wait_for_connect_thread():
                return True
            self.connect(command)
            if self.connected():
                return True
            # connect() does not raise for us in the hard write case, so
            # anything we got here means the nodes were unreachable.
            time.sleep(1)

    def wait_for_connect_thread(self):
        """ Wait for a running connect thread and take over its result.

        There is only one when an earlier request went through the non
        blocking path (see start_connect()).
        """
        with self.connect_lock:
            connect_thread = self.connect_thread
        if connect_thread is None:
            return False
        if not connect_thread.is_alive():
            return self.connected()
        self.connect_done.wait()
        if self.connected():
            return True
        self.raise_connect_error()
        return False

    def connect(self, command):
        """ Connect to a node and mount the share.

        Runs in the connect thread, see start_connect().
        """
        tried_nodes = []
        nodes = self.nodes
        while True:
            remaining_nodes = list(set(nodes) - set(tried_nodes))
            if not remaining_nodes:
                raise_exception = False
                if not self.hard:
                    raise_exception = True
                if command != "fsop_write":
                    raise_exception = True
                if raise_exception:
                    raise OSError(errno.EHOSTUNREACH, _("Server unreachable"))
                break
            if self.username is None:
                try:
                    self.username = self.get_user()
                except Exception as e:
                    msg = _("Unable to get username from agent: {e}")
                    msg = msg.format(e=e)
                    raise OSError(errno.EINVAL, msg) from e
            node = secrets.choice(remaining_nodes)
            log_msg = _("Trying connection to node: {node}", log=True)[1]
            log_msg = log_msg.format(node=node)
            self.logger.info(log_msg)
            try:
                self.fsd_conn = self.get_fsd_connection(node)
            except Exception as e:
                tried_nodes.append(node)
                self.fsd_conn = None
                log_msg = _("Failed to get fsd connection: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                #config.raise_exception()
                if len(tried_nodes) == len(nodes):
                    log_msg = _("Nodes failed: {tried_nodes}", log=True)[1]
                    log_msg = log_msg.format(tried_nodes=tried_nodes)
                    self.logger.warning(log_msg)
                    raise_exception = False
                    if not self.hard:
                        raise_exception = True
                    if command != "fsop_write":
                        raise_exception = True
                    if raise_exception:
                        raise OSError(errno.EHOSTUNREACH, _("Server unreachable")) from e
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
            mount_message = self.mount_share(mount_args)
            if not mount_status:
                done = False
                if mount_status is False:
                    done = True
                if len(tried_nodes) == len(nodes):
                    done = True
                if done:
                    self.fsd_conn.close()
                    self.fsd_conn = None
                    raise_exception = False
                    if not self.hard:
                        raise_exception = True
                    if command != "fsop_write":
                        raise_exception = True
                    if raise_exception:
                        if mount_response_code == status_codes.UNKNOWN_OBJECT:
                            raise OSError(errno.ENOENT, mount_message)
                        elif mount_response_code == status_codes.PERMISSION_DENIED:
                            raise OSError(errno.EACCES, mount_message)
                        else:
                            raise OSError(errno.EINVAL, mount_message)
                time.sleep(1)
                continue
            try:
                remote_command = mount_response['command']
            except KeyError:
                remote_command = None
            if remote_command == "home_dir_enc":
                description = _("Enter new password for encrypting you home share. Use a secure password and save it in a safe place.")
                agent_conn = connections.get(daemon="agent")
                try:
                    try:
                        tty = agent_conn.get_tty()
                    except Exception:
                        tty = None
                    try:
                        display = agent_conn.get_display()
                    except Exception:
                        display = None
                finally:
                    agent_conn.close()
                if not tty and not display:
                    msg, log_msg = _("Failed to get password: No tty and no  DISPLAY", log=True)
                    self.logger.warning(log_msg)
                    self.fsd_conn.close()
                    self.fsd_conn = None
                    raise OSError(errno.EINVAL, msg)
                try:
                    password = get_new_password(description=description, tty=tty, display=display)
                except Exception as e:
                    password = None
                    log_msg = _("Failed to get password via pinentry: {e}", log=True)[1]
                    log_msg = log_msg.format(e=e)
                    self.logger.warning(log_msg)
                if not password:
                    msg = _("Failed to get password.")
                    self.fsd_conn.close()
                    self.fsd_conn = None
                    raise OSError(errno.EINVAL, msg)
                self.fsd_conn.interactive = True
                share_key_response = self.fsd_conn.gen_share_key(mount_response,
                                                                password=password)
                self.fsd_conn.interactive = False
                mount_args['enc_home_data'] = share_key_response
                mount_status, \
                mount_response_code, \
                mount_response, \
                mount_message = self.mount_share(mount_args)
                if not mount_status:
                    continue
            try:
                self.restore_share = mount_response['restore_share']
            except KeyError:
                pass
            try:
                nodes = mount_response['nodes']
                if not nodes:
                    log_msg = _("Received empty share nodes from fsd: {share}: {node}", log=True)[1]
                    log_msg = log_msg.format(share=self.share, node=node)
                    self.logger.warning(log_msg)
            except KeyError:
                nodes = None
                log_msg = _("Mount response misses nodes: {share}: {node}", log=True)[1]
                log_msg = log_msg.format(share=self.share, node=node)
                self.logger.info(log_msg)
            if nodes:
                self.nodes = nodes
            if self.encrypted:
                try:
                    block_size= mount_response['block_size']
                except KeyError as err:
                    log_msg = _("Mount response misses block size: {share}: {node}", log=True)[1]
                    log_msg = log_msg.format(share=self.share, node=node)
                    self.logger.warning(log_msg)
                    self.fsd_conn.close()
                    self.fsd_conn = None
                    tried_nodes.append(node)
                    raise OSError(errno.ENOENT, _("Missing block size")) from err
                # Set block size for encrypted fs.
                self.set_block_size(block_size)
                # What the share says its key is, if it says anything.
                # Read on every mount and not kept from an earlier one: a
                # reconnect gets the share key again, and the check that
                # goes with it comes along.
                self.key_check = mount_response.get('key_check')
                if not self.key:
                    if master_password_mount:
                        try:
                            master_password_hash_params= mount_response['master_password_hash_params']
                        except KeyError as err:
                            log_msg = _("Mount response misses master password hash parameters: {share}: {node}", log=True)[1]
                            log_msg = log_msg.format(share=self.share, node=node)
                            self.logger.warning(log_msg)
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            tried_nodes.append(node)
                            raise OSError(errno.EACCES, _("No share key received")) from err
                        try:
                            hash_data = hash_password(self.master_password,
                                                    encoding=None,
                                                    **master_password_hash_params)
                            share_key = hash_data.pop("hash")
                        except Exception as e:
                            log_msg = _("Failed to derive share key from master password: {share}: {e}", log=True)[1]
                            log_msg = log_msg.format(share=self.share, e=e)
                            self.logger.warning(log_msg)
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            tried_nodes.append(node)
                            raise OSError(errno.EACCES, _("No share key received")) from e
                    else:
                        try:
                            share_key= mount_response['share_key']
                        except KeyError as err:
                            log_msg = _("Mount response misses share key: {share}: {node}", log=True)[1]
                            log_msg = log_msg.format(share=self.share, node=node)
                            self.logger.warning(log_msg)
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            tried_nodes.append(node)
                            raise OSError(errno.EACCES, _("No share key received")) from err
                        # Decrypt share key with key script.
                        try:
                            share_key = stuff.decrypt_share_key(self.username,
                                                                share_key,
                                                                key_mode=None,
                                                                encode=False,
                                                                share=self.share_id)
                        except Exception as e:
                            log_msg = _("Failed to decrypt share key: {share}: {e}", log=True)[1]
                            log_msg = log_msg.format(share=self.share, e=e)
                            self.logger.warning(log_msg)
                            self.fsd_conn.close()
                            self.fsd_conn = None
                            tried_nodes.append(node)
                            raise OSError(errno.EACCES, _("Failed to decrypt share key")) from e
                    try:
                        self.setup_encryption(share_key)
                    except Exception as e:
                        msg, log_msg = _("Failed to setup encryption: {share}: {e}", log=True)
                        msg = msg.format(share=self.share, e=e)
                        log_msg = log_msg.format(share=self.share, e=e)
                        self.logger.warning(log_msg)
                        self.fsd_conn.close()
                        self.fsd_conn = None
                        tried_nodes.append(node)
                        raise OSError(errno.EINVAL, msg) from e
                # Get max filename length for encrypted shares.
                statfs = self.statfs(path="/")
                try:
                    self.max_name = statfs['f_namemax']
                except Exception:
                    pass
                # Before the first request, and before --add-share-key
                # would store this key for good: is it the key this share
                # was written with? A restore mount is left out, it
                # cannot be written and the repository checks its own key
                # (BackupClient.verify_key()).
                if not self.restore_share:
                    try:
                        self.verify_key()
                    except Exception:
                        self.fsd_conn.close()
                        self.fsd_conn = None
                        tried_nodes.append(node)
                        raise
            if self.connection_timeout:
                msg, log_msg = _("Share mounted: {share} ({node}) (tmo={tmo})", log=True)
                msg = msg.format(share=self.share, node=node, tmo=self.connection_timeout)
                log_msg = log_msg.format(share=self.share, node=node, tmo=self.connection_timeout)
            else:
                msg, log_msg = _("Share mounted: {share} ({node})", log=True)
                msg = msg.format(share=self.share, node=node)
                log_msg = log_msg.format(share=self.share, node=node)
            self.logger.info(log_msg)
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
                    log_msg = _("Failed to encrypt share key: {share}: {e}", log=True)[1]
                    log_msg = log_msg.format(share=self.share, e=e)
                    self.logger.warning(log_msg)
                    self.fsd_conn.close()
                    self.fsd_conn = None
                    raise OSError(errno.EACCES, _("Failed to decrypt share key")) from e
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
                    raise OSError(errno.EACCES, _("Failed to add share key."))
                self.add_share_key = False
            self.connection_use_time = time.time()
            self.timeout_reconnect = False
            break

    def send(self, command, command_args, binary_data=None):
        while True:
            if not self.connected():
                if not self.wait_for_connection(command):
                    self.raise_connect_error()
                    msg = _("Share not connected yet: {share}")
                    msg = msg.format(share=self.share)
                    raise OSError(NOT_CONNECTED_ERRNO, msg)
                continue

            if self.connection_timeout and self.connection_use_time:
                connection_age = time.time() - self.connection_use_time
                if connection_age >= self.connection_timeout:
                    log_msg = _("Dropping unused connection: {share}", log=True)[1]
                    log_msg = log_msg.format(share=self.share)
                    self.logger.info(log_msg)
                    if self.fsd_conn:
                        self.fsd_conn.close()
                    # Without this we would send the request over the
                    # connection we just closed. Dropping the reference
                    # makes connected() return False, so the loop below
                    # reconnects first.
                    self.fsd_conn = None
                    # Get the share key from the key script again.
                    self.reset_key()
                    self.connection_use_time = None
                    self.timeout_reconnect = True
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
                log_msg = _("Failed to send data: {command}: {e}", log=True)[1]
                log_msg = log_msg.format(command=command, e=e)
                self.logger.warning(log_msg)
                raise_exception = False
                if not self.hard:
                    raise_exception = True
                if command != "fsop_write":
                    raise_exception = True
                if raise_exception:
                    raise OSError(errno.EHOSTUNREACH, _("Server unreachable")) from e
                time.sleep(1)
                continue
            if response_code == status_codes.BACKUP_CONNECTION_BROKEN:
                try:
                    try_other_node = response['try_other_node']
                except:
                    try_other_node = False
                self.fsd_conn.close()
                self.fsd_conn = None
                time.sleep(1)
                if not try_other_node:
                    raise OSError(errno.EHOSTUNREACH, _("Server unreachable"))
                continue
            self.connection_use_time = time.time()
            break
        return status, response_code, response, binary_data

    def check_connection(self):
        """ Make sure the share is mounted.

        The share is mounted lazily with the first filesystem operation (see
        send()). Settings we get with the mount response (e.g. restore share,
        block size, max filename length) are needed before we can map a
        plaintext path to its encrypted counterpart. So make sure we are
        connected/mounted before using them.
        """
        if self.connected():
            return
        # Any command will do. statfs() is cheap and works for regular and
        # restore shares.
        self.statfs("/")

    def in_no_such_file_cache(self, path):
        """ Check if the given path failed with ENOENT a moment ago. """
        global no_such_file_cache
        try:
            cache_time = no_such_file_cache[path]
        except KeyError:
            return False
        cache_age = time.time() - cache_time
        if cache_age < 2:
            return True
        return False

    def add_no_such_file_cache(self, path):
        """ Remember that the given path failed with ENOENT. """
        global no_such_file_cache
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
                raise OSError(errno.ENODATA, _("No such attribute"))
        no_such_data_cache[path] = time.time()

    def invalidate_caches(self, *paths):
        """ Drop cached metadata after the given paths were modified. """
        global getattr_cache
        global getxattr_cache
        global no_such_file_cache
        global no_such_data_cache
        for path in paths:
            if not path:
                continue
            # readdir() fills getattr/getxattr cache with a snapshot of the
            # whole directory. Without dropping the entry here a file that is
            # modified after that readdir would be served from the stale
            # snapshot until the cache times out.
            getattr_cache.pop(path, None)
            getxattr_cache.pop(path, None)
            no_such_file_cache.pop(path, None)
            no_such_data_cache.pop(path, None)

    @fuse.overrides(fuse.Operations)
    def chmod(self, path: str, mode: int) -> int:
        if config.debug_enabled:
            self.logger.debug(f"chmod method called for path: {path}")
        method_data = encode_method_call(method_name="chmod",
                                        path=path,
                                        mode=mode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_chmod", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"chmod failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"chmod successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def chown(self, path: str, uid: int, gid: int) -> int:
        if config.debug_enabled:
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
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"chown failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"chown successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def create(self, path: str, mode, fi=None) -> int:
        if config.debug_enabled:
            self.logger.debug(f"create method called for path: {path}")
        method_data = encode_method_call(method_name="create",
                                        path=path,
                                        mode=mode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_create", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"create failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"create successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def destroy(self, path: str) -> None:
        if config.debug_enabled:
            self.logger.debug(f"destroy method called for path: {path}")
        # Close fsd connection.
        if self.fsd_conn:
            self.fsd_conn.close()
        # Close other connections.
        connections.close_connections()
        if config.debug_enabled:
            self.logger.debug(f"destroy completed for path: {path}")

    @fuse.overrides(fuse.Operations)
    def getattr(self, path: str, fh: Optional[int] = None):
        global getattr_cache
        if config.debug_enabled:
            self.logger.debug(f"getattr method called for path: {path}")
        try:
            getattr_cached_data = getattr_cache[path]
            cache_time = getattr_cached_data['cache_time']
            use_cache = False
            if cache_time is None:
                use_cache = True
            else:
                now = time.time()
                if (now - cache_time) <= 5:
                    use_cache = True
        except KeyError:
            use_cache = False
        if use_cache:
            try:
                response = getattr_cached_data['result']
                status = True
            except KeyError:
                status = False
                response_code = getattr_cached_data['exc']
        else:
            method_data = encode_method_call(method_name="getattr", path=path)
            command_args = {'method_data':method_data}
            status, \
            response_code, \
            response, \
            binary_data = self.send(command="fsop_getattr", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"getattr failed for path: {path}")
            if response_code == errno.ENOENT:
                self.add_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        block_size = response['st_blksize']
        blocks = response['st_blocks']
        file_size = blocks * block_size
        new_blocks = file_size // PREFERRED_BLOCK_SIZE
        response['st_blocks'] = new_blocks
        response['st_blksize'] = PREFERRED_BLOCK_SIZE
        if config.debug_enabled:
            self.logger.debug(f"getattr successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def statfs(self, path: str):
        if config.debug_enabled:
            self.logger.debug(f"statfs method called for path: {path}")
        method_data = encode_method_call(method_name="statfs", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_statfs", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"statfs failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        # Set blocksize to PREFERRED_BLOCK_SIZE to speedup tools like cp(1).
        orig_frsize = response['f_frsize']
        response['f_blocks'] = (response['f_blocks'] * orig_frsize) // PREFERRED_BLOCK_SIZE
        response['f_bfree'] = (response['f_bfree'] * orig_frsize) // PREFERRED_BLOCK_SIZE
        response['f_bavail'] = (response['f_bavail'] * orig_frsize) // PREFERRED_BLOCK_SIZE
        response['f_bsize'] = PREFERRED_BLOCK_SIZE
        response['f_frsize'] = PREFERRED_BLOCK_SIZE
        if config.debug_enabled:
            self.logger.debug(f"statfs successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def mkdir(self, path: str, mode: int) -> int:
        if config.debug_enabled:
            self.logger.debug(f"mkdir method called for path: {path}")
        method_data = encode_method_call(method_name="mkdir",
                                        path=path,
                                        mode=mode)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_mkdir", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"mkdir failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"mkdir successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        if config.debug_enabled:
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
            if config.debug_enabled:
                self.logger.debug(f"read failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"read successful for path: {path}")
        return binary_data

    @fuse.overrides(fuse.Operations)
    def open(self, path: str, flags) -> int:
        if config.debug_enabled:
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
            if config.debug_enabled:
                self.logger.debug(f"open failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"open successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def fsync(self, path: str, datasync: int, fh: int=None) -> int:
        """ Hand fsync on to the node, and wait for it.

        The base class answers 0 without doing anything, so fsync() on a
        file in a share used to report success while nothing had been
        sent anywhere. Every write is a request of its own with a status
        of its own, so the bytes are at the node -- but at the node they
        sit in its page cache, and that is what this is about.
        """
        if config.debug_enabled:
            self.logger.debug(f"fsync method called for path: {path}")
        method_data = encode_method_call(method_name="fsync",
                                        path=path,
                                        datasync=datasync)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_fsync", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"fsync failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"fsync successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def release(self, path: str, fh: int=None) -> int:
        if config.debug_enabled:
            self.logger.debug(f"release method called for path: {path}")
        method_data = encode_method_call(method_name="release", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_release", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            # Logged, not raised: the kernel calls flush on close() and
            # throws away what release answers, so raising here told
            # nobody. The log is the only place it can be seen. An
            # application that wants to know its data is safe has to
            # ask for it -- that is what fsync is for, and that one does
            # report its failure.
            self.logger.error(f"Release failed for {path}: {response}")
            return 0
        if config.debug_enabled:
            self.logger.debug(f"release successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def access(self, path: str, amode: int) -> int:
        if config.debug_enabled:
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
            if config.debug_enabled:
                self.logger.debug(f"access failed for path: {path}")
            if response_code == errno.ENOENT:
                self.add_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"access successful for path: {path}")
        return 0

    @fuse.overrides(fuse.Operations)
    def readdir(self, path: str, fh: int) -> fuse.ReadDirResult:
        global getattr_cache
        global getxattr_cache
        if config.debug_enabled:
            self.logger.debug(f"readdir method called for path: {path}")
        method_data = encode_method_call(method_name="readdir", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_readdir", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"readdir failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"readdir successful for path: {path}")
        readdir_result = response['readdir']
        getattr_cache = getattr_cache | response['getattr']
        getxattr_cache = getxattr_cache | response['getxattr']
        return readdir_result

    @fuse.overrides(fuse.Operations)
    def readlink(self, path: str) -> str:
        if config.debug_enabled:
            self.logger.debug(f"readlink method called for path: {path}")
        method_data = encode_method_call(method_name="readlink", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_readlink", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"readlink failed for path: {path}")
            if response_code == errno.ENOENT:
                self.add_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"readlink successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def rename(self, old: str, new: str) -> int:
        if config.debug_enabled:
            self.logger.debug(f"rename method called for old: {old}, new: {new}")
        method_data = encode_method_call(method_name="rename",
                                        old=old,
                                        new=new)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_rename", command_args=command_args)
        self.invalidate_caches(old, new)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"rename failed for old: {old}, new: {new}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"rename successful for old: {old}, new: {new}")
        return response

    @fuse.overrides(fuse.Operations)
    def rmdir(self, path: str) -> int:
        if config.debug_enabled:
            self.logger.debug(f"rmdir method called for path: {path}")
        method_data = encode_method_call(method_name="rmdir", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_rmdir", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"rmdir failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"rmdir successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def link(self, target: str, source: str):
        if config.debug_enabled:
            self.logger.debug(f"link method called for target: {target}, source: {source}")
        method_data = encode_method_call(method_name="link",
                                        target=target,
                                        source=source)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_link", command_args=command_args)
        self.invalidate_caches(target, source)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"link failed for target: {target}, source: {source}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"link successful for target: {target}, source: {source}")
        return response

    @fuse.overrides(fuse.Operations)
    def symlink(self, target: str, source: str) -> int:
        if config.debug_enabled:
            self.logger.debug(f"symlink method called for target: {target}, source: {source}")
        method_data = encode_method_call(method_name="symlink",
                                        target=target,
                                        source=source)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_symlink", command_args=command_args)
        self.invalidate_caches(target, source)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"symlink failed for target: {target}, source: {source}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"symlink successful for target: {target}, source: {source}")
        return response

    @fuse.overrides(fuse.Operations)
    def truncate(self, path: str, length: int, fh: Optional[int] = None) -> int:
        if config.debug_enabled:
            self.logger.debug(f"truncate method called for path: {path}")
        method_data = encode_method_call(method_name="truncate",
                                        path=path,
                                        length=length)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_truncate", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"truncate failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"truncate successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def unlink(self, path: str) -> int:
        if config.debug_enabled:
            self.logger.debug(f"unlink method called for path: {path}")
        method_data = encode_method_call(method_name="unlink", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_unlink", command_args=command_args)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"unlink failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"unlink successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def utimens(self, path: str, times: Optional[tuple[int, int]] = None) -> int:
        if config.debug_enabled:
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
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"utimens failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"utimens successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        if config.debug_enabled:
            self.logger.debug(f"write method called for path: {path}")
        method_data = encode_method_call(method_name="write", path=path, offset=offset)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_write", command_args=command_args, binary_data=data)
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"write failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"write successful for path: {path}")
        return response

    def exists(self, path: str):
        if config.debug_enabled:
            self.logger.debug(f"exists method called for path: {path}")
        method_data = encode_method_call(method_name="exists", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_exists", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"exists failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"exists successful for path: {path}")
        return response

    def get_mtime(self, path: str):
        if config.debug_enabled:
            self.logger.debug(f"get_mtime method called for path: {path}")
        method_data = encode_method_call(method_name="get_mtime", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_get_mtime", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"get_mtime failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"get_mtime successful for path: {path}")
        return response

    def get_ctime(self, path: str):
        if config.debug_enabled:
            self.logger.debug(f"get_ctime method called for path: {path}")
        method_data = encode_method_call(method_name="get_ctime", path=path)
        command_args = {'method_data':method_data}
        status, \
        response_code, \
        response, \
        binary_data = self.send(command="fsop_get_ctime", command_args=command_args)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"get_ctime failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"get_ctime successful for path: {path}")
        return response

    @fuse.overrides(fuse.Operations)
    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """Get extended attributes (including POSIX ACLs)"""
        global getxattr_cache
        if config.debug_enabled:
            self.logger.debug(f"getxattr method called for path: {path}")
        try:
            getxattr_cached_data = getxattr_cache[path][name]
            cache_time = getxattr_cached_data['cache_time']
            use_cache = False
            if cache_time is None:
                use_cache = True
            else:
                now = time.time()
                if (now - cache_time) <= 5:
                    use_cache = True
        except KeyError:
            use_cache = False
        if use_cache:
            try:
                binary_data = bytes.fromhex(getxattr_cached_data['result'])
                response = "getxattr data."
                status = True
            except KeyError:
                status = False
                binary_data = None
                response = "getxattr failed."
                response_code = getxattr_cached_data['exc']
        else:
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
            if config.debug_enabled:
                self.logger.debug(f"getxattr failed for path: {path}")
            if response_code == errno.ENOENT:
                self.add_no_such_file_cache(path)
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
            self.logger.debug(f"getxattr successful for path: {path}")
        return binary_data if binary_data else response

    @fuse.overrides(fuse.Operations)
    def setxattr(self, path: str, name: str, value: bytes, options: int, position: int = 0) -> int:
        """Set extended attributes (including POSIX ACLs)"""
        if config.debug_enabled:
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
        self.invalidate_caches(path)
        if status is not True:
            if config.debug_enabled:
                self.logger.debug(f"setxattr failed for path: {path}")
            raise fuse.FuseOSError(response_code)
        if config.debug_enabled:
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
        self.invalidate_caches(path)
        if status is not True:
            raise fuse.FuseOSError(response_code)
        return response


# NOTE: This class was written with help from Grok, ChatGPT and claude code.
#       Especially the block size and offsite calculations were written by AI.
#       I checked them and they seem to work. But if someone with more skills
#       in writing block based FUSE filesystems could have a look at them would
#       be great!
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
        self.aesgcm = None
        self.aesgcm_names = None
        self.add_share_key = add_share_key
        # The key check of the share, as the mount handed it over. None
        # where the share has none yet, or where the node is too old to
        # know about it. See verify_key().
        self.key_check = None
        self.master_password = master_password
        self.block_size = 4096
        self.nonce_size = 12
        self.tag_size = 16
        self.metadata_size = 4 + 4 + self.nonce_size + self.tag_size
        self.block_with_metadata_size = self.block_size + self.metadata_size
        self.max_name = 255
        self.null_block = b'\x00' * self.block_size
        #self._read_file_size_cache = {}

    def set_block_size(self, block_size):
        self.block_size = block_size
        self.block_with_metadata_size = self.block_size + self.metadata_size
        self.null_block = b'\x00' * self.block_size

    def reset_key(self):
        """ Forget the share key and everything derived from it. """
        super().reset_key()
        self.name_key = None
        self.content_key = None
        self.aesgcm = None
        self.aesgcm_names = None

    def setup_encryption(self, key):
        key_len = len(key)
        if key_len not in (16, 24, 32):
            raise ValueError(_("Key must be 16, 24 or 32 bytes."))
        self.key = key
        hkdf_len = key_len * 2
        hkdf = HKDF(algorithm=hashes.SHA256(), length=hkdf_len, salt=None, info=b"otpmefs-keys")
        okm = hkdf.derive(self.key)
        self.content_key = okm[:key_len]
        self.name_key = okm[key_len:key_len * 2]
        self.aesgcm = AESGCM(self.content_key)
        self.aesgcm_names = AESGCM(self.name_key)

    def key_check_plaintext(self, diriv):
        """ What the key check of this share has to decrypt to.

        The diriv of the share root is in it, so the blob belongs to this
        share and not merely to this key -- one share key can serve more
        than one share, and a blob copied from another one would
        otherwise pass.
        """
        return KEY_CHECK_MAGIC + b"\n" + diriv

    def build_key_check(self, diriv):
        """ A key check for this share, made with the key we hold. """
        nonce = os.urandom(self.nonce_size)
        plain = self.key_check_plaintext(diriv)
        return nonce + self.aesgcm.encrypt(nonce, plain, None)

    def looks_like_an_encrypted_name(self, fs_name):
        """ Whether this name could be one this filesystem wrote.

        Every name it writes goes through _encrypt_name_blob(), so it is
        urlsafe base64 of at least a nonce, one byte and a tag -- or it
        is too long for that and becomes a name with LONGNAME_PREFIX.

        Anything else was put there by somebody else, and a share root is
        a place where that happens: it is the mount point of the storage,
        so a lost+found or a README of the admin may well sit in it.
        Those say nothing about a key, in either direction.
        """
        if fs_name.startswith(LONGNAME_PREFIX):
            return True
        shortest = self._b64e(b"\x00" * (self.nonce_size + 1 + self.tag_size))
        if len(fs_name) < len(shortest):
            return False
        return set(fs_name) <= ENC_NAME_CHARS

    def key_belongs_to_this_share(self):
        """ Whether the key we hold reads what the share root holds.

        For a share that has no key check yet, and only for that: it
        decides whether we may write one. A wrong key must not be the one
        that writes it, or it would take the share over and lock the
        right key out for good.

        Asked of the names, because they are encrypted with key material
        of the same share key (setup_encryption) and under AES-GCM, so a
        name that decrypts is one that was written with our key.

        A share with nothing of ours in it is a yes: there is nothing our
        key could fail to belong to. That covers an empty share, the
        files that carry the share itself, and whatever else lies in the
        share root without this filesystem having written it. A name too
        long to be one is read out of the file beside it, which
        _from_fs_name() does for us.
        """
        entries = super().readdir("/", None)
        ours = 0
        for entry in entries:
            if entry in (".", "..", CONF_FILE, DIRIV_NAME, KEY_CHECK_NAME):
                continue
            if not self.looks_like_an_encrypted_name(entry):
                continue
            ours += 1
            if self._from_fs_name("/", entry) is not None:
                return True
        if ours:
            return False
        return True

    def verify_key(self):
        """ Make sure we hold the key the share was written with.

        A wrong key is not noticed by itself. Reading fails with EIO on
        every block, which is loud, but writing is not: a whole block and
        a new file need nothing of what is there, so they are written
        with the wrong key and sit in the share next to data nobody can
        read together with them. See data_loss_review, finding 14.

        So the share keeps a blob encrypted with its key. AES-GCM
        authenticates, which makes decrypting it at all the proof; the
        plaintext is compared as well, to also catch a blob that was
        carried over from another share.

        A share that has none yet gets one, but only where the key has
        shown that it belongs to the share -- see
        key_belongs_to_this_share(). That is what makes this safe to turn
        on for shares that are already in use.

        Raises OSError(EACCES) where the key is not the right one, which
        ends the mount before a single request is served.
        """
        diriv = self._load_diriv("/")
        if self.key_check:
            try:
                blob = bytes.fromhex(self.key_check)
                nonce = blob[:self.nonce_size]
                got = self.aesgcm.decrypt(nonce, blob[self.nonce_size:], None)
            except Exception as e:
                msg, log_msg = _("Wrong key for share: {share}", log=True)
                msg = msg.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
                raise OSError(errno.EACCES, msg) from e
            if got != self.key_check_plaintext(diriv):
                msg, log_msg = _("Key check of another share: {share}", log=True)
                msg = msg.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
                raise OSError(errno.EACCES, msg)
            return
        if not self.key_belongs_to_this_share():
            msg, log_msg = _("Nothing in this share reads with the key we got, so it is either the wrong key or the share holds data of one: {share}", log=True)
            msg = msg.format(share=self.share)
            log_msg = log_msg.format(share=self.share)
            self.logger.warning(log_msg)
            raise OSError(errno.EACCES, msg)
        self.write_key_check(self.build_key_check(diriv))

    def write_key_check(self, blob):
        """ Leave a key check in a share that had none.

        A share that stays without one is not a failed mount: nothing is
        worse than before, and the next mount with a key that does not
        belong to the share is still turned away by the names. A read
        only share is the ordinary case for it.
        """
        command_args = {'key_check':blob.hex()}
        try:
            status, \
            _unused_code, \
            response, \
            _unused_binary = self.fsd_conn.send(command="set_key_check",
                                            command_args=command_args,
                                            handle_response=False,
                                            encrypt_request=False,
                                            encode_request=False,
                                            compress_request=False)
        except Exception as e:
            status = False
            response = str(e)
        if status is not True:
            log_msg = _("Failed to store key check: {share}: {response}", log=True)[1]
            log_msg = log_msg.format(share=self.share, response=response)
            self.logger.warning(log_msg)
            return
        self.key_check = blob.hex()

    def check_restore_share(self, path):
        if not self.restore_share:
            return False
        if path != "/":
            return False
        return True

    def _b64e(self, b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

    def _b64d(self, s: str) -> bytes:
        pad = '=' * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s + pad)

    def _diriv_path(self, enc_dir_path: str) -> str:
        return os.path.join(enc_dir_path, DIRIV_NAME)

    def _create_diriv(self, enc_dir_path: str, iv: bytes=None) -> bytes:
        """ Write the diriv of a directory.

        <iv> is for putting a known one back, which rmdir() does when it
        took the diriv away and then could not remove the directory. A
        directory without its diriv is a directory nobody can look up a
        name in any more, see data_loss_review, finding 9.
        """
        diriv_file = self._diriv_path(enc_dir_path)
        if super().exists(diriv_file):
            return
        try:
            super().create(diriv_file, 0o664, None)
        except Exception as e:
            # Somebody else got there first, which the exists() above
            # cannot rule out. Only logged: a real reason to fail --
            # no room, read only -- comes back from the write below,
            # and that one is not swallowed.
            self.logger.debug(f"Could not create {diriv_file}: {e}")
        if iv is None:
            iv = gen_diriv()
        super().truncate(diriv_file, 0, None)
        super().write(diriv_file, iv, 0, None)
        return iv

    def _load_diriv(self, enc_dir_path: str, use_cache=False) -> bytes:
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
        try:
            diriv = super().read(diriv_file, 16, 0, None)
        except Exception as e:
            # Said out loud with the name of the file. Without it every
            # request for a path in this directory fails, and all the
            # caller saw was a read that did not work.
            self.logger.error(f"Failed to read diriv file {diriv_file}: {e}")
            raise
        # Make sure diriv file is closed and not re-read old diriv from still open fh.
        super().release(diriv_file)
        if not diriv or len(diriv) != 16:
            self.logger.error(f"Invalid diriv file {diriv_file}: {len(diriv) if diriv else 0} bytes, want 16")
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
        if fs_name in (DIRIV_NAME, KEY_CHECK_NAME):
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
        # Mapping depends on mount settings (e.g. self.restore_share). Without
        # an established connection they are still at their defaults which
        # would result in a wrong (e.g. encrypted snapshot dir) path.
        self.check_connection()
        comps = self._split_components(plain_path)
        enc_parts = []
        enc_dir = '/'
        counter = 0
        for name in comps:
            if self.restore_share:
                counter += 1
            if counter == 1:
                enc_name = name
            else:
                enc_name = self._to_fs_name(enc_dir, name, use_diriv_cache=use_diriv_cache)
            enc_parts.append(enc_name)
            enc_dir = self._join_enc(enc_parts)
        enc_path = self._join_enc(enc_parts)
        return enc_path

    @staticmethod
    def block_aad(block_index, unencrypted_block_len):
        """ What a record is tied to besides its own bytes.

        AES-GCM proves that a block was encrypted with our key and not
        changed since. On its own that is all it proves -- not where the
        block belongs. With no additional data, somebody who can reach
        the backing store and has no key at all can swap two records
        inside a file, copy a record from one file over the same place
        in another (one key per share), or put an older copy of a record
        back. Everything decrypts, nothing complains.

        So the position of the block and the length it says it holds go
        in here. The length matters on its own: it is in the clear in
        the record, and the size of the file is worked out from the one
        in the last record -- unbound, it can be changed to cut a file
        off or stretch it.

        The path is deliberately not in here. It would tie every record
        to the name of its file, and then a rename would have to
        re-encrypt the whole file. What that leaves open is noted in
        data_loss_review, finding 12.

        Pure, so it can be driven without a share, see
        tests/unit/test_encrypted_block_aad.py.
        """
        return struct.pack('!QI', block_index, unencrypted_block_len)

    def _encrypt_block(self, block, unencrypted_block_len, nonce, block_index):
        if config.debug_enabled:
            self.logger.debug(f"Encrypting block of size {len(block)} with nonce {nonce.hex()}")
        try:
            aad = self.block_aad(block_index, unencrypted_block_len)
            ciphertext = self.aesgcm.encrypt(nonce, block, aad)
            tag = ciphertext[-self.tag_size:]
            encrypted_block = ciphertext[:-self.tag_size]
            block_len = len(encrypted_block)
            if block_len != self.block_size:
                self.logger.error(f"Encrypted block size invalid: {block_len}, expected {self.block_size}")
                raise fuse.FuseOSError(errno.EIO)
            if config.debug_enabled:
                self.logger.debug(f"Encrypted block size: {block_len}, tag: {tag.hex()}")
            serialized_block = (
                struct.pack('!I', block_len) +
                struct.pack('!I', unencrypted_block_len) +
                encrypted_block +
                nonce +
                tag
            )
            return serialized_block
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e

    def _decrypt_blocks(self, encrypted_data, block_count, start_block=0):
        """ <start_block> is the index of the first block in the file.

        It is part of what each record is tied to, see block_aad(), so a
        record that was moved somewhere else does not decrypt any more.
        """
        mv = memoryview(encrypted_data)
        data_len = len(encrypted_data)
        decrypted_data = bytearray(block_count * self.block_size)
        offset = 0
        dec_offset = 0
        blocks_processed = 0
        while offset < data_len and blocks_processed < block_count:
            block_index = start_block + blocks_processed
            block_len = struct.unpack('!I', mv[offset:offset + 4])[0]
            if block_len == 0:
                block = bytes(mv[offset + 8:offset + 8 + self.block_size])
                block_len = len(block)
                if block == self.null_block:
                    decrypted_data[dec_offset:dec_offset + block_len] = block
                    dec_offset += block_len
                    offset += 8 + block_len + self.nonce_size + self.tag_size
                    blocks_processed += 1
                    continue
                log_msg = _("Found invalid block without block len that is not a null block.", log=True)[1]
                self.logger.error(log_msg)
                raise fuse.FuseOSError(errno.EIO)
            # The length the record says it holds. It goes into the
            # additional data, so it cannot be changed on its own.
            unencrypted_block_len = struct.unpack('!I', mv[offset + 4:offset + 8])[0]
            # Add block_len and unencrypted_block_len to offset.
            offset += 8
            if config.debug_enabled:
                self.logger.debug(f"Reading block {blocks_processed} at offset {offset - 4}, block_len: {block_len}")
            if block_len != self.block_size:
                self.logger.error(f"Invalid block length: {block_len}, expected {self.block_size}")
                raise fuse.FuseOSError(errno.EIO)
            if offset + block_len + self.nonce_size + self.tag_size > data_len:
                self.logger.error(f"Invalid block structure at offset {offset}, not enough data for block")
                raise fuse.FuseOSError(errno.EIO)
            block = bytes(mv[offset:offset + block_len])
            offset += block_len
            nonce = bytes(mv[offset:offset + self.nonce_size])
            offset += self.nonce_size
            tag = bytes(mv[offset:offset + self.tag_size])
            offset += self.tag_size
            if config.debug_enabled:
                self.logger.debug(f"Decrypting block_len: {block_len}, nonce: {nonce.hex()}, tag: {tag.hex()}")
            try:
                aad = self.block_aad(block_index, unencrypted_block_len)
                decrypted_block = self.aesgcm.decrypt(nonce, block + tag, aad)
                decrypted_data[dec_offset:dec_offset + len(decrypted_block)] = decrypted_block
                dec_offset += len(decrypted_block)
            except Exception as e:
                self.logger.error(f"Decryption failed for block {block_index}: {e}")
                raise fuse.FuseOSError(errno.EIO) from e
            blocks_processed += 1
        if blocks_processed < block_count:
            self.logger.error(f"Expected {block_count} blocks, but processed {blocks_processed}")
            raise fuse.FuseOSError(errno.EIO)
        return bytes(decrypted_data)

    #def _decrypt_blocks(self, encrypted_data, block_count):
    #    decrypted_data = bytearray()
    #    offset = 0
    #    blocks_processed = 0
    #    while offset < len(encrypted_data) and blocks_processed < block_count:
    #        block_len = struct.unpack('!I', encrypted_data[offset:offset + 4])[0]
    #        if block_len == 0:
    #            block = encrypted_data[offset + 8:offset + 8 + self.block_size]
    #            block_len = len(block)
    #            if block == self.null_block:
    #                decrypted_data.extend(block)
    #                offset += 8
    #                offset += block_len
    #                offset += self.nonce_size
    #                offset += self.tag_size
    #                blocks_processed += 1
    #                continue
    #            log_msg = _("Found invalid block without block len that is not a null block.", log=True)[1]
    #            self.logger.error(log_msg)
    #            raise fuse.FuseOSError(errno.EIO)
    #        # Add block_len and unencrypted_block_len to offset.
    #        offset += 8
    #        if config.debug_enabled:
    #            self.logger.debug(f"Reading block {blocks_processed} at offset {offset - 4}, block_len: {block_len}")
    #        if block_len != self.block_size:
    #            self.logger.error(f"Invalid block length: {block_len}, expected {self.block_size}")
    #            raise fuse.FuseOSError(errno.EIO)
    #        if offset + block_len + self.nonce_size + self.tag_size > len(encrypted_data):
    #            self.logger.error(f"Invalid block structure at offset {offset}, not enough data for block")
    #            raise fuse.FuseOSError(errno.EIO)
    #        block = encrypted_data[offset:offset + block_len]
    #        offset += block_len
    #        nonce = encrypted_data[offset:offset + self.nonce_size]
    #        offset += self.nonce_size
    #        tag = encrypted_data[offset:offset + self.tag_size]
    #        offset += self.tag_size
    #        if config.debug_enabled:
    #            self.logger.debug(f"Decrypting block_len: {block_len}, nonce: {nonce.hex()}, tag: {tag.hex()}")
    #        try:
    #            decrypted_block = self.aesgcm.decrypt(nonce, block + tag, None)
    #            decrypted_data.extend(decrypted_block)
    #        except Exception as e:
    #            self.logger.error(f"Decryption failed for block {blocks_processed}: {e}")
    #            raise fuse.FuseOSError(errno.EIO) from e
    #        blocks_processed += 1
    #    if blocks_processed < block_count:
    #        self.logger.error(f"Expected {block_count} blocks, but processed {blocks_processed}")
    #        raise fuse.FuseOSError(errno.EIO)
    #    if len(decrypted_data) < block_count * self.block_size:
    #        decrypted_data.extend(b'\x00' * (block_count * self.block_size - len(decrypted_data)))
    #    return bytes(decrypted_data)

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
        #self._read_file_size_cache.pop(enc, None)
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
        except Exception:
            last_create_cache = None
            last_create_cache_time = 0.0
            raise
        # A name that was there before and is new again, so what we
        # worked out about the old one says nothing about this one.
        self.invalidate_size_cache(path)
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
        except Exception:
            if not use_diriv_cache:
                raise
            return self.mkdir(path, mode, use_diriv_cache=False)
        # Create diriv for new directory.
        #
        # Without it the directory is useless: every lookup of a name in
        # it fails with EIO, and a diriv written later does not bring
        # back names that were encrypted with the first one. So if it
        # cannot be written, the directory goes again -- better no
        # directory than one that cannot be repaired. See
        # data_loss_review, finding 9.
        try:
            self._create_diriv(enc_path)
        except Exception:
            try:
                super().rmdir(enc_path)
            except Exception as e:
                self.logger.error(f"Failed to remove {path} again after its diriv could not be written: {e}")
            raise
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
        #
        # It has to go before the rmdir: a directory with a file in it
        # cannot be removed. So it is read first and put back if the
        # rmdir does not happen -- a directory without its diriv is a
        # directory nobody can look up a name in any more, and the names
        # already in it stay unreachable even after a new diriv, see
        # data_loss_review, finding 9.
        removed_diriv = None
        if sorted(empty_dir_entries) == sorted(dir_entries):
            # Read, not taken from the cache: this is the copy that may
            # have to go back. And a directory whose diriv cannot be
            # read is removed all the same -- that is the one case where
            # there is nothing left to protect, and refusing it would
            # leave no way to clean such a directory up.
            try:
                removed_diriv = self._load_diriv(enc, use_cache=False)
            except Exception as e:
                self.logger.warning(f"No diriv to keep for {path}: {e}")
            diriv_path = self._diriv_path(enc)
            super().unlink(diriv_path)
            # The diriv of the directory being removed, not the one of
            # its parent: a later directory of the same name would get a
            # new diriv while this mount still answered with the old one
            # from the cache.
            diriv_cache.pop(enc, None)
            diriv_cache.pop(enc_dir_path, None)
        last_create_cache = None
        last_create_cache_time = 0.0
        try:
            result = super().rmdir(enc)
        except Exception:
            if removed_diriv is not None:
                try:
                    self._create_diriv(enc, iv=removed_diriv)
                except Exception as e:
                    self.logger.error(f"Failed to put the diriv of {path} back: {e}")
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
        # What has to go with the entry, worked out before anything is
        # removed. A symlink whose target is a long name keeps the name
        # in a helper file next to it, and that has to be read off the
        # link while the link is still there.
        helpers = []
        st_info = super().getattr(enc)
        if stat.S_ISLNK(st_info['st_mode']):
            link_target = super().readlink(enc)
            if link_target.startswith(LONGNAME_PREFIX):
                target_longname_file = f"{link_target}.name"
                enc_old_parent = os.path.dirname(enc)
                helpers.append(os.path.join(enc_old_parent,
                                        target_longname_file))
        if os.path.basename(enc).startswith(LONGNAME_PREFIX):
            helpers.append(enc + ".name")
        try:
            result = super().unlink(enc)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.unlink(path, use_diriv_cache=False)
        # Only now, and this order is the whole point: an entry whose
        # name helper is gone cannot be resolved any more --
        # _from_fs_name() answers None, readdir() leaves it out and no
        # lookup finds it. Removing the helper first meant that an
        # unlink which then failed left the data there with no way to
        # reach it. A helper left over the other way round is harmless:
        # it is skipped in readdir and the next entry of that name
        # writes it again.
        for helper in helpers:
            try:
                super().unlink(helper)
            except Exception as e:
                self.logger.warning(f"Failed to remove longname helper {helper}: {e}")
        self.invalidate_size_cache(path)
        return result

    def rename(self, old: str, new: str) -> int:
        enc_old = self._map_plain_to_enc(old)
        new_parent = os.path.dirname(new) if new != '/' else '/'
        new_name = os.path.basename(new)
        enc_new_parent = self._map_plain_to_enc(new_parent)
        # Handle longname symlinks. Read off the link now, moved after
        # the entry: moving it first left the symlink pointing at a
        # target whose name was no longer resolvable whenever the
        # rename below failed.
        target_helper = None
        st_info = super().getattr(enc_old)
        if stat.S_ISLNK(st_info['st_mode']):
            link_target = super().readlink(enc_old)
            if link_target.startswith(LONGNAME_PREFIX):
                target_longname_file = f"{link_target}.name"
                enc_old_parent = os.path.dirname(enc_old)
                target_helper = (
                        os.path.join(enc_old_parent, target_longname_file),
                        os.path.join(enc_new_parent, target_longname_file),
                        )
        enc_new_name = self._to_fs_name(enc_new_parent,
                                        new_name,
                                        create_longname=True)
        enc_new = enc_new_parent.rstrip('/') + '/' + enc_new_name if enc_new_parent != '/' else '/' + enc_new_name
        try:
            result = super().rename(enc_old, enc_new)
        except Exception:
            enc_new_file = os.path.basename(enc_new)
            if enc_new_file.startswith(LONGNAME_PREFIX):
                longname_file = enc_new + ".name"
                super().unlink(longname_file)
            raise
        if target_helper is not None and target_helper[0] != target_helper[1]:
            try:
                super().rename(target_helper[0], target_helper[1])
            except Exception as e:
                self.logger.error(f"Failed to move longname helper of the link target to {new}: {e}")
        enc_old_file = os.path.basename(enc_old)
        if enc_old_file.startswith(LONGNAME_PREFIX):
            longname_file = enc_old + ".name"
            super().unlink(longname_file)
        # Both ends: the old name holds nothing any more, and what the
        # new one held before is gone.
        self.invalidate_size_cache(old, new)
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
                enc_source_longname_file = f"{enc_source}.name"
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
                enc_target_longname_file = f"{enc_target}.name"
                super().unlink(enc_target_longname_file)
            if enc_source.startswith(LONGNAME_PREFIX):
                enc_source_longname_file = f"{enc_source}.name"
                super().unlink(enc_source_longname_file)
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            # On ENOENT error retry withouth diriv cache.
            return self.symlink(target, source, use_diriv_cache=False)

    def readlink(self, path: str, use_diriv_cache: bool=True) -> str:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        # A retry with a re-read diriv only makes sense if we did not already
        # know that the encrypted path is missing. This must be checked before
        # the request because the failing request adds the path to the cache.
        known_missing = self.in_no_such_file_cache(enc)
        try:
            result = super().readlink(enc)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            if known_missing:
                raise
            return self.readlink(path, use_diriv_cache=False)
        enc_dir_path = os.path.dirname(enc) if path != '/' else '/'
        link_clear = self._from_fs_name(enc_dir_path, result)
        return link_clear

    def access(self, path: str, amode: int, use_diriv_cache: bool=True) -> int:
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        known_missing = self.in_no_such_file_cache(enc)
        try:
            return super().access(enc, amode)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            if known_missing:
                raise
            return self.access(path, amode, use_diriv_cache=False)

    def getattr(self, path: str, fh: Optional[int] = None, use_diriv_cache: bool=True):
        global filesize_cache
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        known_missing = self.in_no_such_file_cache(enc)
        try:
            result = super().getattr(enc, fh)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            if known_missing:
                raise
            return self.getattr(path, fh, use_diriv_cache=False)

        if stat.S_ISDIR(result['st_mode']) or stat.S_ISLNK(result['st_mode']):
            if config.debug_enabled:
                self.logger.debug(f"Path {path} is a {'directory' if stat.S_ISDIR(result['st_mode']) else 'symlink'}, returning original st_size: {result['st_size']}")
            return result

        encrypted_size = result['st_size']
        if encrypted_size == 0:
            if config.debug_enabled:
                self.logger.debug(f"No data for {path}, assuming empty file")
            return result

        file_mtime = result['st_mtime']
        file_ctime = result['st_ctime']
        unencrypted_size = None
        cache_data = filesize_cache.get(path)
        # The size of the encrypted file is asked first, and the
        # timestamps only after it. A write that changes the length of a
        # file changes this one, where ctime and mtime are a float from
        # the server's stat: two writes within the same tick carry the
        # same ones, and the second was answered with the size from
        # before the first. fsx found that in eight operations -- a write
        # past the end of a file, and the file still as long as it was,
        # so everything that write had put there was unreadable.
        if cache_data is not None:
            if cache_data.get('enc_size') != encrypted_size:
                filesize_cache.pop(path, None)
                cache_data = None
        if cache_data is not None:
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
        if config.debug_enabled:
            self.logger.debug(f"Unencrypted file size for {path}: {unencrypted_size}")
        result['st_size'] = unencrypted_size
        result['st_blocks'] = unencrypted_blocks
        filesize_cache[path] = {
                                'ctime'     : file_ctime,
                                'mtime'     : file_mtime,
                                'enc_size'  : encrypted_size,
                                'size'      : unencrypted_size,
                                'result'    : result,
                                }
        return result

    def invalidate_size_cache(self, *paths) -> None:
        """ Forget the size we worked out for these files.

        The clear-text size of an encrypted file is not in its stat, it
        is worked out from the last block (_calc_unencrypted_size()), so
        it is cached -- and everything that writes has to say so here.
        OTPmeFS.invalidate_caches() cannot do it: it is handed the
        encrypted path, and this cache is keyed by the clear-text one.
        """
        global filesize_cache
        for path in paths:
            if not path:
                continue
            filesize_cache.pop(path, None)

    def readdir(self, path: str, fh: int) -> fuse.ReadDirResult:
        enc_dir = self._map_plain_to_enc(path)
        try:
            diriv_cache.pop(enc_dir)
        except KeyError:
            pass
        enc_entries = super().readdir(enc_dir, fh)
        plain = []
        for e in enc_entries:
            if self.check_restore_share(path):
                plain.append(e)
            else:
                pt = self._from_fs_name(enc_dir, e)
                if pt is None:
                    continue
                plain.append(pt)
        return plain

    def read(self, path, size, offset, fh):
        enc = self._map_plain_to_enc(path, use_diriv_cache=True)
        if config.debug_enabled:
            self.logger.debug(f"Reading {size} bytes at offset {offset} from {path}")
        start_block = offset // self.block_size
        end_block = (offset + size - 1) // self.block_size
        block_count = end_block - start_block + 1
        if config.debug_enabled:
            self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
        read_offset = start_block * self.block_with_metadata_size
        read_size = block_count * self.block_with_metadata_size
        if config.debug_enabled:
            self.logger.debug(f"Read offset: {read_offset}, read size: {read_size}")
        #try:
        #    encrypted_size = self._read_file_size_cache[enc]
        #except KeyError:
        #    encrypted_size = self._get_file_size(enc)
        #    self._read_file_size_cache[enc] = encrypted_size
        encrypted_size = self._get_file_size(enc)
        if encrypted_size == 0:
            if config.debug_enabled:
                self.logger.debug("File is empty")
            return b''
        # Only whole records are readable. A file can end in half a
        # record after a write that could not put all of its bytes
        # down, and reading into it would fail the read it is in -- so
        # the file ends, as far as reading goes, at the last complete
        # record. _calc_unencrypted_size() reports the size the same
        # way.
        encrypted_size -= encrypted_size % self.block_with_metadata_size
        if encrypted_size == 0:
            return b''
        read_size = min(read_size, encrypted_size - read_offset)
        if read_size <= 0:
            if config.debug_enabled:
                self.logger.debug("No data to read at offset")
            return b''
        try:
            encrypted_data = super().read(enc, read_size, read_offset, fh)
            if config.debug_enabled:
                self.logger.debug(f"Read {len(encrypted_data)} bytes from server")
            if len(encrypted_data) != read_size:
                self.logger.error(f"Expected {read_size} bytes, but read {len(encrypted_data)}")
                raise fuse.FuseOSError(errno.EIO)
        except Exception as e:
            self.logger.error(f"Read failed: {path}: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        decrypted_data = self._decrypt_blocks(encrypted_data, block_count,
                                            start_block=start_block)
        del encrypted_data
        data_offset = offset % self.block_size
        result = decrypted_data[data_offset:data_offset + size]
        del decrypted_data
        return result

    @staticmethod
    def patch_block(old_block, old_len, block_size, at, chunk):
        """ One block as it looks after <chunk> was written into it at
        <at>, and how much of it is then data.

        The whole block, every time: what the write does not cover is
        what was there, and a block that was not there yet is zeros --
        a file has zeros where nobody wrote, and a hole reads as zeros
        too.

        The length is the end of the write or the length it had,
        whichever is further out. That is the one number the size of the
        file is worked out from (_calc_unencrypted_size() reads it off
        the last block), so taking the end of the write for it cuts the
        file off there: writing one byte at the front of a file used to
        leave a file of one byte.

        Pure, so it can be driven without a share, see
        tests/unit/test_encrypted_block_patch.py.
        """
        block = bytearray(block_size)
        if old_block:
            have = min(len(old_block), block_size)
            block[:have] = old_block[:have]
        block[at:at + len(chunk)] = chunk
        return bytes(block), max(old_len, at + len(chunk))

    def read_block(self, enc, index, fh, enc_size=None):
        """ One whole block of an encrypted file, with its length.

        Returns (plaintext, length as it is written in the block), or
        (None, 0) where the block is not in the file.
        """
        if enc_size is None:
            enc_size = self._get_file_size(enc)
        read_offset = index * self.block_with_metadata_size
        if read_offset + self.block_with_metadata_size > enc_size:
            return None, 0
        try:
            raw = super().read(enc, self.block_with_metadata_size,
                            read_offset, fh)
        except Exception as e:
            self.logger.error(f"Failed to read block {index}: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        if len(raw) < self.block_with_metadata_size:
            self.logger.error(f"Short read of block {index}: {len(raw)} bytes")
            raise fuse.FuseOSError(errno.EIO)
        plain = self._decrypt_blocks(raw, 1, start_block=index)[:self.block_size]
        # The second of the two length fields, see _encrypt_block().
        stored_len = struct.unpack('!I', raw[4:8])[0]
        if stored_len > self.block_size:
            self.logger.error(f"Invalid block length {stored_len} in block {index}")
            raise fuse.FuseOSError(errno.EIO)
        return plain, stored_len

    def write_block_records(self, enc, path, start_block, blocks, fh):
        """ Encrypt and write consecutive blocks, each with its length.

        <blocks> is a list of (plaintext, length) in file order,
        starting at <start_block>.
        """
        write_offset = start_block * self.block_with_metadata_size
        serialized_data = bytearray()
        for counter, (block, block_length) in enumerate(blocks):
            # The nonce is all random now, and it has to be.
            #
            # It used to be eight bytes of block number, two bytes of a
            # hash of the path and two random ones. For one block of one
            # file the first ten of those never change, so 16 random
            # bits were left: overwriting the same block of the same
            # file repeated a nonce after a few hundred writes (39% at
            # 256 of them, 94% at 600). And two bytes of path hash means
            # that in a share of a few hundred files two of them share
            # it, so the same block of both files had those 16 bits and
            # nothing else between them.
            #
            # A repeated nonce under one key is the one thing AES-GCM
            # must not see: it gives away the xor of the two plaintexts
            # and, worse, the authentication key, which is what a
            # forgery is made from.
            #
            # Nothing is lost by dropping the block number from it. The
            # nonce is written into the record and read back from there,
            # it was never worked out again (see _decrypt_blocks()), so
            # it bound nothing. What the record is tied to is in the
            # additional data instead, see block_aad().
            #
            # 96 random bits is what NIST SP 800-38D asks of a random
            # nonce, good for 2**32 writes under one key.
            nonce = os.urandom(self.nonce_size)
            serialized_data.extend(self._encrypt_block(block, block_length,
                                                    nonce,
                                                    start_block + counter))
        try:
            if config.debug_enabled:
                self.logger.debug(f"Writing {len(serialized_data)} bytes at offset {write_offset}")
            if len(serialized_data) != len(blocks) * self.block_with_metadata_size:
                self.logger.error(f"Invalid serialized data size: {len(serialized_data)}, expected {len(blocks) * self.block_with_metadata_size}")
                raise fuse.FuseOSError(errno.EIO)
            # Every byte of this has to get there. A write may write
            # less than it was given -- the backing store running out
            # of room in the middle of it is the usual reason -- and
            # half a record is a record that does not decrypt. The
            # caller is told the whole write succeeded, so nobody would
            # ever learn about it.
            payload = bytes(serialized_data)
            written = 0
            while written < len(payload):
                chunk = payload if not written else payload[written:]
                count = super().write(enc, chunk, write_offset + written, fh)
                if not count:
                    self.logger.error(f"Short write at offset {write_offset + written}: nothing written of {len(chunk)} bytes")
                    raise fuse.FuseOSError(errno.EIO)
                if written or count != len(chunk):
                    self.logger.warning(f"Short write at offset {write_offset + written}: {count} of {len(chunk)} bytes, writing the rest")
                written += count
        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            raise fuse.FuseOSError(errno.EIO) from e
        finally:
            del serialized_data
        # The clear-text size is worked out from the last block, so it
        # has to be asked again now, see invalidate_size_cache().
        self.invalidate_size_cache(path)

    def write(self, path, data, offset, fh):
        if not data:
            return 0
        enc = self._map_plain_to_enc(path, use_diriv_cache=True)
        if config.debug_enabled:
            self.logger.debug(f"Writing {len(data)} bytes at offset {offset} to {path}")
        block_size = self.block_size
        start_block = offset // block_size
        end_block = (offset + len(data) - 1) // block_size
        if config.debug_enabled:
            self.logger.debug(f"Start block: {start_block}, End block: {end_block}")
        enc_size = self._get_file_size(enc)
        existing_blocks = enc_size // self.block_with_metadata_size
        blocks = []
        data_offset = 0
        for index in range(start_block, end_block + 1):
            block_start = index * block_size
            at = max(offset, block_start) - block_start
            until = min(offset + len(data), block_start + block_size) - block_start
            chunk = data[data_offset:data_offset + (until - at)]
            data_offset += len(chunk)
            old_block = None
            old_len = 0
            # Read what is there, except where the write covers the
            # whole block anyway -- a full block needs nothing of the
            # old one, and reading it would cost a round trip per block
            # of every sequential write.
            if index < existing_blocks and (at > 0 or until < block_size):
                old_block, stored_len = self.read_block(enc, index, fh,
                                                    enc_size=enc_size)
                # Only the last block of a file holds a length that is
                # not the whole block; the ones before it are full, and
                # for a block that is a hole the stored length is 0
                # while its content is zeros all the same.
                if index < existing_blocks - 1:
                    old_len = block_size
                else:
                    old_len = stored_len
            block, block_length = self.patch_block(old_block, old_len,
                                                block_size, at, chunk)
            blocks.append((block, block_length))
        self.write_block_records(enc, path, start_block, blocks, fh)
        return len(data)

    # The write() the one above replaced, kept for comparison. It wrote
    # the end of the write as the length of the last block, so a write
    # that ended inside a block cut the file off there (data_loss_review,
    # finding 1), and it filled a partial last block with the old data
    # from the front instead of from where the write ended.
    #def write(self, path, data, offset, fh):
    #    global path_hash_cache
    #    enc = self._map_plain_to_enc(path, use_diriv_cache=True)
    #    if config.debug_enabled:
    #        self.logger.debug(f"Writing {len(data)} bytes at offset {offset} to {path}")
    #    start_block = offset // self.block_size
    #    end_block = (offset + len(data) - 1) // self.block_size
    #    block_count = end_block - start_block + 1
    #    if config.debug_enabled:
    #        self.logger.debug(f"Start block: {start_block}, End block: {end_block}, Block count: {block_count}")
    #    write_offset = start_block * self.block_with_metadata_size
    #    if config.debug_enabled:
    #        self.logger.debug(f"Write offset: {write_offset}")
    #    is_first_block_partial = offset % self.block_size != 0
    #    is_last_block_partial = (offset + len(data)) % self.block_size != 0
    #    if config.debug_enabled:
    #        self.logger.debug(f"First block partial: {is_first_block_partial}, Last block partial: {is_last_block_partial}")
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
    #                if config.debug_enabled:
    #                    self.logger.debug(f"Reading block {block} at offset {read_offset}, size {read_size}")
    #                try:
    #                    encrypted_data = super().read(enc, read_size, read_offset, fh)
    #                    decrypted_data[block] = self._decrypt_blocks(encrypted_data, 1)[:self.block_size]
    #                except Exception as e:
    #                    self.logger.error(f"Failed to read block {block}: {e}")
    #                    raise fuse.FuseOSError(errno.EIO) from e
    #    # Create a unique identifier from the file path using SHA-256.
    #    try:
    #        path_hash = path_hash_cache[path]
    #    except KeyError:
    #        path_hash = hashlib.sha256(path.encode('utf-8')).digest()
    #        path_hash_cache[path] = path_hash
    #    data_offset = 0
    #    block_counter = 0
    #    serialized_data = bytearray()
    #    for i in range(start_block, end_block + 1):
    #        block = bytearray()
    #        if i == start_block and is_first_block_partial:
    #            existing_block = decrypted_data.get(i, b'\x00' * self.block_size)
    #            block_offset = offset % self.block_size
    #            block.extend(existing_block[:block_offset])
    #            data_start = data_offset
    #            data_end = min(len(data), data_start + self.block_size - block_offset)
    #            block.extend(data[data_start:data_end])
    #            block_length = len(block)
    #            data_offset = data_end
    #            if len(block) % self.block_size != 0:
    #                block.extend(b'\x00' * (self.block_size - (len(block) % self.block_size)))
    #        elif i == end_block and is_last_block_partial:
    #            existing_block = decrypted_data.get(i, b'\x00' * self.block_size)
    #            remaining_data = data[data_offset:]
    #            block.extend(remaining_data)
    #            block_length = len(remaining_data)
    #            remaining_length = self.block_size - len(remaining_data)
    #            if remaining_length > 0:
    #                block.extend(existing_block[:remaining_length])
    #        else:
    #            data_start = data_offset
    #            data_end = min(len(data), data_start + self.block_size)
    #            block.extend(data[data_start:data_end])
    #            block_length = len(data[data_start:data_end])
    #            data_offset = data_end
    #            if len(block) % self.block_size != 0:
    #                block.extend(b'\x00' * (self.block_size - (len(block) % self.block_size)))
    #        # Get block number for nonce.
    #        block_number = write_offset + block_counter
    #        # Generate nonce: 8 bytes block_number, 2 bytes path_id, 2 bytes random.
    #        nonce = struct.pack('!Q', block_number) + path_hash[:2] + os.urandom(2)
    #        serialized_block = self._encrypt_block(block, block_length, nonce)
    #        serialized_data.extend(serialized_block)
    #        block_counter += 1
    #    try:
    #        if config.debug_enabled:
    #            self.logger.debug(f"Writing {len(serialized_data)} bytes at offset {write_offset}")
    #        if len(serialized_data) != block_count * self.block_with_metadata_size:
    #            self.logger.error(f"Invalid serialized data size: {len(serialized_data)}, expected {block_count * self.block_with_metadata_size}")
    #            raise fuse.FuseOSError(errno.EIO)
    #        super().write(enc, bytes(serialized_data), write_offset, fh)
    #    except Exception as e:
    #        self.logger.error(f"Write failed: {e}")
    #        raise fuse.FuseOSError(errno.EIO) from e
    #    finally:
    #        del serialized_data
    #    #self._read_file_size_cache.pop(enc, None)
    #    return len(data)

    # And the one before that.
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

    def _get_file_size(self, enc_path):
        try:
            attrs = super().getattr(enc_path)
            if config.debug_enabled:
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
            # For restore shares file sizes are saved to the file. If the user does not
            # have permissions to the file, backupd returns the file size of the metadata file.
            if self.restore_share:
                return encrypted_size
            # A record that was left half written, which is what a write
            # that could not put all of its bytes down leaves behind. The
            # whole file used to be refused here, so one torn record at
            # the end cost every block before it as well. The complete
            # records are still readable, so the file is as long as they
            # are and the torn tail is left out of it.
            self.logger.error(f"Incomplete last block for {path}: {encrypted_size} is not a multiple of {self.block_with_metadata_size}, ignoring {encrypted_size % self.block_with_metadata_size} bytes at the end")
            if num_blocks == 0:
                return 0
        unencrypted_size = (num_blocks - 1) * self.block_size if num_blocks > 0 else 0
        try:
            offset = (num_blocks - 1) * self.block_with_metadata_size + 4
            len_data = super().read(enc, 4, offset, None)
            super().release(enc, None)
            unencrypted_block_len = struct.unpack('!I', len_data)[0]
            if config.debug_enabled:
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
        #self._read_file_size_cache.pop(enc, None)
        if config.debug_enabled:
            self.logger.debug(f"Truncating {path} to {length} bytes")

        current_encrypted_size = self._get_file_size(enc)

        # Truncate file to 0.
        if length == 0:
            if config.debug_enabled:
                self.logger.debug("Truncating file to 0 bytes")
            status = super().truncate(enc, 0, fh)
            self.invalidate_size_cache(path)
            return status

        # Pad empty file with zeros.
        if current_encrypted_size == 0:
            if config.debug_enabled:
                self.logger.debug("File is empty, creating zero-filled content")
            zero_data = b'\x00' * length
            self.write(path, zero_data, 0, fh)
            return 0

        # Calculate blocks needed after truncate.
        needed_blocks = (length + self.block_size - 1) // self.block_size
        current_blocks = current_encrypted_size // self.block_with_metadata_size

        if config.debug_enabled:
            self.logger.debug(f"Current blocks: {current_blocks}, needed blocks: {needed_blocks}")

        # File gets bigger, expand with zeros.
        current_unencrypted_size = self._calc_unencrypted_size(path, current_encrypted_size, enc)
        if length > current_unencrypted_size:
            if config.debug_enabled:
                self.logger.debug("Expanding file with zeros")
            zero_data = b'\x00' * (length - current_unencrypted_size)
            self.write(path, zero_data, current_unencrypted_size, fh)
            return 0

        # If needed blocks is 0 truncate file to 0.
        if needed_blocks == 0:
            status = super().truncate(enc, 0, fh)
            self.invalidate_size_cache(path)
            return status

        shrunk = False
        if needed_blocks < current_blocks:
            # If file should shrink, truncate to full block size.
            if config.debug_enabled:
                self.logger.debug(f"Removing blocks: from {current_blocks} to {needed_blocks}")
            new_encrypted_size = needed_blocks * self.block_with_metadata_size
            super().truncate(enc, new_encrypted_size, fh)
            self.invalidate_size_cache(path)
            shrunk = True

        # Handle partial last block.
        last_block = needed_blocks - 1
        last_block_remainder = length % self.block_size
        if last_block_remainder != 0:
            if config.debug_enabled:
                self.logger.debug(f"Adjusting last block to {last_block_remainder} bytes")
            old_block, _unused_len = self.read_block(enc, last_block, fh)
            block = bytearray(self.block_size)
            if old_block:
                block[:last_block_remainder] = old_block[:last_block_remainder]
            # The length is set here, not carried over: this is the one
            # write that makes a file smaller, so the cut away tail goes
            # and the length has to be exactly where the file now ends.
            # write() would keep the longer of the two, see patch_block().
            self.write_block_records(enc, path, last_block,
                                    [(bytes(block), last_block_remainder)],
                                    fh)
        elif shrunk:
            # The file now ends on a block boundary, so it ends with a
            # full block -- and the length in the last record is where
            # the file ends. A block that was never filled to the end
            # has to be filled now: what nobody wrote in it is a hole,
            # and a hole reads as zeros, which is what the record holds.
            # Without this a truncate to a block boundary left the file
            # as short as the last write into that block had made it.
            old_block, stored_len = self.read_block(enc, last_block, fh)
            if stored_len != self.block_size:
                if config.debug_enabled:
                    self.logger.debug(f"Filling last block to {self.block_size} bytes")
                block, block_length = self.patch_block(old_block,
                                                    self.block_size,
                                                    self.block_size, 0, b'')
                self.write_block_records(enc, path, last_block,
                                        [(block, block_length)], fh)

        return 0

    def fsync(self, path: str, datasync: int, fh: int=None,
        use_diriv_cache: bool=True) -> int:
        # A restore share answers 0: it is read only, so there is
        # nothing of ours to put on disk, and its command set does not
        # have fsync.
        if self.restore_share:
            return 0
        enc = self._map_plain_to_enc(path, use_diriv_cache=use_diriv_cache)
        try:
            return super().fsync(enc, datasync, fh)
        except Exception as e:
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            return self.fsync(path, datasync, fh, use_diriv_cache=False)

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
        known_missing = self.in_no_such_file_cache(enc)
        try:
            return super().getxattr(enc, name, position)
        except Exception as e:
            if e.errno == errno.ENODATA:
                self.check_no_such_data_cache(enc)
                raise
            if e.errno != errno.ENOENT:
                raise
            if not use_diriv_cache:
                raise
            if known_missing:
                raise
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

def get_share_realm(share_data):
    """ The realm a share belongs to, as the server named it.

    A server that does not name it yet leaves only one realm it can be:
    ours. Keeps a session that was made before the realm was part of
    the mount path mountable and unmountable. """
    try:
        share_realm = share_data['realm']
    except (TypeError, KeyError):
        share_realm = None
    if not share_realm:
        share_realm = config.realm
    return share_realm

def get_mount_point(username, share_realm, share_site, share_name):
    """ Where a share is mounted.

    The realm is part of the path: two realms may well have a site of
    the same name, and their shares would otherwise want the same
    directory. """
    mount_point = os.path.join(config.mount_root_dir,
                                username,
                                share_realm,
                                share_site,
                                share_name)
    return mount_point

def prepare_mount_point(username, share_realm, share_site, share):
    mount_point = get_mount_point(username, share_realm, share_site, share)
    if stuff.is_mounted(mount_point):
        msg = _("Already mounted: {mount_point}")
        msg = msg.format(mount_point=mount_point)
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
    counter = 0
    found_start = False
    mount_point_split = mount_point.split("/")
    for x_dir in mount_point_split:
        counter += 1
        if x_dir == username:
            found_start = True
        if not found_start:
            continue
        path = "/".join(mount_point_split[0:counter])
        filetools.set_fs_ownership(path=path, user=username, group=True)
    return mount_point

def remove_mount_dir(mount_dir):
    """ Remove one directory a mount left behind.

    An empty one: another share of the same site, or another site of the
    same realm, may still be mounted below it, and that one keeps its
    way there. """
    logger = config.logger
    if not os.path.exists(mount_dir):
        return
    try:
        if os.listdir(mount_dir):
            return
    except OSError as e:
        log_msg = _("Failed to read mountpoint dir: {mount_dir}: {error}", log=True)[1]
        log_msg = log_msg.format(mount_dir=mount_dir, error=e)
        logger.warning(log_msg)
        return
    try:
        os.rmdir(mount_dir)
    except Exception as e:
        log_msg = _("Failed to rmdir mountpoint dir: {mount_dir}: {error}", log=True)[1]
        log_msg = log_msg.format(mount_dir=mount_dir, error=e)
        logger.warning(log_msg)

def remove_mount_dirs(mountpoints):
    """ Remove what is left of a mount: the directory of its site, of
    its realm, and of the user, in that order. """
    for mount_point in mountpoints:
        site_dir = os.path.dirname(mount_point)
        realm_dir = os.path.dirname(site_dir)
        user_dir = os.path.dirname(realm_dir)
        for x_dir in (site_dir, realm_dir, user_dir):
            remove_mount_dir(x_dir)

def mount_share_proc(share, share_site, mount, nodes, encrypted, sotp_signing, **kwargs):
    logger = config.logger
    # The share ID, so two realms with a site of the same name are told
    # apart here too. kwargs and not a parameter of its own: they go to
    # mount_share() unchanged.
    share_id = stuff.get_share_id(kwargs.get('share_realm') or config.realm,
                                share_site, share)
    new_proctitle = f"otpme-mount {share_id} {mount}"
    setproctitle.setproctitle(new_proctitle)
    mount_proc = multiprocessing.start_process(name="mount",
                                            target=mount_share,
                                            target_args=(share,
                                                        share_site,
                                                        mount,
                                                        nodes,
                                                        encrypted,
                                                        sotp_signing),
                                            target_kwargs=kwargs,
                                            daemon=False,
                                            join=False)
    mount_proc.join()
    if mount_proc.exitcode != 0:
        log_msg = _("Failed to mount share: {share}", log=True)[1]
        log_msg = log_msg.format(share=share)
        logger.warning(log_msg)
        return False
    try:
        subprocess.run(["sudo", "-n", "setreadahead", mount])
    except Exception as e:
        log_msg = _("Failed to run setreadahead: {mount}: {error}", log=True)[1]
        log_msg = log_msg.format(mount=mount, error=e)
        logger.warning(log_msg)

def mount_share(share, share_site, mount, nodes, encrypted, sotp_signing,
    share_realm=None, hard=False, master_password=None, add_share_key=False,
    mount_timeout=None, foreground=True, logger=None):
    if add_share_key and not master_password:
        msg = _("Need <master_password> with <add_share_key>")
        raise OTPmeException(msg)
    #if config.debug_enabled:
    #    logging.basicConfig(level=logging.DEBUG)
    try:
        # What mount and df show, so it names the share the way the share
        # ID does: a site name is only unique within its realm.
        share_id = stuff.get_share_id(share_realm or config.realm,
                                    share_site, share)
        fsname = f"OTPmeFS:/{share_id}"
        if logger is None:
            logger = config.logger
        msg = _("Got nodes: {share}: {nodes}")
        msg = msg.format(share=share, nodes=nodes)
        logger.info(msg)
        if encrypted:
            fuse.FUSE(EncryptedFS(share,
                                share_site,
                                logger,
                                nodes,
                                share_realm=share_realm,
                                hard=hard,
                                sotp_signing=sotp_signing,
                                connection_timeout=mount_timeout,
                                master_password=master_password,
                                add_share_key=add_share_key),
                            mount,
                            foreground=foreground,
                            nothreads=True,
                            fsname=fsname,
                            )
        else:
            fuse.FUSE(OTPmeFS(share, share_site, logger, nodes=nodes,
                                share_realm=share_realm, hard=hard,
                                sotp_signing=sotp_signing,
                                connection_timeout=mount_timeout),
                            mount,
                            foreground=foreground,
                            nothreads=True,
                            fsname=fsname,
                            )
    except Exception as e:
        log_msg = _("Failed to mount share: {share}: {error}", log=True)[1]
        log_msg = log_msg.format(share=share, error=e)
        logger.warning(log_msg)
        return False
    return True
