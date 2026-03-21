# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import grp
import zlib
import errno
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.fuse import init_cryptfs
from otpme.lib.fuse import read_cryptfs_settings
from otpme.lib.fuse import load_cryptfs_settings
from otpme.lib.classes.backup import CHUNK_SIZE
from otpme.lib.classes.backup import FLAG_ZLIB
from otpme.lib.classes.backup import decrypt_block

from otpme.lib.protocols import status_codes
from otpme.lib.multiprocessing import drop_privileges
from otpme.lib.protocols.server.fs import OTPmeFsServer1

from otpme.lib.exceptions import *

filehandlers = {}
default_callback = config.get_callback()

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-fs-1.0"

blob_cache = {}

def register():
    config.register_otpme_protocol("fsd", PROTOCOL_VERSION, server=True)

class OTPmeFsP1(OTPmeFsServer1):
    """ Class that implements OTPme-fs-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "fsd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Fsd does require user authentication on client connect.
        self.require_auth = "user"
        self.require_preauth = True
        # No additional encryption for fsd.
        self.encrypt_session = False
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
        # Share mounted.
        self.mounted = False
        # Share is readonly.
        self.read_only = False
        # Share is encrypted.
        self.encrypted = False
        # Encrypted share blocksize.
        self.block_size = 4096
        # Get logger.
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
        # Share is a restore share.
        self.restore_share = False
        # Connection to backup server.
        self.backupd_conn = None
        # AES key for block decryption (set externally before FUSE read).
        self.aes_key = None
        # Call parent class init.
        OTPmeFsServer1.__init__(self, **kwargs)

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
        new_proctitle ="{proctitle} User: {username} Share: {share}"
        new_proctitle = new_proctitle.format(proctitle=self.proctitle,
                                            username=username,
                                            share=share)
        setproctitle.setproctitle(new_proctitle)

    def get_backupd_conn(self, host, backup_key=None):
        try:
            backupd_conn = connections.get("backupd",
                                        node=host,
                                        timeout=3600,
                                        auto_auth=False,
                                        auto_preauth=True,
                                        encrypt_session=False,
                                        verify_preauth=False,
                                        backup_key=backup_key,
                                        interactive=False)
        except Exception as e:
            msg = _("Failed to get backup connection: {host_name}: {e}")
            msg = msg.format(host_name=host, e=e)
            raise OTPmeException(msg)
        return backupd_conn

    def _process(self, command, command_args, binary_data):
        """ Handle fuse requests. """
        if config.use_api:
            if config.auth_token:
                self.username = config.auth_token.owner
                self.authenticated = True

        if not self.authenticated:
            message = _("Please authenticate.")
            status = status_codes.NEED_USER_AUTH
            return self.build_response(status, message)

        if self.mounted and self.root:
            try:
                response = self.process_file_command(command,
                                                command_args,
                                                binary_data)
            except UnknownCommand:
                pass
            else:
                return response
        elif self.mounted and self.restore_share:
            try:
                response = self.process_restore_command(command,
                                                    command_args,
                                                    binary_data)
            except UnknownCommand:
                pass
            else:
                return response
        # All valid commands.
        valid_commands = [
                            "mount",
                            "add_share_key",
                        ]

        # Check if we got a valid command.
        if not command in valid_commands:
            message = _("Unknown command: {command}")
            message = message.format(command=command)
            status = False
            return self.build_response(status, message)

        status = True
        if command == "mount":
            if self.mounted:
                status = False
                message = _("Share already mounted: {share}")
                message = message.format(share=self.share)
                return self.build_response(status, message)
            try:
                self.share = command_args['share']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing share.")
                return self.build_response(status, message)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=self.share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Unknown share: {share}")
                message = message.format(share=self.share)
                return self.build_response(status, message)
            share = result[0]
            self.encrypted = share.encrypted
            if share.restore_share:
                self.restore_share = True
                restore_share = backend.get_object(uuid=share.restore_share)
                if not restore_share:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Share to restore not found: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    return self.build_response(status, message)
                if not share.is_assigned_token(token_uuid=config.auth_token.uuid):
                    status = status_codes.PERMISSION_DENIED
                    message, log_msg = _("No share permissions: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    return self.build_response(status, message)
                self.encrypted = restore_share.encrypted
                # Get backup key
                backup_key = restore_share.get_config_parameter("backup_key")
                if not backup_key:
                    status = status_codes.UNKNOWN_OBJECT
                    message = _("Unable to find backup key for share: {share}")
                    message = message.format(share=self.share)
                    return self.build_response(status, message)
                self.aes_key = bytes.fromhex(backup_key)
            # Get user groups.
            default_group = stuff.get_users_default_group(self.username)
            groups = stuff.get_users_groups(self.username)
            if self.restore_share:
                host = restore_share.get_config_parameter("backup_server")
                if not host:
                    status = status_codes.UNKNOWN_OBJECT
                    message = _("Unable to find backup host for share: {share}")
                    message = message.format(share=self.share)
                    return self.build_response(status, message)
                backup_key = restore_share.get_config_parameter("backup_key")
                repo_id = f"share/{restore_share.site}/{restore_share.name}"
                self.backupd_conn = self.get_backupd_conn(host, backup_key=backup_key)
                try:
                    self.backupd_conn.mount(repo_id,
                                            username=self.username,
                                            default_group=default_group,
                                            groups=groups)
                except Exception as e:
                    status = False
                    log_msg = _("Failed to mount restore share: {share_name}: {e}", log=True)[1]
                    log_msg = log_msg.format(share_name=share.name, e=e)
                    self.logger.warning(log_msg)
                    message = _("Failed to mount restore share: {share_name}")
                    message = message.format(share_name=share.name)
                    return self.build_response(status, message)
                if self.encrypted:
                    try:
                        file_data = self.backupd_conn.read_cryptfs_settings()[1]
                    except Exception as e:
                        status = False
                        message = _("Failed to read cryptfs settings from backup server: {share_name}")
                        message = message.format(share_name=share.name)
                        log_msg = _("Failed to read cryptfs settings from backup server: {share_name}: {e}", log=True)[1]
                        log_msg = log_msg.format(share_name=share.name, e=e)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                    try:
                        file_data = file_data.decode()
                        lines = file_data.strip().split("\n")
                        chunk_hashes = [l for l in lines[2:] if l]
                        buf = b""
                        for h in chunk_hashes:
                            blob = self.backupd_conn.get_chunk(h)[1]
                            # Decrypt and decompress.
                            flag, encrypted = blob[:1], blob[1:]
                            data = decrypt_block(self.aes_key, encrypted)
                            if flag == FLAG_ZLIB:
                                data = zlib.decompress(data)
                            buf += data
                    except Exception as e:
                        status = False
                        message = _("Failed to decrypt cryptfs settings: {share_name}")
                        message = message.format(share_name=share.name)
                        log_msg = _("Failed to decrypt cryptfs settings: {share_name}: {e}", log=True)[1]
                        log_msg = log_msg.format(share_name=share.name, e=e)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                    try:
                        fs_data = load_cryptfs_settings(buf)
                    except Exception as e:
                        status = status_codes.UNKNOWN_OBJECT
                        message = _("Failed to load cryptfs settings.")
                        log_msg = _("Failed to load cryptfs settings: {e}", log=True)[1]
                        log_msg = log_msg.format(e=e)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
            else:
                if not os.path.exists(share.root_dir):
                    status = status_codes.UNKNOWN_OBJECT
                    message = _("Unknown share root dir: {share}: {root_dir}")
                    message = message.format(share=self.share, root_dir=share.root_dir)
                    return self.build_response(status, message)
                if not share.is_assigned_token(token_uuid=config.auth_token.uuid) \
                and not share.is_master_password_token(config.auth_token.rel_path):
                    status = status_codes.PERMISSION_DENIED
                    message, log_msg = _("No share permissions: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    return self.build_response(status, message)
                try:
                    self.root = os.path.realpath(share.root_dir)
                except Exception as e:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Failed to mount share: {share}", log=True)
                    message = message.format(share=share)
                    log_msg = log_msg.format(share=share)
                    log_msg = f"{log_msg}: {e}"
                    self.logger.warning(log_msg)
                    return self.build_response(status, message)
                if share.mount_script_enabled:
                    try:
                        share.run_mount_script()
                    except Exception as e:
                        status = status_codes.ERR
                        message, log_msg = _("Failed to mount share: {share}", log=True)
                        message = message.format(share=share)
                        log_msg = log_msg.format(share=share)
                        log_msg = f"{log_msg}: {e}"
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                if share.force_group_uuid is not None:
                    group = backend.get_object(uuid=share.force_group_uuid)
                    if not group:
                        status = status_codes.UNKNOWN_OBJECT
                        message = _("Unknown force group: {group_uuid}")
                        message = message.format(group_uuid=share.force_group_uuid)
                        return self.build_response(status, message)
                    try:
                        self.force_group_gid = grp.getgrnam(group.name).gr_gid
                    except:
                        status = status_codes.UNKNOWN_OBJECT
                        message = _("Force group does not exists: {group_name}")
                        message = message.format(group_name=group.name)
                        return self.build_response(status, message)
                # Get read-only attribute.
                self.read_only = share.read_only
                if share.directory_mode != "0o000":
                    os.umask(0)
                    self.directory_mode = int(share.directory_mode, 0)
                if share.create_mode != "0o000":
                    os.umask(0)
                    self.create_mode = int(share.create_mode, 0)
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
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Failed to initialize cryptfs: {share_name}", log=True)
                        message = message.format(share_name=share.name)
                        log_msg = log_msg.format(share_name=share.name)
                        log_msg = f"{log_msg}: {e}"
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                    try:
                        fs_data = read_cryptfs_settings(path=self.root)
                    except NotInitialized:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Cryptfs not initialized: {root}", log=True)
                        message = message.format(root=self.root)
                        log_msg = log_msg.format(root=self.root)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                    except Exception as e:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Failed to read cryptfs settings: {share_name}", log=True)
                        message = message.format(share_name=share.name)
                        log_msg = log_msg.format(share_name=share.name)
                        log_msg = f"{log_msg}: {e}"
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
            if self.encrypted:
                try:
                    self.block_size = fs_data['block_size']
                except KeyError:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Cryptfs misses block size: {share_name}", log=True)
                    message = message.format(share_name=share.name)
                    log_msg = log_msg.format(share_name=share.name)
                    self.logger.warning(log_msg)
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
                        message, log_msg = _("Master password mount not allowed: {token_path}", log=True)
                        message = message.format(token_path=config.auth_token.rel_path)
                        log_msg = log_msg.format(token_path=config.auth_token.rel_path)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                    try:
                        master_password_hash_params = fs_data['hash_params']
                    except KeyError:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Cryptfs misses master password hash parameters: {share_name}", log=True)
                        message = message.format(share_name=share.name)
                        log_msg = log_msg.format(share_name=share.name)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                else:
                    share_key_share = share
                    if self.restore_share:
                        share_key_share = restore_share
                    share_key = share_key_share.get_share_key(username=config.auth_user.name,
                                                            verify_acls=False)
                    if not share_key:
                        status = status_codes.PERMISSION_DENIED
                        message, log_msg = _("No share key for user: {user_name}", log=True)
                        message = message.format(user_name=config.auth_user.name)
                        log_msg = log_msg.format(user_name=config.auth_user.name)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)

            mount_result = {}
            if self.restore_share:
                share.update_last_used_time()
            else:
                share.update_last_used_time()
                # Get share node FQDNs to reply.
                share_nodes = share.get_nodes(include_pools=True,
                                            return_type="instance")
                share_node_fqdns = []
                for node in share_nodes:
                    share_node_fqdns.append(node.fqdn)
                if not self.privileges_dropped:
                    if share.force_group_uuid is not None and self.username != "root":
                        if group.name not in groups:
                            status = status_codes.PERMISSION_DENIED
                            message, log_msg = _("Force group enabled and user not in group: {group_name}", log=True)
                            message = message.format(group_name=group.name)
                            log_msg = log_msg.format(group_name=group.name)
                            self.logger.warning(log_msg)
                            return self.build_response(status, message)
                    try:
                        drop_privileges(user=self.username, group=default_group, groups=groups)
                    except Exception as e:
                        status = status_codes.PERMISSION_DENIED
                        message, log_msg = _("Failed to drop privileges: {error}", log=True)
                        message = message.format(error=e)
                        log_msg = log_msg.format(error=e)
                        self.logger.warning(log_msg)
                        return self.build_response(status, message)
                    self.privileges_dropped = True
                mount_result = {'nodes':share_node_fqdns}
            self.set_proctitle(self.username, share)
            if self.encrypted:
                if self.restore_share:
                    mount_result['restore_share'] = True
                mount_result['share_key'] = share_key
                mount_result['block_size'] = self.block_size
                mount_result['master_password_hash_params'] = master_password_hash_params
            message = mount_result
            self.mounted = True
            return self.build_response(status, message)

        elif not self.mounted:
            message = _("No share mounted.")
            status = status_codes.UNKNOWN_OBJECT
            return self.build_response(status, message)

        if command == "add_share_key":
            try:
                share_key = command_args['share_key']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Missing share key.")
                return self.build_response(status, message)
            if not self.mounted:
                message = _("No share mounted.")
                status = status_codes.UNKNOWN_OBJECT
                return self.build_response(status, message)
            if not self.encrypted:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Share not encrypted.")
                return self.build_response(status, message)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=self.share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                status = status_codes.UNKNOWN_OBJECT
                message = _("Unknown share: {share}")
                message = message.format(share=self.share)
                return self.build_response(status, message)
            share = result[0]
            if not share.is_master_password_token(config.auth_token.rel_path):
                status = status_codes.PERMISSION_DENIED
                message, log_msg = _("No share permissions: {share}", log=True)
                message = message.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            if not share_key:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Got no share key: {user_name}", log=True)
                message = message.format(user_name=config.auth_user.name)
                log_msg = log_msg.format(user_name=config.auth_user.name)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            share.add_token(token_path=config.auth_token.rel_path,
                            share_key=share_key,
                            callback=default_callback,
                            verify_acls=False)
            default_callback.write_modified_objects()
            message = _("Share key added for user: {user_name}")
            message = message.format(user_name=config.auth_user.name)
            status = True
            return self.build_response(status, message)

    def process_restore_command(self, command, command_args, binary_data=None):
        status = True
        if command == "exists":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.exists(path)
            return self.build_response(status, message)

        elif command == "get_mtime":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.get_mtime(path)
            return self.build_response(status, message)

        elif command == "get_ctime":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.get_ctime(path)
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
            status, message = self.backupd_conn.access(path, amode)
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
            status, message = self.backupd_conn.create(path, mode)
            return self.build_response(status, message)

        elif command == "getattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.getattr(path)
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
            status, message = self.backupd_conn.link(target, source)
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
            status, binary_data = self.restore_read(path, size, offset)
            message = _("File data.")
            return self.build_response(status, message, binary_data=binary_data)

        elif command == "readdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.readdir(path)
            return self.build_response(status, message)

        elif command == "readlink":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.readlink(path)
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
            status, message = self.backupd_conn.rename(old, new)
            return self.build_response(status, message)

        elif command == "statfs":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.statfs(path)
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
            status, message = self.backupd_conn.symlink(target, source)
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
            status, message = self.backupd_conn.link(target, source)
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
            status, message = self.backupd_conn.truncate(path, length)
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
            status, message = self.backupd_conn.utimens(path, times)
            return self.build_response(status, message)

        elif command == "unlink":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.unlink(path)
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
            status, message = self.backupd_conn.mkdir(path, mode)
            return self.build_response(status, message)

        elif command == "rmdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.rmdir(path)
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
            status, message = self.backupd_conn.chmod(path, mode)
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
            status, message = self.backupd_conn.chown(path, uid, gid)
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
            status, message = self.backupd_conn.write(path, binary_data, offset)
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
            status, message = self.backupd_conn.open(path, flags)
            return self.build_response(status, message)

        elif command == "release":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.release(path)
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
            status, binary_data = self.backupd_conn.getxattr(path, name, position)
            message = _("Extended attribute data.")
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
            status, message = self.backupd_conn.setxattr(path, name, value, options, position)
            return self.build_response(status, message)

        elif command == "listxattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            status, message = self.backupd_conn.listxattr(path)
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
            status, message = self.backupd_conn.removexattr(path, name)
            return self.build_response(status, message)

        else:
            msg = _("Unknown fs command: {command}")
            msg = msg.format(command=command)
            raise UnknownCommand(msg)

    def restore_read(self, path, size, offset):
        # NOTE: This method was written by claude code!
        global blob_cache
        # Cache file metadata (chunk hashes + size) per path.
        try:
            file_info = blob_cache[path]["__file_info__"]
        except KeyError:
            file_data = self.backupd_conn.read_restore_file(path)[1]
            if not file_data:
                return errno.ENOENT, None
            file_data = file_data.decode('utf-8')
            lines = file_data.strip().split("\n")
            header = lines[1].split()
            if header[0] == "HARDLINK":
                return True, b''
            if header[0] == "SYMLINK":
                return True, b''
            file_info = {
                "size": int(header[0]),
                "chunk_hashes": [l for l in lines[2:] if l],
            }
            if path not in blob_cache:
                blob_cache[path] = {}
            blob_cache[path]["__file_info__"] = file_info

        original_size = file_info["size"]
        chunk_hashes = file_info["chunk_hashes"]

        # Clamp to actual file size.
        if offset >= original_size:
            return True, b""
        if offset + size > original_size:
            size = original_size - offset
        # Determine which chunks cover the requested range.
        first_chunk = offset // CHUNK_SIZE
        last_chunk = (offset + size - 1) // CHUNK_SIZE
        buf = b""
        for i in range(first_chunk, last_chunk + 1):
            if i >= len(chunk_hashes):
                break
            h = chunk_hashes[i]
            try:
                data = blob_cache[path][h]
            except KeyError:
                blob = self.backupd_conn.get_chunk(h)[1]
                # Decrypt and decompress.
                flag, encrypted = blob[:1], blob[1:]
                data = decrypt_block(self.aes_key, encrypted)
                if flag == FLAG_ZLIB:
                    data = zlib.decompress(data)
                blob_cache[path][h] = data
            buf += data
        # Slice to the requested range within the chunk-aligned buffer.
        chunk_offset = offset - (first_chunk * CHUNK_SIZE)
        return True, buf[chunk_offset:chunk_offset + size]

    def release(self, path: str) -> int:
        global blob_cache
        if not self.restore_share:
            return super().release(path)
        try:
            blob_cache.pop(path)
        except KeyError:
            pass
        return self.backupd_conn.release(path)
